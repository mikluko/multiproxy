package log

import (
	"context"
	"io"
	"net/http"
	"os"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type ctxKey struct{}

type ctxObj struct {
	access *zap.Logger
	server *zap.Logger
	seq    uint64
	uid    uuid.UUID
	parent *ctxObj

	status        int
	contentLength int
}

// DefaultAccessLogEncoderConfig returns the default configuration for access logger encoder
func DefaultAccessLogEncoderConfig() zapcore.EncoderConfig {
	return zapcore.EncoderConfig{
		TimeKey:        "ts",
		LevelKey:       zapcore.OmitKey,
		NameKey:        "logger",
		CallerKey:      zapcore.OmitKey,
		FunctionKey:    zapcore.OmitKey,
		MessageKey:     zapcore.OmitKey,
		StacktraceKey:  zapcore.OmitKey,
		LineEnding:     zapcore.DefaultLineEnding,
		EncodeLevel:    zapcore.LowercaseLevelEncoder,
		EncodeTime:     zapcore.RFC3339TimeEncoder,
		EncodeDuration: zapcore.MillisDurationEncoder,
		EncodeCaller:   zapcore.ShortCallerEncoder,
	}
}

// DefaultServerLogEncoderConfig returns the default configuration for server logger encoder
func DefaultServerLogEncoderConfig() zapcore.EncoderConfig {
	return zapcore.EncoderConfig{
		TimeKey:        "ts",
		LevelKey:       "level",
		NameKey:        "logger",
		CallerKey:      "caller",
		FunctionKey:    zapcore.OmitKey,
		MessageKey:     "msg",
		StacktraceKey:  "trace",
		LineEnding:     zapcore.DefaultLineEnding,
		EncodeLevel:    zapcore.LowercaseLevelEncoder,
		EncodeTime:     zapcore.RFC3339TimeEncoder,
		EncodeDuration: zapcore.MillisDurationEncoder,
		EncodeCaller:   zapcore.ShortCallerEncoder,
	}
}

// Middleware is logging middleware constructor
func Middleware(aw io.Writer, sw io.Writer, lvl zapcore.Level) func(http.Handler) http.Handler {
	var (
		ac = zapcore.NewCore(
			zapcore.NewJSONEncoder(DefaultAccessLogEncoderConfig()),
			zapcore.AddSync(aw),
			zapcore.InfoLevel,
		)
		al = zap.New(ac).Named("access")
		sc = zapcore.NewCore(
			zapcore.NewJSONEncoder(DefaultServerLogEncoderConfig()),
			zapcore.AddSync(sw),
			lvl,
		)
		sl  = zap.New(sc).Named("server")
		seq uint64
	)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(rw http.ResponseWriter, rq *http.Request) {
			t := time.Now()
			obj, hasParent := rq.Context().Value(ctxKey{}).(*ctxObj)
			if !hasParent {
				obj = &ctxObj{
					access: al,
					server: sl,
					seq:    atomic.AddUint64(&seq, 1),
					uid:    uuid.New(),
				}
			} else {
				obj = &ctxObj{
					access: obj.access.WithOptions(zap.WrapCore(func(_ zapcore.Core) zapcore.Core {
						return ac
					})),
					server: obj.server.WithOptions(zap.WrapCore(func(_ zapcore.Core) zapcore.Core {
						return sc
					})),
					seq:    atomic.AddUint64(&seq, 1),
					uid:    uuid.New(),
					parent: obj,
				}
			}
			obj.server = obj.server.With(
				zap.Uint64("seq", obj.seq),
				zap.String("uid", obj.uid.String()),
			)
			obj.access = obj.access.With(
				zap.Uint64("seq", obj.seq),
				zap.String("uid", obj.uid.String()),
				zap.String("client", rq.RemoteAddr),
				zap.String("method", rq.Method),
			)
			if rq.Method == http.MethodConnect {
				obj.access = obj.access.With(zap.String("server", rq.URL.Host))
			} else {
				obj.access = obj.access.With(zap.String("url", rq.URL.String()))
			}
			if hasParent {
				obj.access = obj.access.With(
					zap.Uint64("parent-seq", obj.parent.seq),
					zap.String("parent-uuid", obj.parent.uid.String()),
				)
				obj.server = obj.server.With(
					zap.Uint64("parent-seq", obj.parent.seq),
					zap.String("parent-uuid", obj.parent.uid.String()),
				)
			}
			ctx := context.WithValue(rq.Context(), ctxKey{}, obj)
			next.ServeHTTP(rw, rq.WithContext(ctx))
			obj.access.Info("",
				zap.Duration("duration", time.Since(t)),
				zap.Stringer("duration-human", time.Since(t).Round(time.Millisecond)),
			)
		})
	}
}

// Log is the convenience wrapper around Middleware
func Log(next http.Handler) http.Handler {
	return Middleware(os.Stdout, os.Stderr, zapcore.InfoLevel)(next)
}

// Logger returns server logger associated with the request. If there's no logger associated with the request, returns
// no-op logger.
func Logger(rq *http.Request) *zap.Logger {
	obj, ok := rq.Context().Value(ctxKey{}).(*ctxObj)
	if !ok {
		return nop
	}
	return obj.server
}

// With pushes the lest of fields into the context of both access and server loggers associated with the request.
func With(rq *http.Request, fields ...zap.Field) {
	obj, ok := rq.Context().Value(ctxKey{}).(*ctxObj)
	if !ok {
		return
	}
	obj.access = obj.access.With(fields...)
	obj.server = obj.server.With(fields...)
}

// Named append name token to both server and access loggers associated with the request.
func Named(rq *http.Request, s string) {
	obj, _ := rq.Context().Value(ctxKey{}).(*ctxObj)
	if obj == nil {
		return
	}
	obj.access = obj.access.Named(s)
	obj.server = obj.server.Named(s)
}

// WithStatusCode pushes response status code into the access logger associated with the request.
func WithStatusCode(rq *http.Request, status int) {
	obj, ok := rq.Context().Value(ctxKey{}).(*ctxObj)
	if !ok {
		return
	}
	obj.status = status
	obj.access = obj.access.With(zap.Int("status", status))
}

// StatusCode returns status code previously pushed into the request context. Returns 0 if no status was pushed.
func StatusCode(rq *http.Request) int {
	obj, ok := rq.Context().Value(ctxKey{}).(*ctxObj)
	if !ok {
		return 0
	}
	return obj.status
}

// WithContentLength pushes response content length into the access logger associated with the request.
func WithContentLength(rq *http.Request, n int) {
	obj, ok := rq.Context().Value(ctxKey{}).(*ctxObj)
	if !ok {
		return
	}
	obj.contentLength = n
	obj.access = obj.access.With(zap.Int("content-length", n))
}

// ContentLength returns content length previously pushed into the request context. Returns 0 if no content length was
// pushed.
func ContentLength(rq *http.Request) int {
	obj, ok := rq.Context().Value(ctxKey{}).(*ctxObj)
	if !ok {
		return 0
	}
	return obj.contentLength
}

// UID returns request identifier from the request context. Returns zero UUID if not found in the context.
func UID(rq *http.Request) uuid.UUID {
	obj, ok := rq.Context().Value(ctxKey{}).(*ctxObj)
	if !ok {
		return uuid.UUID{}
	}
	return obj.uid
}

// Sequence returns request sequence from the request context. Returns 0 if not found in the context.
func Sequence(rq *http.Request) uint64 {
	obj, ok := rq.Context().Value(ctxKey{}).(*ctxObj)
	if !ok {
		return 0
	}
	return obj.seq
}

var nop = zap.NewNop()

// Fatal emits fatal level message using server logger associated with the request.
func Fatal(rq *http.Request, msg string, fields ...zap.Field) {
	Logger(rq).Fatal(msg, fields...)
}

// Panic emits panic level message using server logger associated with the request.
func Panic(rq *http.Request, msg string, fields ...zap.Field) {
	Logger(rq).Panic(msg, fields...)
}

// Error emits error level message using server logger associated with the request.
func Error(rq *http.Request, msg string, fields ...zap.Field) {
	Logger(rq).Error(msg, fields...)
}

// Warn emits warn level message using server logger associated with the request.
func Warn(rq *http.Request, msg string, fields ...zap.Field) {
	Logger(rq).Warn(msg, fields...)
}

// Info emits info level message using server logger associated with the request.
func Info(rq *http.Request, msg string, fields ...zap.Field) {
	Logger(rq).Info(msg, fields...)
}

// Debug emits debug level message using server logger associated with the request.
func Debug(rq *http.Request, msg string, fields ...zap.Field) {
	Logger(rq).Debug(msg, fields...)
}
