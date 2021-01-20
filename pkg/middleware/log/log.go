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
}

var AccessLogEncoderConfig = zapcore.EncoderConfig{
	TimeKey:        "ts",
	LevelKey:       zapcore.OmitKey,
	NameKey:        "handler",
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

var ServerLogEncoderConfig = zapcore.EncoderConfig{
	TimeKey:        "ts",
	LevelKey:       "level",
	NameKey:        "handler",
	CallerKey:      "caller",
	FunctionKey:    zapcore.OmitKey,
	MessageKey:     "msg",
	StacktraceKey:  "trace",
	LineEnding:     zapcore.DefaultLineEnding,
	EncodeLevel:    zapcore.CapitalLevelEncoder,
	EncodeTime:     zapcore.RFC3339TimeEncoder,
	EncodeDuration: zapcore.MillisDurationEncoder,
	EncodeCaller:   zapcore.ShortCallerEncoder,
}

func Middleware(aw io.Writer, sw io.Writer, lvl zapcore.Level) func(http.Handler) http.Handler {
	var (
		ac = zapcore.NewCore(
			zapcore.NewConsoleEncoder(AccessLogEncoderConfig),
			zapcore.AddSync(aw),
			zapcore.InfoLevel,
		)
		al = zap.New(ac).Named("access")
		sc = zapcore.NewCore(
			zapcore.NewConsoleEncoder(ServerLogEncoderConfig),
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

func Log(next http.Handler) http.Handler {
	return Middleware(os.Stdout, os.Stderr, zapcore.InfoLevel)(next)
}

func Logger(rq *http.Request) *zap.Logger {
	obj, ok := rq.Context().Value(ctxKey{}).(*ctxObj)
	if !ok {
		return nop
	}
	return obj.server
}

func With(rq *http.Request, fields ...zap.Field) {
	obj, ok := rq.Context().Value(ctxKey{}).(*ctxObj)
	if !ok {
		return
	}
	obj.access = obj.access.With(fields...)
	obj.server = obj.server.With(fields...)
}

func Named(rq *http.Request, s string) {
	obj, _ := rq.Context().Value(ctxKey{}).(*ctxObj)
	if obj == nil {
		return
	}
	obj.access = obj.access.Named(s)
	obj.server = obj.server.Named(s)
}

func WithStatus(rq *http.Request, status int) {
	obj, ok := rq.Context().Value(ctxKey{}).(*ctxObj)
	if !ok {
		return
	}
	obj.access = obj.access.With(zap.Int("status", status))
}

func WithContentLength(rq *http.Request, n int) {
	obj, ok := rq.Context().Value(ctxKey{}).(*ctxObj)
	if !ok {
		return
	}
	obj.access = obj.access.With(zap.Int("content-length", n))
}

var nop = zap.NewNop()

func Fatal(rq *http.Request, msg string, fields ...zap.Field) {
	Logger(rq).Fatal(msg, fields...)
}

func Panic(rq *http.Request, msg string, fields ...zap.Field) {
	Logger(rq).Panic(msg, fields...)
}

func Error(rq *http.Request, msg string, fields ...zap.Field) {
	Logger(rq).Error(msg, fields...)
}

func Warn(rq *http.Request, msg string, fields ...zap.Field) {
	Logger(rq).Warn(msg, fields...)
}

func Info(rq *http.Request, msg string, fields ...zap.Field) {
	Logger(rq).Info(msg, fields...)
}

func Debug(rq *http.Request, msg string, fields ...zap.Field) {
	Logger(rq).Debug(msg, fields...)
}
