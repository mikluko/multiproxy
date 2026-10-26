// Package log carries an access logger and a server logger in the context of each proxied request.
package log

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
)

type ctxKey struct{}

type ctxObj struct {
	access *slog.Logger
	server *slog.Logger
	name   string
	seq    uint64
	uid    uuid.UUID
	parent *ctxObj

	status        int
	contentLength int
}

// Middleware gives each request an access logger derived from access and a server logger derived from server, and
// writes one access record through the former when the request completes. A request served inside another, as one
// intercepted from a CONNECT session, records the sequence and identifier of the request it is served in.
//
// Every record is written with the request's context.
func Middleware(access, server *slog.Logger) func(http.Handler) http.Handler {
	var seq uint64
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(rw http.ResponseWriter, rq *http.Request) {
			t := time.Now()
			parent, _ := rq.Context().Value(ctxKey{}).(*ctxObj)
			obj := &ctxObj{
				seq:    atomic.AddUint64(&seq, 1),
				uid:    uuid.New(),
				parent: parent,
			}
			ids := []any{"seq", obj.seq, "uid", obj.uid.String()}
			if parent != nil {
				obj.name = parent.name
				ids = append(ids, "parent-seq", parent.seq, "parent-uuid", parent.uid.String())
			}
			obj.server = server.With(ids...)
			obj.access = access.With(append(ids, "client", rq.RemoteAddr, "method", rq.Method)...)
			if rq.Method == http.MethodConnect {
				obj.access = obj.access.With("server", rq.URL.Host)
			} else {
				obj.access = obj.access.With("url", rq.URL.String())
			}

			ctx := context.WithValue(rq.Context(), ctxKey{}, obj)
			next.ServeHTTP(rw, rq.WithContext(ctx))

			d := time.Since(t)
			obj.access.LogAttrs(ctx, slog.LevelInfo, "",
				slog.String("logger", "access"+obj.name),
				slog.Duration("duration", d),
				slog.String("duration-human", d.Round(time.Millisecond).String()),
			)
		})
	}
}

// Log is Middleware writing JSON access records to stdout and JSON server records to stderr.
func Log(next http.Handler) http.Handler {
	return Middleware(
		slog.New(slog.NewJSONHandler(os.Stdout, nil)),
		slog.New(slog.NewJSONHandler(os.Stderr, nil)),
	)(next)
}

func fromRequest(rq *http.Request) *ctxObj {
	obj, _ := rq.Context().Value(ctxKey{}).(*ctxObj)
	return obj
}

// Logger returns the server logger of the request, or a logger that discards everything where the request carries
// none.
func Logger(rq *http.Request) *slog.Logger {
	obj := fromRequest(rq)
	if obj == nil {
		return nop
	}
	return obj.server.With("logger", "server"+obj.name)
}

var nop = slog.New(slog.DiscardHandler)

// With adds attributes, as slog.Logger.With takes them, to both loggers of the request.
func With(rq *http.Request, args ...any) {
	obj := fromRequest(rq)
	if obj == nil {
		return
	}
	obj.access = obj.access.With(args...)
	obj.server = obj.server.With(args...)
}

// Named appends a dot and s to the logger name both loggers of the request record.
func Named(rq *http.Request, s string) {
	obj := fromRequest(rq)
	if obj == nil {
		return
	}
	obj.name += "." + s
}

// WithStatusCode records the response status code in the access logger of the request.
func WithStatusCode(rq *http.Request, status int) {
	obj := fromRequest(rq)
	if obj == nil {
		return
	}
	obj.status = status
	obj.access = obj.access.With("status", status)
}

// StatusCode returns the status code recorded by WithStatusCode, or 0.
func StatusCode(rq *http.Request) int {
	obj := fromRequest(rq)
	if obj == nil {
		return 0
	}
	return obj.status
}

// WithContentLength records the response content length in the access logger of the request.
func WithContentLength(rq *http.Request, n int) {
	obj := fromRequest(rq)
	if obj == nil {
		return
	}
	obj.contentLength = n
	obj.access = obj.access.With("content-length", n)
}

// ContentLength returns the content length recorded by WithContentLength, or 0.
func ContentLength(rq *http.Request) int {
	obj := fromRequest(rq)
	if obj == nil {
		return 0
	}
	return obj.contentLength
}

// UID returns the identifier of the request, or the zero UUID where the request carries none.
func UID(rq *http.Request) uuid.UUID {
	obj := fromRequest(rq)
	if obj == nil {
		return uuid.UUID{}
	}
	return obj.uid
}

// Sequence returns the sequence number of the request, or 0 where the request carries none.
func Sequence(rq *http.Request) uint64 {
	obj := fromRequest(rq)
	if obj == nil {
		return 0
	}
	return obj.seq
}

// Panic writes msg at error level through the server logger of the request, then panics with msg.
func Panic(rq *http.Request, msg string, args ...any) {
	Logger(rq).ErrorContext(rq.Context(), msg, args...)
	panic(msg)
}

// Error writes msg at error level through the server logger of the request.
func Error(rq *http.Request, msg string, args ...any) {
	Logger(rq).ErrorContext(rq.Context(), msg, args...)
}

// Warn writes msg at warn level through the server logger of the request.
func Warn(rq *http.Request, msg string, args ...any) {
	Logger(rq).WarnContext(rq.Context(), msg, args...)
}

// Info writes msg at info level through the server logger of the request.
func Info(rq *http.Request, msg string, args ...any) {
	Logger(rq).InfoContext(rq.Context(), msg, args...)
}

// Debug writes msg at debug level through the server logger of the request.
func Debug(rq *http.Request, msg string, args ...any) {
	Logger(rq).DebugContext(rq.Context(), msg, args...)
}
