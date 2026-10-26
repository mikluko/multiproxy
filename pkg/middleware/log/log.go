// Package log carries an access logger and a server logger in the context of each proxied request.
package log

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"os"
	"sync/atomic"
	"time"

	"github.com/felixge/httpsnoop"
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
// The access record carries the status and the number of body bytes the handler wrote through the ResponseWriter.
// Bytes written to a hijacked connection pass it by, so a handler that hijacks records them with WithStatusCode and
// WithContentLength. The ResponseWriter passed on keeps the optional interfaces of the one received.
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
			next.ServeHTTP(observe(rw, obj), rq.WithContext(ctx))

			d := time.Since(t)
			attrs := []slog.Attr{slog.String("logger", "access"+obj.name)}
			if obj.status != 0 {
				attrs = append(attrs, slog.Int("status", obj.status))
			}
			if obj.status != 0 || obj.contentLength != 0 {
				attrs = append(attrs, slog.Int("content-length", obj.contentLength))
			}
			attrs = append(attrs,
				slog.Duration("duration", d),
				slog.String("duration-human", d.Round(time.Millisecond).String()),
			)
			obj.access.LogAttrs(ctx, slog.LevelInfo, "", attrs...)
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

// observe wraps rw so that the status and body bytes the handler writes are recorded in obj.
func observe(rw http.ResponseWriter, obj *ctxObj) http.ResponseWriter {
	return httpsnoop.Wrap(rw, httpsnoop.Hooks{
		WriteHeader: func(next httpsnoop.WriteHeaderFunc) httpsnoop.WriteHeaderFunc {
			return func(code int) {
				if obj.status == 0 {
					obj.status = code
				}
				next(code)
			}
		},
		Write: func(next httpsnoop.WriteFunc) httpsnoop.WriteFunc {
			return func(p []byte) (int, error) {
				if obj.status == 0 {
					obj.status = http.StatusOK
				}
				n, err := next(p)
				obj.contentLength += n
				return n, err
			}
		},
		ReadFrom: func(next httpsnoop.ReadFromFunc) httpsnoop.ReadFromFunc {
			return func(r io.Reader) (int64, error) {
				if obj.status == 0 {
					obj.status = http.StatusOK
				}
				n, err := next(r)
				obj.contentLength += int(n)
				return n, err
			}
		},
	})
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

// WithStatusCode records status as the response status code of the request, replacing what was observed.
func WithStatusCode(rq *http.Request, status int) {
	obj := fromRequest(rq)
	if obj == nil {
		return
	}
	obj.status = status
}

// StatusCode returns the response status code observed or recorded with WithStatusCode, or 0.
func StatusCode(rq *http.Request) int {
	obj := fromRequest(rq)
	if obj == nil {
		return 0
	}
	return obj.status
}

// WithContentLength records n as the number of response bytes of the request, replacing what was observed.
func WithContentLength(rq *http.Request, n int) {
	obj := fromRequest(rq)
	if obj == nil {
		return
	}
	obj.contentLength = n
}

// ContentLength returns the number of response bytes observed or recorded with WithContentLength, or 0.
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
