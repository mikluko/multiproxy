package log_test

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/justinas/alice"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"sarak.sh/mikluko/multiproxy/pkg/middleware/log"
)

func jsonLogger(w io.Writer) *slog.Logger {
	return slog.New(slog.NewJSONHandler(w, nil))
}

func TestLog(t *testing.T) {
	var (
		access bytes.Buffer
		server bytes.Buffer
		h      = alice.
			New(
				log.Middleware(jsonLogger(&access), jsonLogger(&server)),
				func(next http.Handler) http.Handler {
					return http.HandlerFunc(func(rw http.ResponseWriter, rq *http.Request) {
						next.ServeHTTP(rw, rq)
						require.Equal(t, http.StatusOK, log.StatusCode(rq))
						require.Equal(t, 100500, log.ContentLength(rq))
					})
				},
			).
			ThenFunc(
				func(rw http.ResponseWriter, rq *http.Request) {
					log.Named(rq, "test")
					log.With(rq, "common-field", "yes")

					log.WithContentLength(rq, 100500)
					log.WithStatusCode(rq, http.StatusOK)

					log.Error(rq, "error message")
					log.Warn(rq, "warn message")
					log.Info(rq, "info message")
					log.Debug(rq, "debug message")
				},
			)
	)
	s := httptest.NewServer(h)
	defer s.Close()

	rs, err := http.Get(s.URL)
	require.NoError(t, err)
	_ = rs.Body.Close()

	assert.Contains(t, access.String(), `"logger":"access.test"`)
	assert.Contains(t, access.String(), `"url":"/"`)
	assert.Contains(t, access.String(), `"status":200`)
	assert.Contains(t, access.String(), `"content-length":100500`)
	assert.Contains(t, access.String(), `"common-field":"yes"`)
	assert.Contains(t, access.String(), `"duration"`)

	assert.Contains(t, server.String(), `"logger":"server.test"`)
	assert.Contains(t, server.String(), `"msg":"error message"`)
	assert.Contains(t, server.String(), `"msg":"warn message"`)
	assert.Contains(t, server.String(), `"msg":"info message"`)
	assert.NotContains(t, server.String(), `"msg":"debug message"`)
	assert.Contains(t, server.String(), `"common-field":"yes"`)
	assert.NotContains(t, server.String(), `"status":200`)

	access.Reset()
	server.Reset()

	rs, err = http.Get(s.URL)
	require.NoError(t, err)
	_ = rs.Body.Close()

	assert.Contains(t, access.String(), `"logger":"access.test"`)
	assert.Contains(t, server.String(), `"logger":"server.test"`)
}

func TestLogNested(t *testing.T) {
	var (
		outer bytes.Buffer
		inner bytes.Buffer
		h     = alice.
			New(
				log.Middleware(jsonLogger(io.Discard), jsonLogger(&outer)),
				func(next http.Handler) http.Handler {
					return http.HandlerFunc(func(rw http.ResponseWriter, rq *http.Request) {
						next.ServeHTTP(rw, rq)
						log.With(rq, "outer-only-field", "yes")
						log.Info(rq, "")
					})
				},
				log.Middleware(jsonLogger(io.Discard), jsonLogger(&inner)),
			).
			ThenFunc(
				func(rw http.ResponseWriter, rq *http.Request) {
					log.Named(rq, "inner")
					log.With(rq, "inner-field", "yes")
					log.Info(rq, "")
				},
			)
	)
	s := httptest.NewServer(h)
	defer s.Close()

	rs, err := http.Get(s.URL)
	require.NoError(t, err)
	_ = rs.Body.Close()

	assert.Contains(t, outer.String(), `"logger":"server"`)
	assert.Contains(t, outer.String(), `"outer-only-field":"yes"`)
	assert.NotContains(t, outer.String(), `"inner-field":"yes"`)

	assert.Contains(t, inner.String(), `"logger":"server.inner"`)
	assert.Contains(t, inner.String(), `"inner-field":"yes"`)
	assert.Contains(t, inner.String(), `"parent-seq"`)
	assert.NotContains(t, inner.String(), `"outer-only-field":"yes"`)
}

func TestLogObservesTheResponse(t *testing.T) {
	for name, c := range map[string]struct {
		handler http.HandlerFunc
		want    []string
	}{
		"status and body": {
			func(rw http.ResponseWriter, _ *http.Request) {
				rw.WriteHeader(http.StatusCreated)
				_, _ = io.WriteString(rw, "hello")
			},
			[]string{`"status":201`, `"content-length":5`},
		},
		"body alone is a 200": {
			func(rw http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(rw, "hi") },
			[]string{`"status":200`, `"content-length":2`},
		},
		"copied body": {
			func(rw http.ResponseWriter, _ *http.Request) {
				_, _ = io.Copy(rw, strings.NewReader("streamed"))
			},
			[]string{`"status":200`, `"content-length":8`},
		},
	} {
		t.Run(name, func(t *testing.T) {
			var access bytes.Buffer
			h := log.Middleware(jsonLogger(&access), jsonLogger(io.Discard))(c.handler)
			h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
			for _, w := range c.want {
				assert.Contains(t, access.String(), w)
			}
		})
	}
}

func TestLogKeepsWriterInterfaces(t *testing.T) {
	h := log.Middleware(jsonLogger(io.Discard), jsonLogger(io.Discard))(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		_, isFlusher := rw.(http.Flusher)
		_, isHijacker := rw.(http.Hijacker)
		assert.True(t, isFlusher)
		assert.True(t, isHijacker)
	}))
	s := httptest.NewServer(h)
	defer s.Close()
	rs, err := http.Get(s.URL)
	require.NoError(t, err)
	_ = rs.Body.Close()
}
