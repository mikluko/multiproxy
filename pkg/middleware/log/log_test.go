package log_test

import (
	"bytes"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/justinas/alice"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/akabos/multiproxy/pkg/middleware/log"
)

func TestLog(t *testing.T) {
	var (
		access bytes.Buffer
		server bytes.Buffer
		h      = alice.
			New(
				log.Middleware(&access, &server, zapcore.InfoLevel),
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
					log.With(rq, zap.String("common-field", "yes"))

					log.WithContentLength(rq, 100500)
					log.WithStatusCode(rq, http.StatusOK)

					log.Error(rq, "error message")
					log.Warn(rq, "warn message")
					log.Info(rq, "info message")
					log.Debug(rq, "debug message")
				},
			)
		err error
	)
	s := httptest.NewServer(h)
	defer s.Close()

	_, err = http.Get(s.URL)
	require.NoError(t, err)

	assert.Contains(t, access.String(), `"logger":"access.test"`)
	assert.NotContains(t, access.String(), `"info""`)
	assert.NotContains(t, access.String(), `"INFO""`)
	assert.Contains(t, access.String(), `"url":"/"`)
	assert.Contains(t, access.String(), `"status":200`)
	assert.Contains(t, access.String(), `"content-length":100500`)
	assert.Contains(t, access.String(), `"common-field":"yes"`)

	assert.Contains(t, server.String(), `"logger":"server.test"`)
	assert.Contains(t, server.String(), `"msg":"error message"`)
	assert.Contains(t, server.String(), `"msg":"warn message"`)
	assert.Contains(t, server.String(), `"msg":"info message"`)
	assert.NotContains(t, server.String(), `"msg":"debug message"`)
	assert.Contains(t, server.String(), `"common-field":"yes"`)
	assert.NotContains(t, server.String(), `"status":200`)

	access.Reset()
	server.Reset()

	_, err = http.Get(s.URL)
	require.NoError(t, err)

	assert.Contains(t, access.String(), `"logger":"access.test"`)
	assert.Contains(t, server.String(), `"logger":"server.test"`)
}

func TestLogNested(t *testing.T) {
	var (
		outer bytes.Buffer
		inner bytes.Buffer
		h     = alice.
			New(
				log.Middleware(
					ioutil.Discard,
					&outer,
					zapcore.InfoLevel,
				),
				func(next http.Handler) http.Handler {
					return http.HandlerFunc(func(rw http.ResponseWriter, rq *http.Request) {
						next.ServeHTTP(rw, rq)
						log.With(rq, zap.String("outer-only-field", "yes"))
						log.Info(rq, "")
					})
				},
				log.Middleware(
					ioutil.Discard,
					&inner,
					zapcore.InfoLevel,
				),
			).
			ThenFunc(
				func(rw http.ResponseWriter, rq *http.Request) {
					log.Named(rq, "inner")
					log.With(rq, zap.String("inner-field", "yes"))
					log.Info(rq, "")
				},
			)
		err error
	)
	s := httptest.NewServer(h)
	defer s.Close()

	_, err = http.Get(s.URL)
	require.NoError(t, err)

	assert.Contains(t, outer.String(), `"logger":"server"`)
	assert.Contains(t, outer.String(), `"outer-only-field":"yes"`)
	assert.NotContains(t, outer.String(), `"inner-field":"yes"`)

	assert.Contains(t, inner.String(), `"logger":"server.inner"`)
	assert.Contains(t, inner.String(), `"inner-field":"yes"`)
	assert.NotContains(t, inner.String(), `"outer-only-field":"yes"`)
}
