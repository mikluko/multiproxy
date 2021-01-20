package log_test

import (
	"bytes"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/justinas/alice"
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
			).
			ThenFunc(
				func(rw http.ResponseWriter, rq *http.Request) {
					log.Named(rq, "test")
					log.With(rq, zap.String("common-field", "yes"))

					log.WithContentLength(rq, 100500)
					log.WithStatus(rq, http.StatusOK)

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

	require.Contains(t, access.String(), "\taccess.test\t")
	require.NotContains(t, access.String(), "\tINFO\t")
	require.Contains(t, access.String(), `"url": "/"`)
	require.Contains(t, access.String(), `"status": 200`)
	require.Contains(t, access.String(), `"content-length": 100500`)
	require.Contains(t, access.String(), `"common-field": "yes"`)

	require.Contains(t, server.String(), "\tserver.test\t")
	require.Contains(t, server.String(), "\terror message\t")
	require.Contains(t, server.String(), "\twarn message\t")
	require.Contains(t, server.String(), "\tinfo message\t")
	require.NotContains(t, server.String(), "\tdebug message\t")
	require.Contains(t, server.String(), `"common-field": "yes"`)
	require.NotContains(t, server.String(), `"status": 200`)

	access.Reset()
	server.Reset()

	_, err = http.Get(s.URL)
	require.NoError(t, err)

	require.Contains(t, access.String(), "\taccess.test\t")
	require.Contains(t, server.String(), "\tserver.test\t")
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

	require.Contains(t, outer.String(), "\tserver\t")
	require.Contains(t, outer.String(), `"outer-only-field": "yes"`)
	require.NotContains(t, outer.String(), `"inner-field": "yes"`)

	require.Contains(t, inner.String(), "\tserver.inner\t")
	require.Contains(t, inner.String(), `"inner-field": "yes"`)
	require.NotContains(t, inner.String(), `"outer-only-field": "yes"`)
}
