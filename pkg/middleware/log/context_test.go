package log_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"sarak.sh/mikluko/multiproxy/pkg/middleware/log"
)

func TestOutsideMiddleware(t *testing.T) {
	rq := httptest.NewRequest(http.MethodGet, "/", nil)

	require.NotPanics(t, func() {
		log.With(rq, zap.String("k", "v"))
		log.Named(rq, "name")
		log.WithStatusCode(rq, http.StatusTeapot)
		log.WithContentLength(rq, 42)
		log.Info(rq, "discarded")
	})
	require.NotNil(t, log.Logger(rq))
	require.Zero(t, log.StatusCode(rq))
	require.Zero(t, log.ContentLength(rq))
	require.Equal(t, uuid.UUID{}, log.UID(rq))
	require.Zero(t, log.Sequence(rq))
}

func TestUIDAndSequence(t *testing.T) {
	type seen struct {
		uid uuid.UUID
		seq uint64
	}
	var got []seen
	h := log.Middleware(io.Discard, io.Discard, zapcore.InfoLevel)(http.HandlerFunc(func(_ http.ResponseWriter, rq *http.Request) {
		got = append(got, seen{log.UID(rq), log.Sequence(rq)})
	}))
	for range 2 {
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
	}

	require.Len(t, got, 2)
	require.NotEqual(t, uuid.UUID{}, got[0].uid)
	require.NotEqual(t, got[0].uid, got[1].uid)
	require.Greater(t, got[1].seq, got[0].seq)
}

func TestPanic(t *testing.T) {
	h := log.Middleware(io.Discard, io.Discard, zapcore.InfoLevel)(http.HandlerFunc(func(_ http.ResponseWriter, rq *http.Request) {
		log.Panic(rq, "boom")
	}))
	require.PanicsWithValue(t, "boom", func() {
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
	})
}
