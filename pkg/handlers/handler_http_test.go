package handlers_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/akabos/multiproxy/pkg/handlers"
)

func TestHTTPHandler_ServeHTTP(t *testing.T) {
	p := httptest.NewServer(&handlers.HTTPHandler{})
	defer p.Close()

	tr := testTransport(p.URL)

	t.Run("ok", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()

		rq, _ := http.NewRequest(http.MethodGet, testServer.URL+"/get", nil)
		rs, err := tr.RoundTrip(rq.WithContext(ctx))
		require.NoError(t, err)
		defer rs.Body.Close()

		require.Equal(t, http.StatusOK, rs.StatusCode)

		var data testGetResponse
		_ = json.NewDecoder(rs.Body).Decode(&data)

		require.Equal(t, "Go-http-client/1.1", data.Headers.Get("user-agent"))
	})

	t.Run("method not allowed", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()

		rq, _ := http.NewRequest(http.MethodGet, testTLSServer.URL+"/get", nil)
		_, err := tr.RoundTrip(rq.WithContext(ctx))
		// Transport fails here instead of returning 505. This is expected behaviour.
		require.Error(t, err)
		require.Equal(t, http.StatusText(http.StatusMethodNotAllowed), err.Error())
	})

	t.Run("bad gateway", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()

		rq, _ := http.NewRequest(http.MethodGet, "http://example.invalid", nil)
		rs, err := tr.RoundTrip(rq.WithContext(ctx))
		require.NoError(t, err)
		require.Equal(t, http.StatusBadGateway, rs.StatusCode)
	})

	t.Run("bad request", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()

		rq, _ := http.NewRequest(http.MethodGet, p.URL, nil)
		rs, err := tr.RoundTrip(rq.WithContext(ctx))
		require.NoError(t, err)
		require.Equal(t, http.StatusBadRequest, rs.StatusCode)
	})

	t.Run("small chunked response", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()

		rq, _ := http.NewRequest(http.MethodGet, testServer.URL+"/stream/2", nil)
		rs, err := tr.RoundTrip(rq.WithContext(ctx))
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, rs.StatusCode)
		require.Len(t, rs.TransferEncoding, 0)
		require.Greater(t, rs.ContentLength, int64(0))

		buf := bytes.NewBuffer(nil)
		_, err = io.Copy(buf, rs.Body)
		require.NoError(t, err)
		require.Len(t, strings.Split(strings.TrimSpace(buf.String()), "\n"), 2)
	})

	t.Run("large chunked response", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()

		rq, _ := http.NewRequest(http.MethodGet, testServer.URL+"/stream/100", nil)
		rs, err := tr.RoundTrip(rq.WithContext(ctx))
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, rs.StatusCode)
		require.Equal(t, []string{"chunked"}, rs.TransferEncoding)
		require.Equal(t, rs.ContentLength, int64(-1))

		buf := bytes.NewBuffer(nil)
		_, err = io.Copy(buf, rs.Body)
		require.NoError(t, err)
		require.Len(t, strings.Split(strings.TrimSpace(buf.String()), "\n"), 100)
	})
}
