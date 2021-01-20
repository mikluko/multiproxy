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

func TestMITMHandler_ServeHTTP(t *testing.T) {
	p := httptest.NewServer(&handlers.MITMHandler{})
	defer p.Close()

	tr := testTransport(p.URL)

	t.Run("ok", func(t *testing.T) {
		rq, _ := http.NewRequest(http.MethodGet, testTLSServer.URL+"/get", nil)
		rs, err := tr.RoundTrip(rq)
		require.NoError(t, err)
		defer rs.Body.Close()

		require.Equal(t, http.StatusOK, rs.StatusCode)

		var data testGetResponse
		_ = json.NewDecoder(rs.Body).Decode(&data)

		require.Equal(t, "Go-http-client/1.1", data.Headers.Get("user-agent"))
	})

	t.Run("method not allowed", func(t *testing.T) {
		rq, _ := http.NewRequest(http.MethodGet, "http://example.invalid", nil)
		rs, err := tr.RoundTrip(rq)
		require.NoError(t, err)
		defer rs.Body.Close()

		require.Equal(t, http.StatusMethodNotAllowed, rs.StatusCode)
	})

	t.Run("bad gateway", func(t *testing.T) {
		rq, _ := http.NewRequest(http.MethodGet, "https://example.invalid", nil)
		rs, err := tr.RoundTrip(rq)
		require.NoError(t, err)
		require.Equal(t, http.StatusBadGateway, rs.StatusCode)
	})

	t.Run("chunked transfer encoding", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()

		rq, _ := http.NewRequestWithContext(ctx, http.MethodGet, testTLSServer.URL+"/stream/2", nil)
		rs, err := tr.RoundTrip(rq)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, rs.StatusCode)

		buf := bytes.NewBuffer(nil)
		_, err = io.Copy(buf, rs.Body)
		require.NoError(t, err)
		require.Len(t, strings.Split(strings.TrimSpace(buf.String()), "\n"), 2)
	})

	t.Run("keep alive", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()

		var remotes []string

		s := httptest.NewTLSServer(http.HandlerFunc(func(rw http.ResponseWriter, rq *http.Request) {
			remotes = append(remotes, rq.RemoteAddr)
			rw.WriteHeader(http.StatusNoContent)
		}))
		defer s.Close()

		for i := 0; i < 2; i++ {
			rq, _ := http.NewRequestWithContext(ctx, http.MethodGet, s.URL, nil)
			rs, err := tr.RoundTrip(rq)
			require.NoError(t, err)
			require.Equal(t, http.StatusNoContent, rs.StatusCode)
		}

		require.Len(t, remotes, 2)
		require.Equal(t, remotes[0], remotes[1])
	})

}
