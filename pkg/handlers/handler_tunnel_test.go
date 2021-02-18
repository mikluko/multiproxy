package handlers_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/akabos/multiproxy/pkg/handlers"
)

func TestTunnelProxy_ServeHTTP(t *testing.T) {
	p := httptest.NewServer(&handlers.Tunnel{})
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
		require.Nil(t, rs)
		require.Error(t, err)
		require.Equal(t, "Bad Gateway", err.Error())
	})

	t.Run("gateway timeout", func(t *testing.T) {
		p := httptest.NewServer(&handlers.Tunnel{
			DialTimeout: time.Nanosecond * 100,
		})
		defer p.Close()
		tr := testTransport(p.URL)

		rq, _ := http.NewRequest(http.MethodGet, testTLSServer.URL+"/get", nil)
		rs, err := tr.RoundTrip(rq)
		require.Nil(t, rs)
		require.Error(t, err)
		require.Equal(t, "Gateway Timeout", err.Error())
	})

	t.Run("no gateway timeout", func(t *testing.T) {
		// make sure specified timeout applicable only to dial, not the whole connection life cycle
		p := httptest.NewServer(&handlers.Tunnel{
			DialTimeout: time.Millisecond * 200,
		})
		defer p.Close()
		tr := testTransport(p.URL)

		rq, _ := http.NewRequest(http.MethodGet, testTLSServer.URL+"/delay/1", nil)
		rs, err := tr.RoundTrip(rq)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, rs.StatusCode)
	})
}
