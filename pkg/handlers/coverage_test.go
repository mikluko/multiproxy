package handlers_test

import (
	"bufio"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"sarak.sh/mikluko/multiproxy/pkg/handlers"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(rq *http.Request) (*http.Response, error) { return f(rq) }

func TestHTTPHandler_errors(t *testing.T) {
	for _, c := range []struct {
		name string
		err  error
		want int
	}{
		{"a network error is a bad gateway", &net.OpError{Op: "dial", Err: errors.New("refused")}, http.StatusBadGateway},
		{"any other error is internal", errors.New("boom"), http.StatusInternalServerError},
	} {
		t.Run(c.name, func(t *testing.T) {
			p := httptest.NewServer(&handlers.HTTPHandler{
				Transport: roundTripFunc(func(*http.Request) (*http.Response, error) { return nil, c.err }),
			})
			defer p.Close()

			rq, _ := http.NewRequest(http.MethodGet, "http://upstream.test/", nil)
			rs, err := testTransport(p.URL).RoundTrip(rq)
			require.NoError(t, err)
			defer rs.Body.Close()
			require.Equal(t, c.want, rs.StatusCode)
		})
	}
}

func TestHTTPHandler_NoXForwardedFor(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, rq *http.Request) {
		rw.Header().Set("X-Seen-XFF", rq.Header.Get("X-Forwarded-For"))
	}))
	defer upstream.Close()

	for _, c := range []struct {
		skip bool
		want bool
	}{{false, true}, {true, false}} {
		p := httptest.NewServer(&handlers.HTTPHandler{NoXForwardedFor: c.skip})
		rq, _ := http.NewRequest(http.MethodGet, upstream.URL, nil)
		rq.Header.Set("X-Forwarded-For", "192.0.2.1")
		rs, err := testTransport(p.URL).RoundTrip(rq)
		require.NoError(t, err)
		_ = rs.Body.Close()
		p.Close()
		require.Equal(t, c.want, rs.Header.Get("X-Seen-XFF") != "", "NoXForwardedFor=%v", c.skip)
	}
}

func TestMITMHandler_innerHijack(t *testing.T) {
	p := httptest.NewServer(&handlers.MITMHandler{
		Handler: http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
			conn, bufrw, err := rw.(http.Hijacker).Hijack()
			require.NoError(t, err)
			_, _ = io.WriteString(bufrw, "HTTP/1.1 200 OK\r\nContent-Length: 8\r\nConnection: close\r\n\r\nhijacked")
			_ = bufrw.Flush()
			_ = conn.Close()
		}),
	})
	defer p.Close()

	rq, _ := http.NewRequest(http.MethodGet, testTLSServer.URL+"/get", nil)
	rs, err := testTransport(p.URL).RoundTrip(rq)
	require.NoError(t, err)
	defer rs.Body.Close()
	body, err := io.ReadAll(bufio.NewReader(rs.Body))
	require.NoError(t, err)
	require.Equal(t, "hijacked", string(body))
}

func TestMITMHandler_requiresHijacker(t *testing.T) {
	rq := httptest.NewRequest(http.MethodConnect, "https://example.com:443", nil)
	require.Panics(t, func() {
		(&handlers.MITMHandler{}).ServeHTTP(httptest.NewRecorder(), rq)
	})
}

func TestTunnel_requiresHijacker(t *testing.T) {
	rq := httptest.NewRequest(http.MethodConnect, "https://example.com:443", nil)
	require.Panics(t, func() {
		(&handlers.Tunnel{}).ServeHTTP(httptest.NewRecorder(), rq)
	})
}

func TestMITMHandler_verifiesUpstream(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(rw, "hello")
	}))
	defer upstream.Close()

	status := func(h http.Handler) int {
		p := httptest.NewServer(h)
		defer p.Close()
		rq, _ := http.NewRequest(http.MethodGet, upstream.URL, nil)
		rs, err := testTransport(p.URL).RoundTrip(rq)
		require.NoError(t, err)
		_ = rs.Body.Close()
		return rs.StatusCode
	}

	t.Run("an untrusted upstream certificate is a bad gateway", func(t *testing.T) {
		require.Equal(t, http.StatusBadGateway, status(&handlers.MITMHandler{}))
	})
	t.Run("a trusted one passes", func(t *testing.T) {
		trusting := upstream.Client().Transport
		require.Equal(t, http.StatusOK, status(&handlers.MITMHandler{Handler: &handlers.HTTPHandler{Transport: trusting}}))
	})
}
