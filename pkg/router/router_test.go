package router_test

import (
	"crypto/tls"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/mccutchen/go-httpbin/v2/httpbin"
	"github.com/stretchr/testify/require"

	"sarak.sh/mikluko/multiproxy/pkg/handlers"
	router2 "sarak.sh/mikluko/multiproxy/pkg/router"
)

var (
	testServer    *httptest.Server
	testTLSServer *httptest.Server
)

func TestMain(m *testing.M) {
	testServer = httptest.NewServer(httpbin.New().Handler())
	defer testServer.Close()

	testTLSServer = httptest.NewTLSServer(httpbin.New().Handler())
	defer testTLSServer.Close()

	os.Exit(m.Run())
}

type testGetResponse struct {
	Args    url.Values  `json:"args"`
	Headers http.Header `json:"headers"`
	Origin  string      `json:"origin"`
	URL     string      `json:"url"`
}

func testTransport(proxy string) *http.Transport {
	return &http.Transport{
		Proxy: func(_ *http.Request) (*url.URL, error) {
			return url.Parse(proxy)
		},
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		MaxIdleConnsPerHost:   runtime.GOMAXPROCS(0) + 1,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}
}

func TestRouter_ServeHTTP(t *testing.T) {
	// The upstream is reached as localhost, which the httptest certificate does not name; this test is about routing.
	d := &handlers.HTTPHandler{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	router := &router2.Router{
		Default: d,
		Connect: &handlers.MITMHandler{
			Handler: http.HandlerFunc(func(rw http.ResponseWriter, rq *http.Request) {
				rq.Header.Add("x-test-route", "default")
				d.ServeHTTP(rw, rq)
			}),
		},
	}
	router.HandleConnectHost("localhost", &handlers.MITMHandler{
		Handler: http.HandlerFunc(func(rw http.ResponseWriter, rq *http.Request) {
			rq.Header.Add("x-test-route", "custom")
			d.ServeHTTP(rw, rq)
		}),
	})
	p := httptest.NewServer(router)

	tr := testTransport(p.URL)

	t.Run("http", func(t *testing.T) {

		rq, _ := http.NewRequest(http.MethodGet, testServer.URL+"/get", nil)
		rs, err := tr.RoundTrip(rq)
		require.NoError(t, err)
		defer rs.Body.Close()

		require.Equal(t, http.StatusOK, rs.StatusCode)

		var data testGetResponse
		_ = json.NewDecoder(rs.Body).Decode(&data)

		require.Equal(t, "Go-http-client/1.1", data.Headers.Get("user-agent"))
	})

	t.Run("https", func(t *testing.T) {
		rq, _ := http.NewRequest(http.MethodGet, testTLSServer.URL+"/get", nil)
		rs, err := tr.RoundTrip(rq)
		require.NoError(t, err)
		defer rs.Body.Close()

		require.Equal(t, http.StatusOK, rs.StatusCode)

		var data testGetResponse
		_ = json.NewDecoder(rs.Body).Decode(&data)

		require.Equal(t, "Go-http-client/1.1", data.Headers.Get("user-agent"))
		require.Equal(t, "default", data.Headers.Get("x-test-route"))
	})

	t.Run("https match host", func(t *testing.T) {
		u := strings.ReplaceAll(testTLSServer.URL, "127.0.0.1", "localhost") + "/get"
		rq, _ := http.NewRequest(http.MethodGet, u, nil)
		rs, err := tr.RoundTrip(rq)
		require.NoError(t, err)
		defer rs.Body.Close()

		require.Equal(t, http.StatusOK, rs.StatusCode)

		var data testGetResponse
		_ = json.NewDecoder(rs.Body).Decode(&data)

		require.Equal(t, "Go-http-client/1.1", data.Headers.Get("user-agent"))
		require.Equal(t, "custom", data.Headers.Get("x-test-route"))
	})
}

func TestRouter_ServeHTTP_hostRules(t *testing.T) {
	ok := http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) { rw.WriteHeader(http.StatusNoContent) })

	serve := func(r *router2.Router, method, target string) int {
		rq := httptest.NewRequest(method, target, nil)
		rw := httptest.NewRecorder()
		r.ServeHTTP(rw, rq)
		return rw.Code
	}

	t.Run("no rules refuse every host", func(t *testing.T) {
		r := &router2.Router{Default: ok}
		require.Equal(t, http.StatusForbidden, serve(r, http.MethodGet, "http://example.com/"))
		require.Equal(t, http.StatusMethodNotAllowed, serve(r, http.MethodConnect, "example.com:443"))
	})
	t.Run("a host pattern admits plain HTTP to that host only", func(t *testing.T) {
		r := &router2.Router{Default: ok}
		r.HandleConnectHost(".example.com", ok)
		require.Equal(t, http.StatusNoContent, serve(r, http.MethodGet, "http://www.example.com/"))
		require.Equal(t, http.StatusNoContent, serve(r, http.MethodGet, "http://example.com:8080/"))
		require.Equal(t, http.StatusForbidden, serve(r, http.MethodGet, "http://anything.test/"))
	})
	t.Run("a fallback admits every host", func(t *testing.T) {
		r := &router2.Router{Default: ok, Connect: ok}
		require.Equal(t, http.StatusNoContent, serve(r, http.MethodGet, "http://anything.test/"))
	})
	t.Run("origin-form requests are not proxied", func(t *testing.T) {
		r := &router2.Router{Default: ok, Connect: ok}
		rq := httptest.NewRequest(http.MethodGet, "/", nil)
		rq.URL.Host = ""
		rw := httptest.NewRecorder()
		r.ServeHTTP(rw, rq)
		require.Equal(t, http.StatusNotFound, rw.Code)
	})
}

func TestRouter_HandleConnectHost_fallback(t *testing.T) {
	ok := http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) { rw.WriteHeader(http.StatusNoContent) })
	other := http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) { rw.WriteHeader(http.StatusAccepted) })
	r := &router2.Router{Default: ok}
	r.HandleConnectHost("*", other)
	r.HandleConnectHost("example.com", ok)

	serve := func(method, target string) int {
		rw := httptest.NewRecorder()
		r.ServeHTTP(rw, httptest.NewRequest(method, target, nil))
		return rw.Code
	}
	require.Equal(t, http.StatusNoContent, serve(http.MethodConnect, "example.com:443"), "a pattern added after * still wins")
	require.Equal(t, http.StatusAccepted, serve(http.MethodConnect, "anything.test:443"))
	require.Equal(t, http.StatusNoContent, serve(http.MethodGet, "http://anything.test/"))
}
