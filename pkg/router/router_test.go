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

	"github.com/mccutchen/go-httpbin/httpbin"
	"github.com/stretchr/testify/require"

	"github.com/akabos/multiproxy/pkg/handlers"
	router2 "github.com/akabos/multiproxy/pkg/router"
)

var (
	testServer    *httptest.Server
	testTLSServer *httptest.Server
)

func TestMain(m *testing.M) {
	testServer = httptest.NewServer(httpbin.NewHTTPBin().Handler())
	defer testServer.Close()

	testTLSServer = httptest.NewTLSServer(httpbin.NewHTTPBin().Handler())
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
	d := &handlers.HTTPHandler{}
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
