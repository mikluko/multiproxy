package handlers_test

import (
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/mccutchen/go-httpbin/v2/httpbin"

	"sarak.sh/mikluko/multiproxy/pkg/handlers"
)

var (
	testServer    *httptest.Server
	testTLSServer *httptest.Server

	// trustingUpstream trusts the certificate every httptest TLS server shares.
	trustingUpstream http.RoundTripper
)

// trustingMITM is a MITMHandler whose upstream requests trust httptest TLS servers.
func trustingMITM() *handlers.MITMHandler {
	return &handlers.MITMHandler{Handler: &handlers.HTTPHandler{Transport: trustingUpstream}}
}

func TestMain(m *testing.M) {
	testServer = httptest.NewServer(httpbin.New().Handler())
	defer testServer.Close()

	testTLSServer = httptest.NewTLSServer(httpbin.New().Handler())
	defer testTLSServer.Close()
	trustingUpstream = testTLSServer.Client().Transport

	os.Exit(m.Run())
}

type testGetResponse struct {
	Args    url.Values  `json:"args"`
	Headers http.Header `json:"headers"`
	Origin  string      `json:"origin"`
	URL     string      `json:"url"`
}

type testBodyResponse struct {
	Args    url.Values  `json:"args"`
	Headers http.Header `json:"headers"`
	Origin  string      `json:"origin"`
	URL     string      `json:"url"`

	Data  string              `json:"data"`
	Files map[string][]string `json:"files"`
	Form  map[string][]string `json:"form"`
	JSON  interface{}         `json:"json"`
}

func testTransport(proxy string) *http.Transport {
	return &http.Transport{
		Proxy: func(rq *http.Request) (*url.URL, error) {
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
