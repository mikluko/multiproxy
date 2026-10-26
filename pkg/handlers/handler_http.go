package handlers

import (
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httputil"
	"runtime"
	"sync"
	"time"
)

// HTTPHandler is a plain HTTP proxy capable of serving any method except for CONNECT.
//
// The zero value for HTTPHandler is a valid instance.
type HTTPHandler struct {
	// Transport specifies optional transport to use for making requests to target servers.
	//
	// If Transport is nil, DefaultTransport is used.
	Transport http.RoundTripper

	// Instruct httputil.ReverseProxy to skip the addition of X-Forwarded-For header
	NoXForwardedFor bool

	once  sync.Once
	proxy *httputil.ReverseProxy
}

func (s *HTTPHandler) httpError(rw http.ResponseWriter, code int) {
	http.Error(rw, http.StatusText(code), code)
}

func (s *HTTPHandler) ServeHTTP(rw http.ResponseWriter, rq *http.Request) {
	if rq.URL.Host == "" {
		s.httpError(rw, http.StatusBadRequest)
		return
	}
	if rq.Method == http.MethodConnect {
		s.httpError(rw, http.StatusMethodNotAllowed)
		return
	}

	s.once.Do(func() {
		if s.Transport == nil {
			s.Transport = DefaultTransport
		}
		s.proxy = &httputil.ReverseProxy{
			Transport:    s.Transport,
			Director:     s.director,
			ErrorHandler: s.handleError,
		}
	})

	s.proxy.ServeHTTP(rw, rq)
}

func (s *HTTPHandler) director(rq *http.Request) {
	rq.RequestURI = ""
	if s.NoXForwardedFor {
		rq.Header["X-Forwarded-For"] = nil
	}
}

func (s *HTTPHandler) handleError(rw http.ResponseWriter, rq *http.Request, err error) {
	if _, ok := err.(*net.OpError); ok {
		http.Error(rw, http.StatusText(http.StatusBadGateway), http.StatusBadGateway)
		return
	}
	http.Error(rw, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
	return
}

// DefaultTransport is the default transport for HTTPHandler to execute HTTP requests
var DefaultTransport = &http.Transport{
	Proxy: http.ProxyFromEnvironment,
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
	DisableCompression: true,
	DisableKeepAlives:  false,
}
