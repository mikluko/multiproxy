package handlers

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"runtime"
	"sync"
	"time"

	"github.com/akabos/multiproxy/pkg/middleware/log"
)

// HTTPHandler is a plain HTTP proxy capable of serving any method except for CONNECT.
//
// The zero value for HTTPHandler is a valid instance.
type HTTPHandler struct {
	// Transport specifies optional transport to use for making requests to target servers.
	//
	// If Transport is nil, DefaultTransport is used.
	Transport http.RoundTripper

	once  sync.Once
	proxy *httputil.ReverseProxy
}

func (s *HTTPHandler) httpError(rw http.ResponseWriter, code int) {
	http.Error(rw, http.StatusText(code), code)
}

type httpHandlerCtxKey struct {}

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
			Transport: s.Transport,
			Director:  s.director,
			ModifyResponse: s.modifyResponse,
			ErrorHandler: s.handleError,
		}
	})

	wg := sync.WaitGroup{}
	ctx := context.WithValue(rq.Context(), httpHandlerCtxKey{}, &wg)

	s.proxy.ServeHTTP(rw, rq.WithContext(ctx))

	wg.Wait()
	return
}

func (s *HTTPHandler) director(rq *http.Request) {
	rq.RequestURI = ""
}

func (s *HTTPHandler) modifyResponse(rs *http.Response) error {
	rq := rs.Request

	log.WithStatusCode(rq, rs.StatusCode)
	if rs.ContentLength >= 0 {
		log.WithContentLength(rq, int(rs.ContentLength))
		return nil
	}

	wg := rq.Context().Value(httpHandlerCtxKey{}).(*sync.WaitGroup)
	wg.Add(1)

	var r, w = io.Pipe()

	go func(dst io.WriteCloser, src io.ReadCloser) {
		length, _ := io.Copy(dst, src)
		_ = src.Close()
		_ = dst.Close()
		log.WithContentLength(rq, int(length))
		wg.Done()
	}(w, rs.Body)

	rs.Body = r
	return nil
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
