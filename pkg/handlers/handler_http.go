package handlers

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httputil"
	"runtime"
	"sync"
	"time"

	"go.uber.org/zap"

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
}

func (s *HTTPHandler) transport() http.RoundTripper {
	if s.Transport != nil {
		return s.Transport
	}
	return DefaultTransport
}

func (s *HTTPHandler) httpError(rw http.ResponseWriter, code int) {
	http.Error(rw, http.StatusText(code), code)
}

var hopHeaders = []string{
	"Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Te",
	"Trailer", // not Trailers, there's a typo in RFC; http://www.rfc-editor.org/errata_search.php?eid=4522
	"Transfer-Encoding",
	"Upgrade",
	"Proxy-Connection", // non-standard but still sent by libcurl
}

// removeHopHeaders removes hop-by-hop headers defined in https://tools.ietf.org/html/rfc2616#section-13.5.1
func (s *HTTPHandler) removeHopHeaders(rq *http.Request) *http.Request {
	for _, name := range hopHeaders {
		rq.Header.Del(name)
	}
	return rq
}

// removeConnectionHeaders removes headers listed in `Connection` header as defined in
// https://tools.ietf.org/html/rfc2616#section-14.10
func (s *HTTPHandler) removeConnectionHeaders(rq *http.Request) *http.Request {
	for _, name := range rq.Header.Values("connection") {
		rq.Header.Del(name)
	}
	return rq
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

	rq = rq.Clone(rq.Context())
	rq.RequestURI = ""
	s.removeHopHeaders(rq)
	s.removeConnectionHeaders(rq)

	rs, err := s.transport().RoundTrip(rq)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			s.httpError(rw, http.StatusGatewayTimeout)
			return
		}
		s.httpError(rw, http.StatusBadGateway)
		return
	}
	defer rs.Body.Close()

	n, err := s.writeResponse(rw, rs)
	if err != nil {
		log.Debug(rq, "client response write failed", zap.Error(err))
	}
	log.WithStatus(rq, rs.StatusCode)
	log.WithContentLength(rq, int(n))

	return
}

func (s *HTTPHandler) writeResponse(rw http.ResponseWriter, rs *http.Response) (int64, error) {
	hj, ok := rw.(http.Hijacker)
	if !ok {
		return 0, errors.New("response writer must implement http.Hijacker")
	}
	conn, buf, err := hj.Hijack()
	if err != nil {
		return 0, fmt.Errorf("connection hijack failed: %w", err)
	}
	defer conn.Close()
	defer buf.Flush()
	if rs.ContentLength < 0 {
		return s.writeResponseWriterChunked(buf, rs)
	}
	return s.writeResponseWriter(buf, rs)
}

func (s *HTTPHandler) writeResponseWriter(w io.Writer, res *http.Response) (int64, error) {
	return res.ContentLength, res.Write(w)
}

func (s *HTTPHandler) writeResponseWriterChunked(w io.Writer, rs *http.Response) (size int64, err error) {
	var (
		pr, pw = io.Pipe()
		wg     = sync.WaitGroup{}
	)
	wg.Add(1)

	go func() {
		sc := bufio.NewScanner(pr)
		for sc.Scan() && sc.Text() != "" {
		}
		size, _ = io.Copy(ioutil.Discard, httputil.NewChunkedReader(pr))
		_, _ = io.Copy(ioutil.Discard, pr)
		wg.Done()
	}()

	err = rs.Write(io.MultiWriter(w, pw))
	_, _ = pr.Close(), pw.Close()
	wg.Wait()

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
