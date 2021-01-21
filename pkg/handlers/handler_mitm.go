package handlers

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"sync"

	lru "github.com/hashicorp/golang-lru"
	"go.uber.org/zap"
	"golang.org/x/net/publicsuffix"

	"github.com/akabos/multiproxy/pkg/issuer"
	"github.com/akabos/multiproxy/pkg/middleware/log"
)

// MITMHandler is an HTTP proxy which handles CONNECT requests using  Man-in-the-Middle technique.
//
// The zero value of MITMHandler is a valid http.Handler.
type MITMHandler struct {
	// Handler is an optional http.Handler which will be used by the proxy to serve intercepted sub-requests
	//
	// If nil, zero value of HTTPProxy will be used.
	Handler http.Handler

	// Issuer specifies optional certificate issuer.
	//
	// If Issuer is nil, issuer.SelfSignedCA will be used.
	Issuer issuer.Issuer

	// CertCacheSize specifies the size of certificate cache used by the proxy.
	//
	// If CertCacheSize is 0, platform-specific max int value will be used.
	CertCacheSize int

	once sync.Once

	certCache    *lru.ARCCache
	certCacheMux sync.Mutex
}

func (s *MITMHandler) init() {
	if s.Handler == nil {
		s.Handler = &HTTPHandler{}
	}
	if s.Issuer == nil {
		s.Issuer = &issuer.SelfSignedCA{}
	}
	if s.CertCacheSize == 0 {
		s.CertCacheSize = int(^uint(0) >> 1)
	}
	s.certCache, _ = lru.NewARC(s.CertCacheSize)
}

func (s *MITMHandler) httpError(rw http.ResponseWriter, code int) {
	http.Error(rw, http.StatusText(code), code)
}

//goland:noinspection GoUnhandledErrorResult
func (s *MITMHandler) ServeHTTP(rw http.ResponseWriter, rq *http.Request) {
	s.once.Do(s.init)

	if rq.Method != http.MethodConnect {
		s.httpError(rw, http.StatusMethodNotAllowed)
		return
	}

	hj, ok := rw.(http.Hijacker)
	if !ok {
		s.httpError(rw, http.StatusInternalServerError)
		panic("underlying http.ResponseWriter MUST implement http.Hijacker")
		return
	}

	conn, bufrw, err := hj.Hijack()
	if err != nil {
		s.httpError(rw, http.StatusInternalServerError)
		log.Warn(rq, "failed to hijack client connection", zap.Error(err))
		return
	}
	defer conn.Close()

	_, _ = fmt.Fprintf(bufrw, "HTTP/1.1 200 OK\r\n\r\n")
	_ = bufrw.Flush()

	cert, err := s.certForRequest(rq)
	if err != nil {
		s.httpError(rw, http.StatusInternalServerError)
		log.Warn(rq, "failed to issue certificate", zap.Error(err))
		return
	}

	mitmconn := mitmCounterConn{
		Conn: conn,
	}
	defer func() {
		log.WithStatusCode(rq, http.StatusOK)
		log.WithContentLength(rq, mitmconn.bytesWritten)
	}()

	tlsconn := tls.Server(&mitmconn, &tls.Config{
		Certificates: []tls.Certificate{*cert},
	})
	err = tlsconn.Handshake()
	if err != nil {
		log.Warn(rq, "TLS handshake failed", zap.Error(err))
		return
	}
	defer tlsconn.Close()

	for seq := uint64(1); true; seq++ {
		err = s.roundTrip(rq.Context(), tlsconn)
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			log.Debug(rq, "sub-request failed", zap.Uint64("sub-seq", seq), zap.Error(err))
			break
		}
	}
}

func (s *MITMHandler) roundTrip(ctx context.Context, conn net.Conn) error {
	rq, err := http.ReadRequest(bufio.NewReader(conn))
	if err != nil {
		return err
	}
	rq = rq.WithContext(ctx)

	rq.URL, _ = url.Parse("https://" + rq.Host + rq.URL.String())
	rq.RemoteAddr = conn.RemoteAddr().String()

	rw := mitmResponseWriter{conn: &mitmNoopCloseConn{conn}}
	s.Handler.ServeHTTP(&rw, rq)
	return rw.Close()
}

func (s *MITMHandler) certForRequest(rq *http.Request) (*tls.Certificate, error) {
	type cacheEntry struct {
		cert *tls.Certificate
		mux  sync.Mutex
	}
	var (
		hostname    = rq.URL.Hostname()
		cn          string
		dnsnames    []string
		ipaddresses []net.IP
		err         error
		entry       *cacheEntry
	)

	tldplus, err := publicsuffix.EffectiveTLDPlusOne(hostname)
	if err != nil {
		cn = tldplus
		dnsnames = append(dnsnames, tldplus, "."+tldplus)
	} else {
		cn = hostname
	}
	if ip := net.ParseIP(hostname); ip != nil {
		cn = ip.String()
		ipaddresses = append(ipaddresses, ip)
	}

	s.certCacheMux.Lock()
	if x, ok := s.certCache.Get(cn); ok {
		entry, ok = x.(*cacheEntry)
		if !ok {
			panic("invalid value in cache")
		}
	} else {
		entry = &cacheEntry{}
		s.certCache.Add(cn, entry)
	}
	entry.mux.Lock()
	defer entry.mux.Unlock()

	s.certCacheMux.Unlock()

	if entry.cert == nil {
		entry.cert, err = s.Issuer.Issue(cn, dnsnames, ipaddresses)
		if err != nil {
			return nil, err
		}
	}

	return entry.cert, nil
}

// mitmResponseWriter implements http.ResponseWriter
//
// not thread-safe
type mitmResponseWriter struct {
	conn       net.Conn
	body       bytes.Buffer
	header     http.Header
	statusCode int
	hijacked   bool
}

// Header implements http.ResponseWriter interface
func (rw *mitmResponseWriter) Header() http.Header {
	if rw.header == nil {
		rw.header = http.Header{}
	}
	return rw.header
}

// Write implements http.ResponseWriter interface
func (rw *mitmResponseWriter) Write(p []byte) (int, error) {
	// We put writes into the buffer and flush it upon response writer Close() call. It is not efficient memory-wise for
	// large responses, but should be okay in this particular case since the underlying handler would only write
	// directly in case of error responses which would be very small.
	return rw.body.Write(p)
}

// WriteHeader implements http.ResponseWriter interface
func (rw *mitmResponseWriter) WriteHeader(statusCode int) {
	if rw.statusCode != 0 {
		panic("spurious header write")
	}
	rw.statusCode = statusCode
}

func (rw *mitmResponseWriter) Close() error {
	if rw.hijacked {
		return nil
	}
	return (&http.Response{
		ProtoMajor:       1,
		ProtoMinor:       1,
		StatusCode:       rw.statusCode,
		Header:           rw.header,
		Body:             ioutil.NopCloser(&rw.body),
		ContentLength:    int64(rw.body.Len()),
		TransferEncoding: []string{"identity"},
	}).Write(rw.conn)
}

// Hijack implements http.Hijacker interface
func (rw *mitmResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if rw.hijacked {
		panic("spurious connection hijack")
	}
	rw.hijacked = true
	return rw.conn, bufio.NewReadWriter(bufio.NewReader(rw.conn), bufio.NewWriter(rw.conn)), nil
}

type mitmCounterConn struct {
	net.Conn
	bytesWritten int
}

// Write wraps net.Conn
func (c *mitmCounterConn) Write(p []byte) (n int, err error) {
	n, err = c.Conn.Write(p)
	c.bytesWritten += n
	return
}

type mitmNoopCloseConn struct {
	net.Conn
}

// Close wraps net.Conn
func (c *mitmNoopCloseConn) Close() error {
	return nil
}
