package handlers

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	arc "github.com/hashicorp/golang-lru/arc/v2"

	"sarak.sh/mikluko/multiproxy/pkg/issuer"
	"sarak.sh/mikluko/multiproxy/pkg/middleware/log"
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

	// CertCacheSize specifies the size of certificate cache used by the proxy. A cached certificate past its
	// NotAfter is issued again.
	//
	// If CertCacheSize is 0, platform-specific max int value will be used.
	CertCacheSize int

	once sync.Once

	certCache    *arc.ARCCache[string, *certCacheEntry]
	certCacheMux sync.Mutex
}

type certCacheEntry struct {
	cert *tls.Certificate
	mux  sync.Mutex
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
	s.certCache, _ = arc.NewARC[string, *certCacheEntry](s.CertCacheSize)
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
		log.Warn(rq, "failed to hijack client connection", "error", err)
		return
	}
	defer conn.Close()

	_, _ = fmt.Fprintf(bufrw, "HTTP/1.1 200 OK\r\n\r\n")
	_ = bufrw.Flush()

	cert, err := s.certForRequest(rq)
	if err != nil {
		s.httpError(rw, http.StatusInternalServerError)
		log.Warn(rq, "failed to issue certificate", "error", err)
		return
	}

	client := &mitmCounterConn{Conn: newBufferedConn(conn, bufrw.Reader)}
	defer func() {
		log.WithStatusCode(rq, http.StatusOK)
		log.WithContentLength(rq, int(client.bytesWritten.Load()))
	}()

	tlsconn := tls.Server(client, &tls.Config{
		Certificates: []tls.Certificate{*cert},
	})
	if err := tlsconn.Handshake(); err != nil {
		log.Warn(rq, "TLS handshake failed", "error", err)
		return
	}
	defer tlsconn.Close()

	s.serve(rq, tlsconn)
}

// serve answers the requests the client sends over conn through Handler, until conn is closed, whether by the
// server or by a handler that hijacked it. Each request gets connect's context, so that it is logged and traced
// inside the CONNECT session.
func (s *MITMHandler) serve(connect *http.Request, conn net.Conn) {
	c := &closeSignalConn{Conn: conn, done: make(chan struct{})}
	srv := &http.Server{
		Handler: http.HandlerFunc(func(rw http.ResponseWriter, rq *http.Request) {
			rq.URL.Scheme = "https"
			rq.URL.Host = rq.Host
			s.Handler.ServeHTTP(rw, rq)
		}),
		BaseContext: func(net.Listener) context.Context { return connect.Context() },
		ErrorLog:    slog.NewLogLogger(log.Logger(connect).Handler(), slog.LevelDebug),
	}
	_ = srv.Serve(&singleConnListener{conn: c})
}

// singleConnListener accepts conn once, then blocks until conn is closed and reports itself closed.
type singleConnListener struct {
	conn     *closeSignalConn
	accepted bool
}

func (l *singleConnListener) Accept() (net.Conn, error) {
	if !l.accepted {
		l.accepted = true
		return l.conn, nil
	}
	<-l.conn.done
	return nil, net.ErrClosed
}

func (l *singleConnListener) Close() error { return nil }

func (l *singleConnListener) Addr() net.Addr { return l.conn.LocalAddr() }

// closeSignalConn closes done once it is closed.
type closeSignalConn struct {
	net.Conn
	once sync.Once
	done chan struct{}
}

func (c *closeSignalConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() { close(c.done) })
	return err
}

// bufferedConn reads first the bytes the hijacking reader had already buffered from the client, then conn itself.
// Reading on through that reader instead would hand read errors, deadline aborts included, to the HTTP server that
// owns it, which cancels the CONNECT request's context.
type bufferedConn struct {
	net.Conn
	pending []byte
}

func newBufferedConn(conn net.Conn, r *bufio.Reader) *bufferedConn {
	pending, _ := r.Peek(r.Buffered())
	return &bufferedConn{Conn: conn, pending: append([]byte(nil), pending...)}
}

func (c *bufferedConn) Read(p []byte) (int, error) {
	if len(c.pending) > 0 {
		n := copy(p, c.pending)
		c.pending = c.pending[n:]
		return n, nil
	}
	return c.Conn.Read(p)
}

func (s *MITMHandler) certForRequest(rq *http.Request) (*tls.Certificate, error) {
	var (
		hostname    = rq.URL.Hostname()
		cn          = hostname
		dnsnames    []string
		ipaddresses []net.IP
		err         error
		entry       *certCacheEntry
	)

	if ip := net.ParseIP(hostname); ip != nil {
		cn = ip.String()
		ipaddresses = []net.IP{ip}
	} else {
		dnsnames = []string{hostname}
	}

	s.certCacheMux.Lock()
	if x, ok := s.certCache.Get(cn); ok {
		entry = x
	} else {
		entry = &certCacheEntry{}
		s.certCache.Add(cn, entry)
	}
	entry.mux.Lock()
	defer entry.mux.Unlock()

	s.certCacheMux.Unlock()

	if entry.cert == nil || !time.Now().Before(entry.cert.Leaf.NotAfter) {
		entry.cert, err = s.Issuer.Issue(cn, dnsnames, ipaddresses)
		if err != nil {
			return nil, err
		}
	}

	return entry.cert, nil
}

// mitmCounterConn counts the bytes written to the client.
type mitmCounterConn struct {
	net.Conn
	bytesWritten atomic.Int64
}

func (c *mitmCounterConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	c.bytesWritten.Add(int64(n))
	return n, err
}
