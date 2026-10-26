package handlers

import (
	"bufio"
	"context"
	"crypto/tls"
	"log/slog"
	"net"
	"net/http"
	"sync"

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

	// Issuer issues a certificate for each intercepted host, on every CONNECT request; wrap it in issuer.Cache to
	// keep the certificates.
	//
	// If Issuer is nil, an issuer.Cache of an issuer.SelfSignedCA will be used.
	Issuer issuer.Issuer

	once sync.Once
}

func (s *MITMHandler) init() {
	if s.Handler == nil {
		s.Handler = &HTTPHandler{}
	}
	if s.Issuer == nil {
		s.Issuer = &issuer.Cache{Issuer: &issuer.SelfSignedCA{}}
	}
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

	accept := connectAcceptor(rw, rq)
	if accept == nil {
		s.httpError(rw, http.StatusInternalServerError)
		panic("underlying http.ResponseWriter MUST implement http.Hijacker or ConnectAcceptor")
	}

	cert, err := s.certForRequest(rq)
	if err != nil {
		s.httpError(rw, http.StatusInternalServerError)
		log.Warn(rq, "failed to issue certificate", "error", err)
		return
	}

	conn, bufrw, err := accept()
	if err != nil {
		s.httpError(rw, http.StatusInternalServerError)
		log.Warn(rq, "failed to accept client connection", "error", err)
		return
	}
	defer conn.Close()

	tlsconn := tls.Server(newBufferedConn(conn, bufrw.Reader), &tls.Config{
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
	hostname := rq.URL.Hostname()
	if ip := net.ParseIP(hostname); ip != nil {
		return s.Issuer.Issue(ip.String(), nil, []net.IP{ip})
	}
	return s.Issuer.Issue(hostname, []string{hostname}, nil)
}
