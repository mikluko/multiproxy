// Package socks5 is a SOCKS5 server, RFC 1928, that hands each connection to an http.Handler as a CONNECT
// request, so that SOCKS clients are routed by the same rules as HTTP proxy clients.
//
// Only the CONNECT command and the no-authentication method are supported.
package socks5

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

// Server accepts SOCKS5 connections and serves each CONNECT as an HTTP CONNECT request to Handler.
//
// The handler accepts the connection through the AcceptConnect method of its ResponseWriter, which satisfies
// handlers.ConnectAcceptor and answers the client with success. A status written before it is a refusal: 403 or 405
// is answered as refused by ruleset, 502 as host unreachable, 504 as TTL expired, and anything else as a general
// failure. The ResponseWriter cannot be hijacked.
type Server struct {
	// Handler serves the CONNECT requests.
	Handler http.Handler

	// HandshakeTimeout bounds the negotiation before the request reaches Handler.
	//
	// If 0, DefaultHandshakeTimeout will be used.
	HandshakeTimeout time.Duration
}

// DefaultHandshakeTimeout is the default bound on a client's negotiation.
const DefaultHandshakeTimeout = 10 * time.Second

// Serve accepts connections on l and serves each in its own goroutine. It returns the error that stops Accept.
func (s *Server) Serve(l net.Listener) error {
	for {
		c, err := l.Accept()
		if err != nil {
			return err
		}
		go s.ServeConn(c)
	}
}

// ServeConn serves one SOCKS5 connection and closes it.
func (s *Server) ServeConn(c net.Conn) {
	defer c.Close()

	timeout := s.HandshakeTimeout
	if timeout == 0 {
		timeout = DefaultHandshakeTimeout
	}
	_ = c.SetDeadline(time.Now().Add(timeout))
	br := bufio.NewReader(c)
	target, err := handshake(br, c)
	if err != nil {
		return
	}
	_ = c.SetDeadline(time.Time{})

	rq := &http.Request{
		Method:     http.MethodConnect,
		URL:        &url.URL{Host: target},
		Host:       target,
		RequestURI: target,
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     http.Header{},
		RemoteAddr: c.RemoteAddr().String(),
	}
	rw := &responseWriter{conn: c, r: br, header: http.Header{}}
	s.Handler.ServeHTTP(rw, rq)
	if !rw.replied {
		rw.WriteHeader(http.StatusOK)
	}
}

const (
	version         = 5
	methodNoAuth    = 0
	methodNone      = 0xff
	cmdConnect      = 1
	atypIPv4        = 1
	atypDomain      = 3
	atypIPv6        = 4
	repSucceeded    = 0
	repFailure      = 1
	repNotAllowed   = 2
	repUnreachable  = 4
	repTTLExpired   = 6
	repCmdNotSupp   = 7
	repAtypNotSuppl = 8
)

var errProtocol = errors.New("socks5: protocol error")

// handshake negotiates the method and reads the request, answering errors itself. It returns the target as
// host:port.
func handshake(r *bufio.Reader, w io.Writer) (string, error) {
	head := make([]byte, 2)
	if _, err := io.ReadFull(r, head); err != nil {
		return "", err
	}
	if head[0] != version {
		return "", errProtocol
	}
	methods := make([]byte, head[1])
	if _, err := io.ReadFull(r, methods); err != nil {
		return "", err
	}
	if bytes.IndexByte(methods, methodNoAuth) < 0 {
		_, _ = w.Write([]byte{version, methodNone})
		return "", errProtocol
	}
	if _, err := w.Write([]byte{version, methodNoAuth}); err != nil {
		return "", err
	}

	rq := make([]byte, 4)
	if _, err := io.ReadFull(r, rq); err != nil {
		return "", err
	}
	if rq[0] != version {
		return "", errProtocol
	}
	if rq[1] != cmdConnect {
		_ = reply(w, repCmdNotSupp)
		return "", errProtocol
	}
	var host string
	switch rq[3] {
	case atypIPv4, atypIPv6:
		ip := make(net.IP, 4)
		if rq[3] == atypIPv6 {
			ip = make(net.IP, 16)
		}
		if _, err := io.ReadFull(r, ip); err != nil {
			return "", err
		}
		host = ip.String()
	case atypDomain:
		n, err := r.ReadByte()
		if err != nil {
			return "", err
		}
		name := make([]byte, n)
		if _, err := io.ReadFull(r, name); err != nil {
			return "", err
		}
		host = string(name)
	default:
		_ = reply(w, repAtypNotSuppl)
		return "", errProtocol
	}
	port := make([]byte, 2)
	if _, err := io.ReadFull(r, port); err != nil {
		return "", err
	}
	return net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(port)))), nil
}

// reply writes a reply with code and an unspecified bound address.
func reply(w io.Writer, code byte) error {
	_, err := w.Write([]byte{version, code, 0, atypIPv4, 0, 0, 0, 0, 0, 0})
	return err
}

// replyFor maps an HTTP status to a reply code.
func replyFor(status int) byte {
	switch status {
	case http.StatusOK:
		return repSucceeded
	case http.StatusForbidden, http.StatusMethodNotAllowed:
		return repNotAllowed
	case http.StatusBadGateway:
		return repUnreachable
	case http.StatusGatewayTimeout:
		return repTTLExpired
	default:
		return repFailure
	}
}

// responseWriter answers the SOCKS client for a handler: with success from AcceptConnect, or with the reply its status
// maps to where the handler writes a response instead. A response body is discarded.
type responseWriter struct {
	conn    net.Conn
	r       *bufio.Reader
	header  http.Header
	replied bool
}

func (rw *responseWriter) Header() http.Header { return rw.header }

func (rw *responseWriter) WriteHeader(status int) {
	if rw.replied {
		return
	}
	code := replyFor(status)
	if code == repSucceeded {
		code = repFailure
	}
	_ = rw.reply(code)
}

func (rw *responseWriter) Write(p []byte) (int, error) {
	if !rw.replied {
		rw.WriteHeader(http.StatusOK)
	}
	return len(p), nil
}

// AcceptConnect answers the client with success and returns its connection, reading first what the handshake
// buffered.
func (rw *responseWriter) AcceptConnect() (net.Conn, *bufio.ReadWriter, error) {
	if rw.replied {
		return nil, nil, errors.New("socks5: accept after reply")
	}
	if err := rw.reply(repSucceeded); err != nil {
		return nil, nil, err
	}
	c := &conn{Conn: rw.conn, r: rw.r}
	return c, bufio.NewReadWriter(rw.r, bufio.NewWriter(rw.conn)), nil
}

func (rw *responseWriter) reply(code byte) error {
	rw.replied = true
	return reply(rw.conn, code)
}

// conn is the client connection, reading first what the handshake buffered.
type conn struct {
	net.Conn
	r *bufio.Reader
}

func (c *conn) Read(p []byte) (int, error) { return c.r.Read(p) }
