package handlers

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"

	"sarak.sh/mikluko/multiproxy/pkg/middleware/log"
)

// ConnectAcceptor is implemented by a ResponseWriter whose client is answered in a protocol of its own, as the
// SOCKS5 server's is. AcceptConnect tells the client that the connection to the target is established, and returns
// the client connection with a reader holding whatever the client already sent. Tunnel and MITMHandler call it in
// place of hijacking the connection and writing a 200 response.
//
// A refusal before AcceptConnect is written as an HTTP status, through WriteHeader.
type ConnectAcceptor interface {
	AcceptConnect() (net.Conn, *bufio.ReadWriter, error)
}

// connectAcceptor returns how to accept the CONNECT request rq on rw: the ConnectAcceptor rw implements, directly or
// behind a chain of Unwrap methods, or else hijacking rw and writing a 200 response. It returns nil where rw offers
// neither.
//
// An accepted session is recorded in the request's access log with status 200 and, once the returned connection is
// closed, with the number of bytes written to the client.
func connectAcceptor(rw http.ResponseWriter, rq *http.Request) func() (net.Conn, *bufio.ReadWriter, error) {
	accept := acceptorOf(rw)
	if accept == nil {
		return nil
	}
	return func() (net.Conn, *bufio.ReadWriter, error) {
		conn, bufrw, err := accept()
		if err != nil {
			return nil, nil, err
		}
		log.WithStatusCode(rq, http.StatusOK)
		c := &countingConn{Conn: conn, rq: rq}
		return c, bufio.NewReadWriter(bufrw.Reader, bufio.NewWriter(c)), nil
	}
}

func acceptorOf(rw http.ResponseWriter) func() (net.Conn, *bufio.ReadWriter, error) {
	var hj http.Hijacker
	for w := rw; w != nil; {
		if a, ok := w.(ConnectAcceptor); ok {
			return a.AcceptConnect
		}
		if h, ok := w.(http.Hijacker); ok && hj == nil {
			hj = h
		}
		u, ok := w.(interface{ Unwrap() http.ResponseWriter })
		if !ok {
			break
		}
		w = u.Unwrap()
	}
	if hj == nil {
		return nil
	}
	return func() (net.Conn, *bufio.ReadWriter, error) {
		conn, bufrw, err := hj.Hijack()
		if err != nil {
			return nil, nil, err
		}
		if _, err := io.WriteString(bufrw, "HTTP/1.1 200 OK\r\n\r\n"); err != nil {
			_ = conn.Close()
			return nil, nil, err
		}
		if err := bufrw.Flush(); err != nil {
			_ = conn.Close()
			return nil, nil, err
		}
		return conn, bufrw, nil
	}
}

// countingConn counts the bytes written to the client and records them in rq's access log when it is closed.
type countingConn struct {
	net.Conn
	rq      *http.Request
	written atomic.Int64
	once    sync.Once
}

func (c *countingConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	c.written.Add(int64(n))
	return n, err
}

func (c *countingConn) Close() error {
	c.once.Do(func() { log.WithContentLength(c.rq, int(c.written.Load())) })
	return c.Conn.Close()
}
