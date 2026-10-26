package handlers

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"sarak.sh/mikluko/multiproxy/pkg/middleware/log"
)

// Tunnel is a proxy server capable of serving CONNECT requests.
//
// The zero value of Tunnel is a valid instance.
type Tunnel struct {

	// DialContext specifies the dial function for creating unencrypted TCP connections.
	//
	// If DialContext is nil then the proxy dials using package net.
	DialContext func(context.Context, string, string) (net.Conn, error)

	// DialTimeout specifies an optional timeout for the dialer to establish upstream connection.
	DialTimeout time.Duration

	once sync.Once
}

func (s *Tunnel) init() {
	if s.DialContext == nil {
		d := net.Dialer{}
		s.DialContext = d.DialContext
	}
}

func (s *Tunnel) httpError(rw http.ResponseWriter, rq *http.Request, code int) {
	http.Error(rw, http.StatusText(code), code)
}

func (s *Tunnel) ServeHTTP(rw http.ResponseWriter, rq *http.Request) {
	if rq.Method != http.MethodConnect {
		s.httpError(rw, rq, http.StatusMethodNotAllowed)
		return
	}

	accept := connectAcceptor(rw, rq)
	if accept == nil {
		s.httpError(rw, rq, http.StatusInternalServerError)
		log.Panic(rq, "underlying http.ResponseWriter MUST implement http.Hijacker or ConnectAcceptor")
		return
	}

	s.once.Do(s.init)

	u, err := s.dialContext(rq.Context(), "tcp", rq.RequestURI)
	if err != nil {
		werr := errors.Unwrap(err)
		if werr != nil && werr.Error() == "i/o timeout" {
			s.httpError(rw, rq, http.StatusGatewayTimeout)
		} else {
			s.httpError(rw, rq, http.StatusBadGateway)
		}
		return
	}
	defer u.Close()

	conn, bufrw, err := accept()
	if err != nil {
		s.httpError(rw, rq, http.StatusInternalServerError)
		log.Warn(rq, "failed to accept client connection", "error", err)
		return
	}
	defer conn.Close()

	wg := sync.WaitGroup{}
	wg.Add(2)

	go func() {
		defer wg.Done()
		_, err := s.copy(u, bufrw.Reader)
		if err != nil {
			log.Debug(rq, "client -> upstream copy error", "error", err)
		}
	}()
	go func() {
		defer wg.Done()
		_, err := s.copy(conn, u)
		if err != nil {
			log.Debug(rq, "upstream -> client copy error", "error", err)
		}
	}()

	wg.Wait()
}

func (s *Tunnel) copy(dst io.Writer, src io.Reader) (int, error) {
	n, err := io.Copy(dst, src)
	switch {
	case errors.Is(err, io.EOF):
		return int(n), nil
	case errors.Is(err, os.ErrDeadlineExceeded):
		return int(n), nil
	default:
		return int(n), err
	}
}

func (s *Tunnel) dialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if s.DialTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, s.DialTimeout)
		defer cancel()
	}
	return s.DialContext(ctx, network, addr)
}
