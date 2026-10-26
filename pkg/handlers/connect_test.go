package handlers_test

import (
	"bufio"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"sarak.sh/mikluko/multiproxy/pkg/handlers"
)

// acceptor is a ResponseWriter for a front end that answers an accepted CONNECT in its own protocol.
type acceptor struct {
	httptest.ResponseRecorder
	conn     net.Conn
	accepted chan struct{}
}

func (a *acceptor) AcceptConnect() (net.Conn, *bufio.ReadWriter, error) {
	close(a.accepted)
	return a.conn, bufio.NewReadWriter(bufio.NewReader(a.conn), bufio.NewWriter(a.conn)), nil
}

// wrapped hides the acceptor behind an Unwrap method, as middleware such as otelhttp does.
type wrapped struct{ http.ResponseWriter }

func (w wrapped) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func TestConnectAcceptor(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(rw, "hello")
	}))
	defer upstream.Close()
	target := upstream.Listener.Addr().String()

	for name, h := range map[string]http.Handler{
		"tunnel": &handlers.Tunnel{},
		"mitm":   trustingMITM(),
	} {
		for _, unwrap := range []bool{false, true} {
			t.Run(name+map[bool]string{false: "", true: " behind Unwrap"}[unwrap], func(t *testing.T) {
				server, client := net.Pipe()
				defer client.Close()
				require.NoError(t, client.SetDeadline(time.Now().Add(5*time.Second)))
				a := &acceptor{ResponseRecorder: *httptest.NewRecorder(), conn: server, accepted: make(chan struct{})}
				var rw http.ResponseWriter = a
				if unwrap {
					rw = wrapped{a}
				}
				rq := httptest.NewRequest(http.MethodConnect, "https://"+target, nil)
				rq.Host = target
				rq.RequestURI = target
				rq.URL.Host = target
				go h.ServeHTTP(rw, rq)

				<-a.accepted
				tc := tls.Client(client, &tls.Config{InsecureSkipVerify: true})
				require.NoError(t, tc.Handshake(), "the client must see TLS, not an HTTP response")
				_, err := io.WriteString(tc, "GET / HTTP/1.1\r\nHost: "+target+"\r\nConnection: close\r\n\r\n")
				require.NoError(t, err)
				rs, err := http.ReadResponse(bufio.NewReader(tc), nil)
				require.NoError(t, err)
				body, err := io.ReadAll(rs.Body)
				require.NoError(t, err)
				require.Equal(t, "hello", string(body))
			})
		}
	}
}
