package socks5_test

import (
	"bufio"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"sarak.sh/mikluko/multiproxy/pkg/handlers"
	"sarak.sh/mikluko/multiproxy/pkg/issuer"
	"sarak.sh/mikluko/multiproxy/pkg/router"
	"sarak.sh/mikluko/multiproxy/pkg/socks5"
)

// serve starts a SOCKS5 server for h and returns its address.
func serve(t *testing.T, h http.Handler) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = l.Close() })
	go func() { _ = (&socks5.Server{Handler: h}).Serve(l) }()
	return l.Addr().String()
}

// dial opens a SOCKS5 session to server, sends a CONNECT for host:port with address type atyp, and returns the
// connection with the reply code.
func dial(t *testing.T, server string, atyp byte, host string, port int) (net.Conn, byte) {
	t.Helper()
	c, err := net.DialTimeout("tcp", server, time.Second)
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Close() })
	require.NoError(t, c.SetDeadline(time.Now().Add(5*time.Second)))

	_, err = c.Write([]byte{5, 1, 0})
	require.NoError(t, err)
	method := make([]byte, 2)
	_, err = io.ReadFull(c, method)
	require.NoError(t, err)
	require.Equal(t, []byte{5, 0}, method)

	rq := []byte{5, 1, 0, atyp}
	switch atyp {
	case 1:
		rq = append(rq, net.ParseIP(host).To4()...)
	case 3:
		rq = append(rq, byte(len(host)))
		rq = append(rq, host...)
	case 4:
		rq = append(rq, net.ParseIP(host).To16()...)
	}
	rq = binary.BigEndian.AppendUint16(rq, uint16(port))
	_, err = c.Write(rq)
	require.NoError(t, err)

	return c, readReply(t, c)
}

func readReply(t *testing.T, c net.Conn) byte {
	t.Helper()
	head := make([]byte, 4)
	_, err := io.ReadFull(c, head)
	require.NoError(t, err)
	require.Equal(t, byte(5), head[0])
	var skip int
	switch head[3] {
	case 1:
		skip = 4
	case 4:
		skip = 16
	default:
		t.Fatalf("unexpected bound address type %d", head[3])
	}
	_, err = io.ReadFull(c, make([]byte, skip+2))
	require.NoError(t, err)
	return head[1]
}

func hostPort(t *testing.T, rawURL string) (string, int) {
	t.Helper()
	rq, err := http.NewRequest(http.MethodGet, rawURL, nil)
	require.NoError(t, err)
	port, err := strconv.Atoi(rq.URL.Port())
	require.NoError(t, err)
	return rq.URL.Hostname(), port
}

func TestServer(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(rw, "hello")
	}))
	defer upstream.Close()
	tlsUpstream := httptest.NewTLSServer(upstream.Config.Handler)
	defer tlsUpstream.Close()
	host, port := hostPort(t, upstream.URL)
	_, tlsPort := hostPort(t, tlsUpstream.URL)

	getOver := func(t *testing.T, c net.Conn, target string) string {
		t.Helper()
		rq, _ := http.NewRequest(http.MethodGet, target, nil)
		require.NoError(t, rq.Write(c))
		rs, err := http.ReadResponse(bufio.NewReader(c), rq)
		require.NoError(t, err)
		defer rs.Body.Close()
		body, err := io.ReadAll(rs.Body)
		require.NoError(t, err)
		return string(body)
	}

	tunnel := serve(t, &router.Router{Connect: &handlers.Tunnel{}})

	t.Run("tunnels to an IPv4 address", func(t *testing.T) {
		c, code := dial(t, tunnel, 1, host, port)
		require.Equal(t, byte(0), code)
		require.Equal(t, "hello", getOver(t, c, upstream.URL))
	})
	t.Run("tunnels to a domain name", func(t *testing.T) {
		c, code := dial(t, tunnel, 3, "localhost", port)
		require.Equal(t, byte(0), code)
		require.Equal(t, "hello", getOver(t, c, upstream.URL))
	})
	t.Run("intercepts with MITM", func(t *testing.T) {
		ca := &issuer.SelfSignedCA{}
		mitm := serve(t, &router.Router{Connect: &handlers.MITMHandler{
			Issuer:  ca,
			Handler: &handlers.HTTPHandler{Transport: tlsUpstream.Client().Transport},
		}})
		c, code := dial(t, mitm, 1, host, tlsPort)
		require.Equal(t, byte(0), code)
		tc := tls.Client(c, &tls.Config{InsecureSkipVerify: true, ServerName: host})
		require.NoError(t, tc.Handshake())
		require.Equal(t, ca.Cert.Leaf.Subject.CommonName, tc.ConnectionState().PeerCertificates[0].Issuer.CommonName)
		require.Equal(t, "hello", getOver(t, tc, tlsUpstream.URL))
	})
	t.Run("refuses a host no rule admits", func(t *testing.T) {
		r := &router.Router{}
		r.HandleConnectHost("example.com", &handlers.Tunnel{})
		_, code := dial(t, serve(t, r), 1, host, port)
		require.Equal(t, byte(2), code)
	})
	t.Run("reports an unreachable host", func(t *testing.T) {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		_, closed := hostPort(t, "http://"+l.Addr().String())
		require.NoError(t, l.Close())
		_, code := dial(t, tunnel, 1, host, closed)
		require.Equal(t, byte(4), code)
	})
	t.Run("hands the handler a CONNECT request", func(t *testing.T) {
		got := make(chan *http.Request, 1)
		srv := serve(t, http.HandlerFunc(func(rw http.ResponseWriter, rq *http.Request) {
			got <- rq
			rw.WriteHeader(http.StatusForbidden)
		}))
		_, code := dial(t, srv, 4, "::1", 443)
		require.Equal(t, byte(2), code)
		rq := <-got
		require.Equal(t, http.MethodConnect, rq.Method)
		require.Equal(t, "[::1]:443", rq.Host)
		require.Equal(t, "::1", rq.URL.Hostname())
		require.NotEmpty(t, rq.RemoteAddr)
	})
	t.Run("an answer without a tunnel is a general failure", func(t *testing.T) {
		srv := serve(t, http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(rw, "no")
		}))
		_, code := dial(t, srv, 1, host, port)
		require.Equal(t, byte(1), code)
	})
}

func TestServer_protocolErrors(t *testing.T) {
	srv := serve(t, &router.Router{Connect: &handlers.Tunnel{}})

	open := func(t *testing.T) net.Conn {
		c, err := net.DialTimeout("tcp", srv, time.Second)
		require.NoError(t, err)
		t.Cleanup(func() { _ = c.Close() })
		require.NoError(t, c.SetDeadline(time.Now().Add(5*time.Second)))
		return c
	}

	t.Run("no acceptable method", func(t *testing.T) {
		c := open(t)
		_, err := c.Write([]byte{5, 1, 2})
		require.NoError(t, err)
		reply := make([]byte, 2)
		_, err = io.ReadFull(c, reply)
		require.NoError(t, err)
		require.Equal(t, []byte{5, 0xff}, reply)
	})
	t.Run("not SOCKS5", func(t *testing.T) {
		c := open(t)
		_, err := c.Write([]byte{4, 1, 0})
		require.NoError(t, err)
		_, err = c.Read(make([]byte, 1))
		require.ErrorIs(t, err, io.EOF)
	})
	t.Run("unsupported command", func(t *testing.T) {
		c := open(t)
		_, err := c.Write([]byte{5, 1, 0, 5, 2, 0, 1, 127, 0, 0, 1, 0, 80})
		require.NoError(t, err)
		_, err = io.ReadFull(c, make([]byte, 2))
		require.NoError(t, err)
		require.Equal(t, byte(7), readReply(t, c))
	})
	t.Run("unsupported address type", func(t *testing.T) {
		c := open(t)
		_, err := c.Write([]byte{5, 1, 0, 5, 1, 0, 9})
		require.NoError(t, err)
		_, err = io.ReadFull(c, make([]byte, 2))
		require.NoError(t, err)
		require.Equal(t, byte(8), readReply(t, c))
	})
}
