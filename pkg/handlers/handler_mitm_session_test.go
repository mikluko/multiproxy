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

// connectMITM opens a CONNECT session to target through proxy p and returns the client side of the intercepted
// TLS connection.
func connectMITM(t *testing.T, p *httptest.Server, target string) *tls.Conn {
	t.Helper()
	c, err := net.DialTimeout("tcp", p.Listener.Addr().String(), time.Second)
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Close() })
	require.NoError(t, c.SetDeadline(time.Now().Add(5*time.Second)))

	_, err = io.WriteString(c, "CONNECT "+target+" HTTP/1.1\r\nHost: "+target+"\r\n\r\n")
	require.NoError(t, err)
	br := bufio.NewReader(c)
	rs, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, rs.StatusCode)
	require.Zero(t, br.Buffered())

	tc := tls.Client(c, &tls.Config{InsecureSkipVerify: true})
	require.NoError(t, tc.Handshake())
	return tc
}

func TestMITMHandler_streams(t *testing.T) {
	release := make(chan struct{})
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(rw, "first\n")
		rw.(http.Flusher).Flush()
		<-release
		_, _ = io.WriteString(rw, "second\n")
	}))
	defer upstream.Close()
	defer close(release)

	p := httptest.NewServer(&handlers.MITMHandler{})
	defer p.Close()

	line := make(chan string, 1)
	go func() {
		rq, _ := http.NewRequest(http.MethodGet, upstream.URL, nil)
		rs, err := testTransport(p.URL).RoundTrip(rq)
		if err != nil {
			line <- err.Error()
			return
		}
		defer rs.Body.Close()
		s, _ := bufio.NewReader(rs.Body).ReadString('\n')
		line <- s
	}()
	select {
	case s := <-line:
		require.Equal(t, "first\n", s)
	case <-time.After(3 * time.Second):
		t.Fatal("the first chunk did not arrive before the upstream finished")
	}
}

func TestMITMHandler_pipelining(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(rw http.ResponseWriter, rq *http.Request) {
		_, _ = io.WriteString(rw, rq.URL.Path)
	}))
	defer upstream.Close()

	p := httptest.NewServer(&handlers.MITMHandler{})
	defer p.Close()

	target := upstream.Listener.Addr().String()
	tc := connectMITM(t, p, target)
	_, err := io.WriteString(tc, "GET /one HTTP/1.1\r\nHost: "+target+"\r\n\r\nGET /two HTTP/1.1\r\nHost: "+target+"\r\n\r\n")
	require.NoError(t, err)

	br := bufio.NewReader(tc)
	for _, want := range []string{"/one", "/two"} {
		rs, err := http.ReadResponse(br, nil)
		require.NoError(t, err)
		body, err := io.ReadAll(rs.Body)
		require.NoError(t, err)
		require.Equal(t, want, string(body))
	}
}

// eagerConn is a client connection that sends prefix, the CONNECT request, in the same write as the first TLS
// handshake record, and whose first read skips the CONNECT response.
type eagerConn struct {
	net.Conn
	br      *bufio.Reader
	prefix  []byte
	skipped bool
}

func (c *eagerConn) Write(p []byte) (int, error) {
	if c.prefix != nil {
		buf := append(c.prefix, p...)
		c.prefix = nil
		if _, err := c.Conn.Write(buf); err != nil {
			return 0, err
		}
		return len(p), nil
	}
	return c.Conn.Write(p)
}

func (c *eagerConn) Read(p []byte) (int, error) {
	if !c.skipped {
		c.skipped = true
		rs, err := http.ReadResponse(c.br, &http.Request{Method: http.MethodConnect})
		if err != nil {
			return 0, err
		}
		if rs.StatusCode != http.StatusOK {
			return 0, io.ErrUnexpectedEOF
		}
	}
	return c.br.Read(p)
}

func TestMITMHandler_handshakeBeforeConnectResponse(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(rw, "hello")
	}))
	defer upstream.Close()
	p := httptest.NewServer(&handlers.MITMHandler{})
	defer p.Close()

	target := upstream.Listener.Addr().String()
	c, err := net.DialTimeout("tcp", p.Listener.Addr().String(), time.Second)
	require.NoError(t, err)
	defer c.Close()
	require.NoError(t, c.SetDeadline(time.Now().Add(5*time.Second)))
	connect := []byte("CONNECT " + target + " HTTP/1.1\r\nHost: " + target + "\r\n\r\n")

	tc := tls.Client(&eagerConn{Conn: c, br: bufio.NewReader(c), prefix: connect}, &tls.Config{InsecureSkipVerify: true})
	require.NoError(t, tc.Handshake())
	_, err = io.WriteString(tc, "GET / HTTP/1.1\r\nHost: "+target+"\r\nConnection: close\r\n\r\n")
	require.NoError(t, err)
	rs, err := http.ReadResponse(bufio.NewReader(tc), nil)
	require.NoError(t, err)
	body, err := io.ReadAll(rs.Body)
	require.NoError(t, err)
	require.Equal(t, "hello", string(body))
}
