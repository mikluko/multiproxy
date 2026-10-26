package proxy_test

import (
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"

	"sarak.sh/mikluko/multiproxy/pkg/issuer"
	"sarak.sh/mikluko/multiproxy/pkg/proxy"
)

// echo answers 200 and reports the X-Test header it received as X-Seen-Test.
func echo(rw http.ResponseWriter, rq *http.Request) {
	rw.Header().Set("X-Seen-Test", rq.Header.Get("X-Test"))
}

func start(t *testing.T, cfg proxy.Config) *http.Client {
	t.Helper()
	h, err := proxy.New(cfg)
	require.NoError(t, err)
	s := httptest.NewServer(h)
	t.Cleanup(s.Close)
	u, err := url.Parse(s.URL)
	require.NoError(t, err)
	return &http.Client{Transport: &http.Transport{
		Proxy:           http.ProxyURL(u),
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}}
}

func get(t *testing.T, c *http.Client, target string) *http.Response {
	t.Helper()
	rs, err := c.Get(target)
	require.NoError(t, err)
	_, _ = io.Copy(io.Discard, rs.Body)
	_ = rs.Body.Close()
	return rs
}

func TestNew(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(echo))
	defer upstream.Close()
	tlsUpstream := httptest.NewTLSServer(http.HandlerFunc(echo))
	defer tlsUpstream.Close()

	t.Run("with no patterns, every host is tunnelled", func(t *testing.T) {
		c := start(t, proxy.Config{})
		require.Equal(t, http.StatusOK, get(t, c, upstream.URL).StatusCode)
		rs := get(t, c, tlsUpstream.URL)
		require.True(t, rs.TLS.PeerCertificates[0].Equal(tlsUpstream.Certificate()))
	})
	t.Run("a MITM pattern intercepts", func(t *testing.T) {
		ca := &issuer.SelfSignedCA{}
		c := start(t, proxy.Config{MITM: []string{"127.0.0.1"}, Issuer: ca, Transport: tlsUpstream.Client().Transport})
		rs := get(t, c, tlsUpstream.URL)
		require.Equal(t, ca.Cert.Leaf.Subject.CommonName, rs.TLS.PeerCertificates[0].Issuer.CommonName)
	})
	t.Run("middleware reaches plain and intercepted requests", func(t *testing.T) {
		setTest := func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(rw http.ResponseWriter, rq *http.Request) {
				rq.Header.Set("X-Test", "yes")
				next.ServeHTTP(rw, rq)
			})
		}
		c := start(t, proxy.Config{
			MITM:       []string{"127.0.0.1"},
			Middleware: []func(http.Handler) http.Handler{setTest},
			Transport:  tlsUpstream.Client().Transport,
		})
		require.Equal(t, "yes", get(t, c, upstream.URL).Header.Get("X-Seen-Test"))
		require.Equal(t, "yes", get(t, c, tlsUpstream.URL).Header.Get("X-Seen-Test"))
	})
	t.Run("a host no pattern admits is refused", func(t *testing.T) {
		c := start(t, proxy.Config{Tunnel: []string{"example.com"}})
		require.Equal(t, http.StatusForbidden, get(t, c, upstream.URL).StatusCode)
	})
	t.Run("two fallbacks", func(t *testing.T) {
		_, err := proxy.New(proxy.Config{MITM: []string{"*"}, Tunnel: []string{"*"}})
		require.ErrorContains(t, err, "*")
	})
}
