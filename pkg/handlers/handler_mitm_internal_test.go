package handlers

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"sarak.sh/mikluko/multiproxy/pkg/issuer"
)

func TestMITMHandler_certForRequest(t *testing.T) {
	ca := &issuer.SelfSignedCA{}
	h := &MITMHandler{Issuer: ca}
	h.init()

	for _, host := range []string{"example.com", "www.example.com", "a.b.example.co.uk", "localhost", "127.0.0.1", "::1"} {
		t.Run(host, func(t *testing.T) {
			rq, err := http.NewRequest(http.MethodConnect, "https://"+net.JoinHostPort(host, "443"), nil)
			require.NoError(t, err)

			cert, err := h.certForRequest(rq)
			require.NoError(t, err)

			roots := x509.NewCertPool()
			roots.AddCert(ca.Cert.Leaf)
			_, err = cert.Leaf.Verify(x509.VerifyOptions{DNSName: host, Roots: roots})
			require.NoError(t, err)
		})
	}
}

func TestMITMHandler_certForRequest_reissuesExpired(t *testing.T) {
	is := &countingIssuer{validity: -time.Minute}
	h := &MITMHandler{Issuer: is}
	h.init()
	rq, err := http.NewRequest(http.MethodConnect, "https://example.com:443", nil)
	require.NoError(t, err)

	_, err = h.certForRequest(rq)
	require.NoError(t, err)
	_, err = h.certForRequest(rq)
	require.NoError(t, err)
	require.Equal(t, 2, is.calls)

	is.validity = time.Hour
	_, err = h.certForRequest(rq)
	require.NoError(t, err)
	_, err = h.certForRequest(rq)
	require.NoError(t, err)
	require.Equal(t, 3, is.calls)
}

// countingIssuer returns certificates that expire validity from now, and counts the calls.
type countingIssuer struct {
	validity time.Duration
	calls    int
}

func (is *countingIssuer) Issue(cn string, _ []string, _ []net.IP) (*tls.Certificate, error) {
	is.calls++
	return &tls.Certificate{Leaf: &x509.Certificate{
		Subject:  pkix.Name{CommonName: cn},
		NotAfter: time.Now().Add(is.validity),
	}}, nil
}
