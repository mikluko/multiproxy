package handlers

import (
	"crypto/x509"
	"net"
	"net/http"
	"testing"

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
