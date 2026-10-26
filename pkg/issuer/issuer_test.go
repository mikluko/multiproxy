package issuer_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"sarak.sh/mikluko/multiproxy/pkg/issuer"
)

func TestIssuer_Issue(t *testing.T) {
	t.Run("DNSNames", func(t *testing.T) {
		cert, err := (&issuer.SelfSignedCA{}).Issue("example.com", []string{"example.com"}, nil)
		require.NoError(t, err)
		require.NotNil(t, cert.Leaf)
		require.Len(t, cert.Leaf.DNSNames, 1)
		require.Equal(t, []string{"example.com"}, cert.Leaf.DNSNames)
	})
	t.Run("IPAddresses", func(t *testing.T) {
		cert, err := (&issuer.SelfSignedCA{}).Issue("example.com", nil, []net.IP{net.ParseIP("192.0.2.1")})
		require.NoError(t, err)
		require.NotNil(t, cert.Leaf)
		require.Len(t, cert.Leaf.IPAddresses, 1)
		require.True(t, cert.Leaf.IPAddresses[0].Equal(net.ParseIP("192.0.2.1")))
	})
	t.Run("default key is RSA 2048", func(t *testing.T) {
		cert, err := (&issuer.SelfSignedCA{}).Issue("example.com", []string{"example.com"}, nil)
		require.NoError(t, err)
		key, ok := cert.Leaf.PublicKey.(*rsa.PublicKey)
		require.True(t, ok)
		require.Equal(t, 2048, key.N.BitLen())
	})
	t.Run("BitSize", func(t *testing.T) {
		cert, err := (&issuer.SelfSignedCA{BitSize: 3072}).Issue("example.com", []string{"example.com"}, nil)
		require.NoError(t, err)
		require.Equal(t, 3072, cert.Leaf.PublicKey.(*rsa.PublicKey).N.BitLen())
	})
	t.Run("ECDSA", func(t *testing.T) {
		ca := &issuer.SelfSignedCA{KeyAlgorithm: x509.ECDSA}
		cert, err := ca.Issue("example.com", []string{"example.com"}, nil)
		require.NoError(t, err)
		key, ok := cert.Leaf.PublicKey.(*ecdsa.PublicKey)
		require.True(t, ok)
		require.Equal(t, elliptic.P256(), key.Curve)

		roots := x509.NewCertPool()
		roots.AddCert(ca.Cert.Leaf)
		_, err = cert.Leaf.Verify(x509.VerifyOptions{DNSName: "example.com", Roots: roots})
		require.NoError(t, err)
	})
	t.Run("unsupported KeyAlgorithm", func(t *testing.T) {
		_, err := (&issuer.SelfSignedCA{KeyAlgorithm: x509.Ed25519}).Issue("example.com", []string{"example.com"}, nil)
		require.Error(t, err)
	})
	t.Run("default validity", func(t *testing.T) {
		cert, err := (&issuer.SelfSignedCA{}).Issue("example.com", []string{"example.com"}, nil)
		require.NoError(t, err)
		require.WithinDuration(t, time.Now().Add(issuer.DefaultIssuerValidity), cert.Leaf.NotAfter, time.Minute)
	})
	t.Run("Validity", func(t *testing.T) {
		cert, err := (&issuer.SelfSignedCA{Validity: 48 * time.Hour}).Issue("example.com", []string{"example.com"}, nil)
		require.NoError(t, err)
		require.WithinDuration(t, time.Now().Add(48*time.Hour), cert.Leaf.NotAfter, time.Minute)
	})
	t.Run("serial numbers differ", func(t *testing.T) {
		ca := &issuer.SelfSignedCA{KeyAlgorithm: x509.ECDSA}
		a, err := ca.Issue("a.example.com", []string{"a.example.com"}, nil)
		require.NoError(t, err)
		b, err := ca.Issue("b.example.com", []string{"b.example.com"}, nil)
		require.NoError(t, err)
		require.NotEqual(t, a.Leaf.SerialNumber, b.Leaf.SerialNumber)
	})
}
