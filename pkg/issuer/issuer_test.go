package issuer_test

import (
	"net"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/akabos/multiproxy/pkg/issuer"
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
}
