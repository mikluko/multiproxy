package issuer_test

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"sarak.sh/mikluko/multiproxy/pkg/issuer"
)

// countingIssuer issues certificates that expire validity from now, and counts the calls per common name.
type countingIssuer struct {
	mu       sync.Mutex
	calls    map[string]int
	total    atomic.Int64
	validity time.Duration
	fail     bool
	delay    time.Duration
}

func (is *countingIssuer) Issue(cn string, _ []string, _ []net.IP) (*tls.Certificate, error) {
	time.Sleep(is.delay)
	is.total.Add(1)
	is.mu.Lock()
	defer is.mu.Unlock()
	if is.calls == nil {
		is.calls = map[string]int{}
	}
	is.calls[cn]++
	if is.fail {
		return nil, errors.New("issuer down")
	}
	return &tls.Certificate{Leaf: &x509.Certificate{
		Subject:  pkix.Name{CommonName: cn},
		NotAfter: time.Now().Add(is.validity),
	}}, nil
}

func TestCache(t *testing.T) {
	t.Run("issues once per common name", func(t *testing.T) {
		is := &countingIssuer{validity: time.Hour}
		c := &issuer.Cache{Issuer: is}
		for range 3 {
			_, err := c.Issue("a.example.com", []string{"a.example.com"}, nil)
			require.NoError(t, err)
		}
		_, err := c.Issue("b.example.com", []string{"b.example.com"}, nil)
		require.NoError(t, err)
		require.Equal(t, map[string]int{"a.example.com": 1, "b.example.com": 1}, is.calls)
	})
	t.Run("issues again past NotAfter", func(t *testing.T) {
		is := &countingIssuer{validity: -time.Minute}
		c := &issuer.Cache{Issuer: is}
		for range 2 {
			_, err := c.Issue("example.com", nil, nil)
			require.NoError(t, err)
		}
		require.Equal(t, 2, is.calls["example.com"])
	})
	t.Run("does not keep errors", func(t *testing.T) {
		is := &countingIssuer{validity: time.Hour, fail: true}
		c := &issuer.Cache{Issuer: is}
		_, err := c.Issue("example.com", nil, nil)
		require.Error(t, err)
		is.fail = false
		_, err = c.Issue("example.com", nil, nil)
		require.NoError(t, err)
		require.Equal(t, 2, is.calls["example.com"])
	})
	t.Run("concurrent requests for one name issue once", func(t *testing.T) {
		is := &countingIssuer{validity: time.Hour, delay: 50 * time.Millisecond}
		c := &issuer.Cache{Issuer: is}
		var wg sync.WaitGroup
		for range 10 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, _ = c.Issue("example.com", nil, nil)
			}()
		}
		wg.Wait()
		require.EqualValues(t, 1, is.total.Load())
	})
	t.Run("Size bounds the entries", func(t *testing.T) {
		is := &countingIssuer{validity: time.Hour}
		c := &issuer.Cache{Issuer: is, Size: 1}
		for _, cn := range []string{"a.test", "b.test", "a.test"} {
			_, err := c.Issue(cn, nil, nil)
			require.NoError(t, err)
		}
		require.Equal(t, 2, is.calls["a.test"])
	})
	t.Run("caches a SelfSignedCA", func(t *testing.T) {
		c := &issuer.Cache{Issuer: &issuer.SelfSignedCA{KeyAlgorithm: x509.ECDSA}}
		a, err := c.Issue("example.com", []string{"example.com"}, nil)
		require.NoError(t, err)
		b, err := c.Issue("example.com", []string{"example.com"}, nil)
		require.NoError(t, err)
		require.Same(t, a, b)
	})
}
