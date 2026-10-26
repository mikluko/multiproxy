package issuer

import (
	"crypto/tls"
	"net"
	"sync"
	"time"

	arc "github.com/hashicorp/golang-lru/arc/v2"
)

// Cache is an Issuer that keeps the certificates Issuer issues, by common name, and has Issuer issue again for a
// name whose certificate is past its NotAfter. Concurrent requests for one name wait for a single issue. An error is
// returned and not kept.
//
// The zero value is not usable: Issuer must be set.
type Cache struct {
	// Issuer issues the certificates the cache keeps.
	Issuer Issuer

	// Size is the number of names kept; the least valuable is evicted past it, by the ARC policy.
	//
	// If 0, the cache is unbounded.
	Size int

	once    sync.Once
	mu      sync.Mutex
	entries *arc.ARCCache[string, *cacheEntry]
}

type cacheEntry struct {
	mu   sync.Mutex
	cert *tls.Certificate
}

// Issue implements Issuer.
func (c *Cache) Issue(cn string, dnsnames []string, ipaddresses []net.IP) (*tls.Certificate, error) {
	c.once.Do(func() {
		size := c.Size
		if size == 0 {
			size = int(^uint(0) >> 1)
		}
		c.entries, _ = arc.NewARC[string, *cacheEntry](size)
	})

	c.mu.Lock()
	entry, ok := c.entries.Get(cn)
	if !ok {
		entry = &cacheEntry{}
		c.entries.Add(cn, entry)
	}
	entry.mu.Lock()
	c.mu.Unlock()
	defer entry.mu.Unlock()

	if entry.cert != nil && time.Now().Before(entry.cert.Leaf.NotAfter) {
		return entry.cert, nil
	}
	cert, err := c.Issuer.Issue(cn, dnsnames, ipaddresses)
	if err != nil {
		return nil, err
	}
	entry.cert = cert
	return cert, nil
}
