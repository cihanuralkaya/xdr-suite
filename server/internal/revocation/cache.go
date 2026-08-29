// Package revocation, iptal edilmiş istemci sertifikalarını mTLS el sıkışmasında
// reddeder. Her bağlantıda DB'ye gitmek pahalı olduğundan, iptal edilen
// sertifika parmak izleri (SHA-256(DER)) bellek-içi bir kümede tutulur ve
// periyodik olarak DB'den tazelenir.
package revocation

import "sync"

// Cache, iptal edilmiş sertifika parmak izlerinin eşzamanlı-güvenli kümesidir.
type Cache struct {
	mu  sync.RWMutex
	set map[string]struct{}
}

// NewCache oluşturur (başlangıçta boş).
func NewCache() *Cache {
	return &Cache{set: make(map[string]struct{})}
}

// Replace, kümeyi verilen parmak izleriyle atomik olarak değiştirir (tazeleme).
func (c *Cache) Replace(fingerprints [][]byte) {
	next := make(map[string]struct{}, len(fingerprints))
	for _, fp := range fingerprints {
		next[string(fp)] = struct{}{}
	}
	c.mu.Lock()
	c.set = next
	c.mu.Unlock()
}

// IsRevoked, verilen parmak izinin iptal edilmiş olup olmadığını döner.
func (c *Cache) IsRevoked(fingerprint []byte) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	_, ok := c.set[string(fingerprint)]
	return ok
}

// Size, iptal kümesindeki parmak izi sayısıdır.
func (c *Cache) Size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.set)
}
