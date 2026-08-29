// Package discovery, pasif ağ keşfi sağlar: ajanın komşu/ARP tablosundan ağdaki
// cihazları tespit eder, yeni görülenleri işaretler ve bir allowlist'e göre
// yetkili/yetkisiz olarak sınıflandırır (mimari 4.3).
//
// Not: Bu ilk sürüm işletim sisteminin ARP/komşu tablosunu (read-only, güvenli)
// okur. Aktif ARP sorgusu / pasif paket dinleme (packet sniffing) sonraki bir
// alt-fazda eklenebilir; Tracker mantığı kaynak-bağımsızdır ve test edilebilir.
package discovery

import (
	"sync"
	"time"
)

// NeighborSource, OS'un ARP/komşu tablosunu okuyan platform kaynağıdır.
type NeighborSource interface {
	Neighbors() ([]Host, error)
}

// Host, ağda gözlemlenen bir cihazdır.
type Host struct {
	MAC    string // normalize edilmiş "aa:bb:cc:dd:ee:ff"
	IP     string
	Vendor string // OUI'den türetilmiş üretici (opsiyonel)
}

// Discovered, bir tarama sonucunda YENİ tespit edilmiş bir cihazdır.
type Discovered struct {
	Host       Host
	Authorized bool
}

// Tracker, görülen cihazları hatırlar ve yeni görülenleri raporlar.
type Tracker struct {
	mu         sync.Mutex
	known      map[string]time.Time // MAC -> son görülme
	authorized map[string]bool      // MAC -> allowlist'te mi
}

// NewTracker, verilen yetkili MAC listesiyle (allowlist) bir takipçi oluşturur.
func NewTracker(authorizedMACs []string) *Tracker {
	auth := make(map[string]bool, len(authorizedMACs))
	for _, m := range authorizedMACs {
		if n := NormalizeMAC(m); n != "" {
			auth[n] = true
		}
	}
	return &Tracker{known: map[string]time.Time{}, authorized: auth}
}

// Observe, bir tarama turunu işler: tüm cihazların son-görülme zamanını
// günceller ve bu turda İLK KEZ görülenleri (yeni) döner.
func (t *Tracker) Observe(hosts []Host, now time.Time) []Discovered {
	t.mu.Lock()
	defer t.mu.Unlock()

	var newly []Discovered
	for _, h := range hosts {
		if h.MAC == "" {
			continue
		}
		if _, seen := t.known[h.MAC]; !seen {
			newly = append(newly, Discovered{Host: h, Authorized: t.authorized[h.MAC]})
		}
		t.known[h.MAC] = now
	}
	return newly
}

// Count, şimdiye dek görülmüş benzersiz cihaz sayısıdır.
func (t *Tracker) Count() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.known)
}
