package discovery

import "testing"

// TestRealNeighborsSmoke, gerçek OS komşu tablosunu okur (read-only, güvenli).
// Tablo boşsa veya platform desteklemiyorsa atlanır.
func TestRealNeighborsSmoke(t *testing.T) {
	hosts, err := NewNeighborSource().Neighbors()
	if err != nil {
		t.Skipf("komşu kaynağı okunamadı: %v", err)
	}
	if len(hosts) == 0 {
		t.Skip("ARP/komşu tablosu boş; atlanıyor")
	}
	for _, h := range hosts {
		if len(h.MAC) != 17 {
			t.Errorf("geçersiz MAC biçimi: %q", h.MAC)
		}
	}
	t.Logf("gerçek komşu keşfi OK: %d cihaz", len(hosts))
}
