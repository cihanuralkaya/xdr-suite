package certrenew

import (
	"testing"
	"time"
)

func TestShouldRenew(t *testing.T) {
	nb := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	na := nb.AddDate(0, 0, 30) // 30 günlük sertifika

	cases := []struct {
		name string
		now  time.Time
		want bool
	}{
		{"gün 5 - taze", nb.AddDate(0, 0, 5), false},    // 25 gün kaldı (>1/3)
		{"gün 19 - taze", nb.AddDate(0, 0, 19), false},  // 11 gün kaldı (>10 gün eşiği)
		{"gün 21 - yenile", nb.AddDate(0, 0, 21), true}, // 9 gün kaldı (<1/3=10 gün)
		{"gün 30 - dolmuş", na, true},
		{"gün 40 - dolmuş", nb.AddDate(0, 0, 40), true},
	}
	for _, c := range cases {
		if got := ShouldRenew(nb, na, c.now, 1.0/3.0); got != c.want {
			t.Errorf("%s: ShouldRenew=%v, beklenen %v", c.name, got, c.want)
		}
	}
}

func TestShouldRenewInvalidWindow(t *testing.T) {
	now := time.Now()
	// notAfter <= notBefore → yenile.
	if !ShouldRenew(now, now.Add(-time.Hour), now, 0.33) {
		t.Fatal("geçersiz pencerede yenileme gerekli")
	}
}
