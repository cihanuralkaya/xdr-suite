// Package liveness, çift-süreç karşılıklı gözetimi sağlar: ajan ve watchdog
// birbirlerinin canlılığını dosya-tabanlı "beacon"larla izler. Watchdog zaten
// ajanı süreç-çıkışıyla yeniden başlatır (bkz. watchdog paketi); bu paket ters
// yönü ekler: ajan, watchdog'un beacon'u bayatlarsa onu yeniden başlatır.
package liveness

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Beacon, bir sürecin canlılık zaman damgasını tutan dosyadır.
type Beacon struct {
	path string
}

// NewBeacon oluşturur.
func NewBeacon(path string) *Beacon { return &Beacon{path: path} }

// Write, verilen zamanı beacon'a atomik olarak yazar (temp + rename).
func (b *Beacon) Write(t time.Time) error {
	data := []byte(strconv.FormatInt(t.UnixNano(), 10))
	tmp := b.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return fmt.Errorf("liveness: beacon yazma: %w", err)
	}
	if err := os.Rename(tmp, b.path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("liveness: beacon rename: %w", err)
	}
	return nil
}

// LastSeen, beacon'daki son zaman damgasını döner. Dosya yok/okunamaz/bozuksa
// ok=false döner.
func (b *Beacon) LastSeen() (time.Time, bool) {
	data, err := os.ReadFile(b.path)
	if err != nil {
		return time.Time{}, false
	}
	n, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
	if err != nil {
		return time.Time{}, false
	}
	return time.Unix(0, n), true
}
