//go:build linux

package usbmon

import (
	"os"
	"path/filepath"
	"strings"
)

type linuxScanner struct{}

// NewScanner, mevcut platform için tarayıcı döner.
func NewScanner() Scanner { return linuxScanner{} }

// Scan, /sys/block/*/removable == 1 olan blok aygıtlarını çıkarılabilir sayar.
func (linuxScanner) Scan() []Drive {
	var ds []Drive
	entries, err := filepath.Glob("/sys/block/*/removable")
	if err != nil {
		return nil
	}
	for _, p := range entries {
		b, err := os.ReadFile(p)
		if err != nil || strings.TrimSpace(string(b)) != "1" {
			continue
		}
		// /sys/block/sdb/removable → /dev/sdb
		name := filepath.Base(filepath.Dir(p))
		ds = append(ds, Drive{ID: "/dev/" + name})
	}
	return ds
}
