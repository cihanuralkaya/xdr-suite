//go:build linux

package netconn

import "os"

type linuxScanner struct{}

// NewScanner, mevcut platform için bağlantı tarayıcısı döner.
func NewScanner() Scanner { return linuxScanner{} }

// Scan, /proc/net/tcp (IPv4) üzerinden kurulu giden bağlantıları toplar.
// /proc/net/tcp süreç eşlemesi taşımaz (PID=0). Okunamazsa boş döner.
func (linuxScanner) Scan() []Conn {
	b, err := os.ReadFile("/proc/net/tcp")
	if err != nil {
		return nil
	}
	return parseProcNetTcp(string(b))
}
