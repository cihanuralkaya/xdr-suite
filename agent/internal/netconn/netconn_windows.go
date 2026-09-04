//go:build windows

package netconn

import "os/exec"

type winScanner struct{}

// NewScanner, mevcut platform için bağlantı tarayıcısı döner.
func NewScanner() Scanner { return winScanner{} }

// Scan, `netstat -ano -p TCP` ile kurulu giden bağlantıları toplar.
func (winScanner) Scan() []Conn {
	out, err := exec.Command("netstat", "-ano", "-p", "TCP").Output()
	if err != nil {
		return nil
	}
	return parseNetstat(string(out))
}
