//go:build !windows && !linux

package netconn

type noScanner struct{}

// NewScanner, desteklenmeyen platformlar için boş tarayıcı döner.
func NewScanner() Scanner { return noScanner{} }

func (noScanner) Scan() []Conn { return nil }
