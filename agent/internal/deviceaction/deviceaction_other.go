//go:build !windows && !linux

package deviceaction

import "errors"

// Lock, desteklenmeyen platformda hata döner.
func Lock() error { return errors.New("deviceaction: kilitleme bu platformda desteklenmiyor") }

// Restart, desteklenmeyen platformda hata döner.
func Restart() error {
	return errors.New("deviceaction: yeniden başlatma bu platformda desteklenmiyor")
}
