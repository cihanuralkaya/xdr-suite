//go:build windows

package deviceaction

import "os/exec"

// Lock, çalışma istasyonunun ekranını kilitler (LockWorkStation).
func Lock() error {
	return exec.Command("rundll32.exe", "user32.dll,LockWorkStation").Run()
}

// Restart, cihazı 60 sn gecikmeyle yeniden başlatır (kullanıcıya uyarı penceresi).
func Restart() error {
	return exec.Command("shutdown", "/r", "/t", "60", "/c", "XDR uzaktan yeniden baslatma").Run()
}
