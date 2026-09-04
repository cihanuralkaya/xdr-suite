//go:build linux

package deviceaction

import "os/exec"

// Lock, oturumları kilitler (loginctl lock-sessions).
func Lock() error {
	return exec.Command("loginctl", "lock-sessions").Run()
}

// Restart, cihazı yeniden başlatır (systemctl reboot).
func Restart() error {
	return exec.Command("systemctl", "reboot").Run()
}
