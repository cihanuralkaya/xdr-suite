//go:build windows

package compliance

import (
	"os"
	"os/exec"
)

type winChecker struct{}

// NewChecker, mevcut platform için uyum denetleyicisi döner.
func NewChecker() Checker { return winChecker{} }

// DiskEncryption, sistem sürücüsünün BitLocker koruma durumunu döner.
func (winChecker) DiskEncryption() string {
	sys := os.Getenv("SystemDrive")
	if sys == "" {
		sys = "C:"
	}
	out, err := exec.Command("manage-bde", "-status", sys).Output()
	if err != nil {
		return EncUnknown
	}
	return parseBitLockerStatus(string(out))
}
