//go:build linux

package compliance

import "os/exec"

type linuxChecker struct{}

// NewChecker, mevcut platform için uyum denetleyicisi döner.
func NewChecker() Checker { return linuxChecker{} }

// DiskEncryption, blok cihazlarında LUKS/dm-crypt ("crypt" türü) olup olmadığını
// lsblk ile denetler.
func (linuxChecker) DiskEncryption() string {
	out, err := exec.Command("lsblk", "-no", "TYPE").Output()
	if err != nil {
		return EncUnknown
	}
	return parseLsblkCrypt(string(out))
}
