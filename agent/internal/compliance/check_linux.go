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

// Firewall, ufw durumunu döner (yaygın Linux güvenlik duvarı ön-yüzü). ufw yoksa
// veya sorgulanamazsa unknown.
func (linuxChecker) Firewall() string {
	out, err := exec.Command("ufw", "status").Output()
	if err != nil {
		return FwUnknown
	}
	return parseUfwStatus(string(out))
}
