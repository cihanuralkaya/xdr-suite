//go:build linux

package inventory

import "os/exec"

type linuxCollector struct{}

// NewCollector, mevcut platform için envanter toplayıcısı döner.
func NewCollector() Collector { return linuxCollector{} }

// Software, dpkg (Debian/Ubuntu) ile paketleri listeler; yoksa rpm'e (RHEL/SUSE)
// düşer. İkisi de yoksa boş döner.
func (linuxCollector) Software() []string {
	if out, err := exec.Command("dpkg-query", "-W", "-f=${Package}\t${Version}\n").Output(); err == nil {
		return parseDpkg(string(out))
	}
	if out, err := exec.Command("rpm", "-qa").Output(); err == nil {
		return parseRpm(string(out))
	}
	return nil
}
