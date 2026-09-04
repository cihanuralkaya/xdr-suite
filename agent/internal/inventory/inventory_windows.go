//go:build windows

package inventory

import "os/exec"

type winCollector struct{}

// NewCollector, mevcut platform için envanter toplayıcısı döner.
func NewCollector() Collector { return winCollector{} }

// uninstallKeys, hem 64-bit hem 32-bit (WOW6432Node) kaldırma anahtarlarını
// kapsar (32-bit uygulamalar ayrı dalda listelenir).
var uninstallKeys = []string{
	`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`,
	`HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall`,
}

// Software, kaldırma kayıt anahtarlarındaki DisplayName değerlerini toplar.
func (winCollector) Software() []string {
	var names []string
	for _, k := range uninstallKeys {
		out, err := exec.Command("reg", "query", k, "/s", "/v", "DisplayName").Output()
		if err != nil {
			continue // anahtar yoksa/erişilemezse diğerine geç (best-effort)
		}
		names = append(names, parseRegUninstall(string(out))...)
	}
	return names
}
