//go:build windows

package osinfo

import "os/exec"

// Version, `cmd /c ver` çıktısından Windows sürümünü döner (okunamazsa "windows").
func Version() string {
	out, err := exec.Command("cmd", "/c", "ver").Output()
	if err != nil {
		return "windows"
	}
	return parseWinVer(string(out))
}
