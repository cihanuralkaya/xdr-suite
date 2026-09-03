//go:build linux

package osinfo

import "os"

// Version, /etc/os-release PRETTY_NAME'ini döner (okunamazsa "linux").
func Version() string {
	b, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return "linux"
	}
	if v := parseOSRelease(string(b)); v != "" {
		return v
	}
	return "linux"
}
