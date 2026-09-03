//go:build !windows && !linux

package osinfo

import "runtime"

// Version, desteklenmeyen platformlarda GOOS döner.
func Version() string { return runtime.GOOS }
