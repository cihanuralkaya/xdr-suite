//go:build !windows && !linux

package compliance

type unknownChecker struct{}

// NewChecker, desteklenmeyen platformlar için uyum durumu bilinmeyen döner.
func NewChecker() Checker { return unknownChecker{} }

func (unknownChecker) DiskEncryption() string { return EncUnknown }
