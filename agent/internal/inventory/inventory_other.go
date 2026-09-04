//go:build !windows && !linux

package inventory

type unknownCollector struct{}

// NewCollector, desteklenmeyen platformlar için boş envanter döner.
func NewCollector() Collector { return unknownCollector{} }

func (unknownCollector) Software() []string { return nil }
