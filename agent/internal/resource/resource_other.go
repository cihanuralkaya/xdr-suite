//go:build !windows && !linux

package resource

type unknownCollector struct{}

// NewCollector, desteklenmeyen platformlar için boş anlık görüntü döner.
func NewCollector() Collector { return unknownCollector{} }

func (unknownCollector) Snapshot() Snapshot { return Snapshot{} }
