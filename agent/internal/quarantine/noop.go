package quarantine

// NoopIsolator, gerçek ağ değişikliği YAPMAYAN izolatördür. Demo/güvenli mod
// için kullanılır: karantina akışı (komut → Manager → olay) uçtan uca çalışır
// ama makinenin ağı gerçekten kesilmez.
type NoopIsolator struct{}

func (NoopIsolator) Isolate([]string) error { return nil }
func (NoopIsolator) Release() error         { return nil }
