// Package deviceaction, MDM uzaktan cihaz eylemlerini (ekran kilitleme, yeniden
// başlatma, veri silme) OS-özel olarak uygular. Yıkıcı eylemler (RESTART/WIPE)
// yalnız güvenli-mod KAPALIYKEN çağrılır (çağıran katman güvenli-modu denetler).
//
// WIPE KASITLI OLARAK gerçek yıkıcı silme YAPMAZ: platforma özgü güvenli-silme
// (BitLocker anahtar imhası / secure-erase) entegrasyonu ayrı ve riskli olduğundan
// bu sürümde bir GÜDÜK'tür (komut/RBAC/denetim/olay akışı tamdır, fiziksel silme
// yoktur). Böylece test/demo sırasında yanlışlıkla veri kaybı olmaz.
package deviceaction

import "errors"

// ErrWipeNotImplemented, WIPE'ın bu sürümde gerçek silme yapmadığını belirtir.
var ErrWipeNotImplemented = errors.New("deviceaction: WIPE bu sürümde gerçek silme yapmaz (platform secure-erase entegrasyonu gerekir)")

// Wipe, veri silmeyi gerçekleştirmez (güvenlik gereği güdük). Her platformda
// aynı; gerçek dağıtımda platforma özgü güvenli-silme ile değiştirilir.
func Wipe() error { return ErrWipeNotImplemented }
