package deviceaction

import (
	"errors"
	"testing"
)

// Wipe, bu sürümde KASITLI olarak gerçek silme yapmamalı — her zaman
// ErrWipeNotImplemented dönmeli. Bu, birinin yanlışlıkla yıkıcı gerçek silme
// bağlamasına karşı bir güvenlik-koruma (regresyon) testidir; kırılırsa
// gözden geçirilmeden birleştirilmemeli.
func TestWipeIsSafeStub(t *testing.T) {
	err := Wipe()
	if err == nil {
		t.Fatal("Wipe() nil döndü — WIPE gerçek silme YAPMAMALI (güvenlik güdüğü)")
	}
	if !errors.Is(err, ErrWipeNotImplemented) {
		t.Fatalf("Wipe() ErrWipeNotImplemented dönmeliydi, dönen: %v", err)
	}
}
