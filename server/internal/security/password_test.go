package security

import (
	"testing"
	"time"
)

func TestPasswordHashVerify(t *testing.T) {
	hash, err := HashPassword("s3cret-parola")
	if err != nil {
		t.Fatal(err)
	}
	ok, err := VerifyPassword(hash, "s3cret-parola")
	if err != nil || !ok {
		t.Fatalf("doğru parola doğrulanamadı: ok=%v err=%v", ok, err)
	}
	ok, _ = VerifyPassword(hash, "yanlis")
	if ok {
		t.Fatal("yanlış parola kabul edildi")
	}
}

func TestSessionSignVerify(t *testing.T) {
	s := NewSessionSigner(DeriveKey(make([]byte, 32), LabelSessionToken))
	now := time.Unix(1000, 0)
	tok := s.Sign("admin-1", now.Add(time.Hour))

	id, ok := s.Verify(tok, now)
	if !ok || id != "admin-1" {
		t.Fatalf("geçerli token doğrulanamadı: id=%q ok=%v", id, ok)
	}
	// Süresi geçmiş.
	if _, ok := s.Verify(tok, now.Add(2*time.Hour)); ok {
		t.Fatal("süresi geçmiş token kabul edildi")
	}
	// Kurcalanmış.
	if _, ok := s.Verify(tok+"x", now); ok {
		t.Fatal("kurcalanmış token kabul edildi")
	}
	// Farklı anahtar doğrulamamalı.
	other := NewSessionSigner(DeriveKey([]byte("baska-32-baytlik-anahtar-degeri!!"), LabelSessionToken))
	if _, ok := other.Verify(tok, now); ok {
		t.Fatal("farklı anahtar token'ı doğruladı")
	}
}
