package ioc

import (
	"strings"
	"testing"
)

const sample = `
# tehdit istihbaratı feed'i
10.13.37.5        known-c2
AA:BB:CC:DD:EE:FF  rogue-device
evil.example.com   phishing
mimikatz.exe       kimlik-hirsizi
`

func mustLoad(t *testing.T) *Set {
	t.Helper()
	s, err := Load(strings.NewReader(sample))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestLoadAndSize(t *testing.T) {
	s := mustLoad(t)
	if s.Size() != 4 {
		t.Fatalf("4 gösterge beklenirdi, %d", s.Size())
	}
}

func TestMatchDetailsExact(t *testing.T) {
	s := mustLoad(t)
	// IP Details'te tam eşleşme.
	if lbl, ind, ok := s.Match(map[string]any{"ip": "10.13.37.5", "mac": "x"}, "yeni cihaz"); !ok || lbl != "known-c2" || ind != "10.13.37.5" {
		t.Fatalf("IP eşleşmeliydi: %s %s %v", lbl, ind, ok)
	}
	// MAC büyük/küçük harf duyarsız.
	if lbl, _, ok := s.Match(map[string]any{"mac": "aa:bb:cc:dd:ee:ff"}, ""); !ok || lbl != "rogue-device" {
		t.Fatalf("MAC (küçük harf) eşleşmeliydi: %s %v", lbl, ok)
	}
	// Süreç adı Details'te.
	if lbl, _, ok := s.Match(map[string]any{"process": "mimikatz.exe", "pid": 500}, ""); !ok || lbl != "kimlik-hirsizi" {
		t.Fatalf("süreç eşleşmeliydi: %s %v", lbl, ok)
	}
}

func TestMatchMessageSubstring(t *testing.T) {
	s := mustLoad(t)
	if lbl, _, ok := s.Match(nil, "bağlantı denendi: evil.example.com:443"); !ok || lbl != "phishing" {
		t.Fatalf("mesaja gömülü alan adı eşleşmeliydi: %s %v", lbl, ok)
	}
}

func TestNoMatch(t *testing.T) {
	s := mustLoad(t)
	if _, _, ok := s.Match(map[string]any{"ip": "8.8.8.8"}, "temiz olay"); ok {
		t.Fatal("temiz olay eşleşmemeliydi")
	}
	// Boş/nil set eşleşmez.
	var empty *Set
	if _, _, ok := empty.Match(map[string]any{"ip": "10.13.37.5"}, ""); ok {
		t.Fatal("nil set eşleşmemeliydi")
	}
}

func TestLoadSkipsCommentsAndBlanks(t *testing.T) {
	s, err := Load(strings.NewReader("# yorum\n\n   \n1.2.3.4\n"))
	if err != nil {
		t.Fatal(err)
	}
	if s.Size() != 1 {
		t.Fatalf("yalnız 1 gösterge (yorum/boş atlanmalı), %d", s.Size())
	}
	if lbl, _, ok := s.Match(map[string]any{"ip": "1.2.3.4"}, ""); !ok || lbl != "etiketsiz" {
		t.Fatalf("etiketsiz gösterge eşleşmeliydi: %s %v", lbl, ok)
	}
}
