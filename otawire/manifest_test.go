package otawire

import "testing"

func TestCanonicalDeterministic(t *testing.T) {
	m := Manifest{TargetVersion: "1.2.0", SHA256Hex: "abcd", DownloadURL: "https://x/y", Mandatory: true}
	if string(CanonicalBytes(m)) != string(CanonicalBytes(m)) {
		t.Fatal("aynı manifest farklı bayt üretti")
	}
}

func TestCanonicalUnambiguous(t *testing.T) {
	// Alanların birleşimi ayraç karışıklığına yol açmamalı: "ab"+"c" != "a"+"bc".
	a := CanonicalBytes(Manifest{TargetVersion: "ab", SHA256Hex: "c"})
	b := CanonicalBytes(Manifest{TargetVersion: "a", SHA256Hex: "bc"})
	if string(a) == string(b) {
		t.Fatal("uzunluk-öneki ayrımı sağlamadı")
	}
}

func TestMandatoryChangesBytes(t *testing.T) {
	m1 := Manifest{TargetVersion: "1", SHA256Hex: "h", DownloadURL: "u", Mandatory: false}
	m2 := m1
	m2.Mandatory = true
	if string(CanonicalBytes(m1)) == string(CanonicalBytes(m2)) {
		t.Fatal("mandatory bayrağı imzalı baytları değiştirmeliydi")
	}
}
