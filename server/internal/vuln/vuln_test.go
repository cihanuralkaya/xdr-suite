package vuln

import (
	"strings"
	"testing"
)

const sample = `[
  {"product":"7-Zip 19","cve":"CVE-2022-0001","severity":"HIGH","fixed_version":"21.07","description":"heap overflow"},
  {"product":"log4j","cve":"CVE-2021-44228","severity":"CRITICAL","fixed_version":"2.17.0"},
  {"product":"OpenSSL 1.0","cve":"CVE-2016-2107","severity":"MEDIUM"}
]`

func TestLoadAndMatch(t *testing.T) {
	s, err := Load(strings.NewReader(sample))
	if err != nil {
		t.Fatal(err)
	}
	if s.Size() != 3 {
		t.Fatalf("3 kayıt beklenirdi, %d", s.Size())
	}
	software := []string{"7-Zip 19.00 (x64)", "Google Chrome", "Apache Log4j Core", "Notepad++"}
	f := s.Match(software)
	// 7-Zip 19 + log4j eşleşmeli (2); OpenSSL yok.
	if len(f) != 2 {
		t.Fatalf("2 bulgu beklenirdi, %d: %+v", len(f), f)
	}
	seen := map[string]string{}
	for _, x := range f {
		seen[x.CVE] = x.Package
	}
	if seen["CVE-2022-0001"] != "7-Zip 19.00 (x64)" {
		t.Fatalf("7-Zip CVE eşleşmesi hatalı: %+v", seen)
	}
	if seen["CVE-2021-44228"] != "Apache Log4j Core" {
		t.Fatalf("log4j CVE eşleşmesi hatalı: %+v", seen)
	}
}

func TestLoadRejectsIncomplete(t *testing.T) {
	if _, err := Load(strings.NewReader(`[{"product":"x","severity":"HIGH"}]`)); err == nil {
		t.Fatal("cve eksik → hata beklenirdi")
	}
}

func TestMatchEmptySet(t *testing.T) {
	var s *Set
	if f := s.Match([]string{"anything"}); f != nil {
		t.Fatalf("nil set eşleşme üretmemeli: %+v", f)
	}
}

func TestMatchCaseInsensitive(t *testing.T) {
	s, _ := Load(strings.NewReader(`[{"product":"LOG4J","cve":"CVE-X","severity":"HIGH"}]`))
	if f := s.Match([]string{"apache log4j core"}); len(f) != 1 {
		t.Fatalf("küçük/büyük harf duyarsız eşleşmeliydi: %+v", f)
	}
}
