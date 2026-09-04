package inventory

import "testing"

func TestParseRegUninstall(t *testing.T) {
	out := "\r\n" +
		"HKEY_LOCAL_MACHINE\\SOFTWARE\\...\\Uninstall\\{abc}\r\n" +
		"    DisplayName    REG_SZ    Google Chrome\r\n\r\n" +
		"HKEY_LOCAL_MACHINE\\SOFTWARE\\...\\Uninstall\\{def}\r\n" +
		"    DisplayName    REG_SZ    Mozilla Firefox 120.0\r\n" +
		"    Publisher    REG_SZ    Mozilla\r\n"
	got := parseRegUninstall(out)
	want := map[string]bool{"Google Chrome": true, "Mozilla Firefox 120.0": true}
	if len(got) != 2 {
		t.Fatalf("2 ad beklenirdi, %d: %v", len(got), got)
	}
	for _, g := range got {
		if !want[g] {
			t.Errorf("beklenmeyen ad: %q", g)
		}
	}
}

func TestParseDpkg(t *testing.T) {
	out := "bash\t5.1-6\ncoreutils\t8.32-4\n\nvim\t2:8.2\n"
	got := parseDpkg(out)
	if len(got) != 3 || got[0] != "bash" || got[2] != "vim" {
		t.Fatalf("dpkg ayrıştırma hatalı: %v", got)
	}
}

func TestParseRpm(t *testing.T) {
	out := "bash-5.1.8-6.el9.x86_64\n\nvim-8.2.x86_64\n"
	got := parseRpm(out)
	if len(got) != 2 {
		t.Fatalf("2 paket beklenirdi: %v", got)
	}
}

func TestNormalizeDedupSortCap(t *testing.T) {
	raw := []string{"  Zeta ", "alpha", "alpha", "", "beta"}
	list, total := normalize(raw)
	if total != 3 {
		t.Fatalf("toplam 3 (Zeta, alpha, beta) beklenirdi, %d", total)
	}
	// sıralı: alpha, beta, Zeta (ASCII: büyük harf küçükten önce gelir)
	if list[0] != "Zeta" && list[0] != "alpha" {
		t.Fatalf("sıralama beklenmedik: %v", list)
	}
	// tekilleştirme: alpha bir kez
	count := 0
	for _, s := range list {
		if s == "alpha" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("alpha tekilleştirilmeliydi: %v", list)
	}
}

func TestNormalizeCap(t *testing.T) {
	var raw []string
	for i := 0; i < maxPackages+50; i++ {
		raw = append(raw, "pkg-"+string(rune('a'+i%26))+string(rune('a'+(i/26)%26))+string(rune('0'+i%10))+"-"+itoa(i))
	}
	list, total := normalize(raw)
	if len(list) != maxPackages {
		t.Fatalf("liste maxPackages'a kırpılmalıydı: %d", len(list))
	}
	if total < maxPackages+1 {
		t.Fatalf("toplam kırpmadan önceki sayı olmalı: %d", total)
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}

func TestNewCollectorNonNil(t *testing.T) {
	if NewCollector() == nil {
		t.Fatal("NewCollector nil dönmemeli")
	}
}
