package osinfo

import "testing"

func TestParseOSRelease(t *testing.T) {
	c := "NAME=\"Ubuntu\"\nVERSION=\"22.04.3 LTS\"\nPRETTY_NAME=\"Ubuntu 22.04.3 LTS\"\nID=ubuntu\n"
	if got := parseOSRelease(c); got != "Ubuntu 22.04.3 LTS" {
		t.Fatalf("PRETTY_NAME beklenirdi, %q", got)
	}
	if got := parseOSRelease("NAME=x\nID=y\n"); got != "" {
		t.Fatalf("PRETTY_NAME yoksa boş, %q", got)
	}
}

func TestParseWinVer(t *testing.T) {
	if got := parseWinVer("\r\nMicrosoft Windows [Version 10.0.19045.5011]\r\n"); got != "Windows 10.0.19045.5011" {
		t.Fatalf("Windows sürümü beklenirdi, %q", got)
	}
	// Beklenmeyen biçim → temizlenmiş ham metin.
	if got := parseWinVer("garip çıktı"); got != "garip çıktı" {
		t.Fatalf("ham metne düşmeliydi, %q", got)
	}
}
