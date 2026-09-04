package resource

import "testing"

func TestComputeSnapshot(t *testing.T) {
	// 16 GB toplam, 4 GB kullanılabilir → %75 kullanım.
	// 100 GB disk, 25 GB boş → %75 kullanım. 7200 sn → 2 saat.
	s := computeSnapshot(16*1024*1024, 4*1024*1024, 100*1024*1024*1024, 25*1024*1024*1024, 7200)
	if !s.OK {
		t.Fatal("OK olmalıydı")
	}
	if s.MemTotalMB != 16*1024 {
		t.Errorf("MemTotalMB=%d beklenen %d", s.MemTotalMB, 16*1024)
	}
	if s.MemUsedPct != 75 {
		t.Errorf("MemUsedPct=%d beklenen 75", s.MemUsedPct)
	}
	if s.DiskTotalGB != 100 {
		t.Errorf("DiskTotalGB=%d beklenen 100", s.DiskTotalGB)
	}
	if s.DiskUsedPct != 75 {
		t.Errorf("DiskUsedPct=%d beklenen 75", s.DiskUsedPct)
	}
	if s.UptimeHours != 2 {
		t.Errorf("UptimeHours=%d beklenen 2", s.UptimeHours)
	}
}

func TestComputeSnapshotZeroGuards(t *testing.T) {
	// Sıfır/negatif ölçümler panik üretmemeli, yüzdeler 0 kalmalı.
	s := computeSnapshot(0, 0, 0, 0, 0)
	if s.MemUsedPct != 0 || s.DiskUsedPct != 0 || s.UptimeHours != 0 {
		t.Fatalf("sıfır ölçümlerde yüzdeler 0 olmalı: %+v", s)
	}
	// avail > total (tuhaf) → used 0'a kırpılır.
	s2 := computeSnapshot(1000, 2000, 0, 0, 0)
	if s2.MemUsedPct != 0 {
		t.Fatalf("avail>total durumunda kullanım 0 olmalı: %d", s2.MemUsedPct)
	}
}

func TestParseKV(t *testing.T) {
	m := parseKV("mem_total_kb=16030588\r\nmem_free_kb=5206304\r\n\r\nboot=2026-09-04T06:42:00\r\n")
	if m["mem_total_kb"] != "16030588" || m["mem_free_kb"] != "5206304" {
		t.Fatalf("parseKV hatalı: %+v", m)
	}
	if m["boot"] != "2026-09-04T06:42:00" {
		t.Fatalf("boot ayrıştırma hatalı: %q", m["boot"])
	}
}

func TestParseMeminfo(t *testing.T) {
	out := "MemTotal:       16384000 kB\nMemFree:         1000000 kB\nMemAvailable:    4096000 kB\nBuffers:          100 kB\n"
	total, avail := parseMeminfo(out)
	if total != 16384000 || avail != 4096000 {
		t.Fatalf("parseMeminfo total=%d avail=%d", total, avail)
	}
}

func TestParseUptimeProc(t *testing.T) {
	if got := parseUptimeProc("3600.50 12000.00\n"); got != 3600 {
		t.Fatalf("parseUptimeProc=%d beklenen 3600", got)
	}
	if got := parseUptimeProc(""); got != 0 {
		t.Fatalf("boş uptime 0 olmalı, %d", got)
	}
}

func TestNewCollectorNonNil(t *testing.T) {
	if NewCollector() == nil {
		t.Fatal("NewCollector nil dönmemeli")
	}
}
