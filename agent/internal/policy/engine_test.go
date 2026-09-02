package policy

import (
	"testing"
	"time"
)

// matchesTarget, çalışılan platformdan BAĞIMSIZ olarak hem Windows ('\') hem
// Unix ('/') yollarında dosya adıyla eşleşmeli. (filepath.Base OS'a bağlıydı;
// bu, Linux CI'da politika eşleşmesini kaçıran bir regresyondu.)
func TestMatchesTargetSeparatorAgnostic(t *testing.T) {
	cases := []struct {
		proc, target string
		want         bool
	}{
		{`D:\apps\torrent.exe`, "torrent.exe", true},
		{`C:\Games\game.exe`, "game.exe", true},
		{"/opt/games/torrent", "torrent", true},
		{"torrent.exe", "torrent.exe", true},
		{"notepad.exe", "torrent.exe", false},
		{"/usr/bin/steam", "game.exe", false},
	}
	for _, c := range cases {
		if got := matchesTarget(c.proc, c.target); got != c.want {
			t.Errorf("matchesTarget(%q,%q)=%v, beklenen %v", c.proc, c.target, got, c.want)
		}
	}
}

func weekdays(ds ...time.Weekday) [7]bool {
	var a [7]bool
	for _, d := range ds {
		a[int(d)] = true
	}
	return a
}

// at, belirli bir yıl-ay-gün-saat oluşturur (UTC; test için gün/saat önemli).
func at(y int, m time.Month, d, h, min int) time.Time {
	return time.Date(y, m, d, h, min, 0, 0, time.UTC)
}

func TestParseHHMM(t *testing.T) {
	if v, ok := ParseHHMM("18:00"); !ok || v != 1080 {
		t.Fatalf("18:00 => %d ok=%v", v, ok)
	}
	if _, ok := ParseHHMM("25:00"); ok {
		t.Fatal("geçersiz saat kabul edildi")
	}
}

func TestOvernightWindow(t *testing.T) {
	start, _ := ParseHHMM("18:00")
	end, _ := ParseHHMM("08:00")
	// Mesai-dışı yasak: Pzt-Cum 18:00–08:00.
	rule := Rule{
		ID:         "r1",
		Type:       RuleAppTimeBlock,
		Target:     "game.exe",
		Start:      start,
		End:        end,
		ActiveDays: weekdays(time.Monday, time.Tuesday, time.Wednesday, time.Thursday, time.Friday),
	}
	e := New(Bundle{Version: "v1", Rules: []Rule{rule}})

	// 2026-08-28 Cuma.
	cases := []struct {
		name string
		when time.Time
		want bool
	}{
		{"Cuma 20:00 - yasak", at(2026, 8, 28, 20, 0), true},
		{"Cumartesi 02:00 - Cuma gecesine taşan yasak", at(2026, 8, 29, 2, 0), true},
		{"Cumartesi 20:00 - Cmt aktif değil", at(2026, 8, 29, 20, 0), false},
		{"Pazar 02:00 - Cmt aktif değil, taşma yok", at(2026, 8, 30, 2, 0), false},
		{"Pazartesi 12:00 - mesai içi", at(2026, 8, 31, 12, 0), false},
		{"Cuma 08:00 - pencere kapandı (yarı-açık)", at(2026, 8, 28, 8, 0), false},
		{"Cuma 18:00 - pencere başladı", at(2026, 8, 28, 18, 0), true},
	}
	for _, c := range cases {
		got := e.EvaluateProcess("C:\\Games\\game.exe", c.when)
		if got.Blocked != c.want {
			t.Errorf("%s: blocked=%v beklenen=%v", c.name, got.Blocked, c.want)
		}
	}
}

func TestSameDayWindow(t *testing.T) {
	start, _ := ParseHHMM("09:00")
	end, _ := ParseHHMM("17:00")
	e := New(Bundle{Rules: []Rule{{
		ID: "r", Type: RuleAppTimeBlock, Target: "steam.exe",
		Start: start, End: end, ActiveDays: weekdays(time.Monday),
	}}})
	if !e.EvaluateProcess("steam.exe", at(2026, 8, 31, 10, 0)).Blocked { // Pzt 10:00
		t.Error("Pzt 10:00 yasak olmalı")
	}
	if e.EvaluateProcess("steam.exe", at(2026, 8, 31, 18, 0)).Blocked { // Pzt 18:00
		t.Error("Pzt 18:00 pencere dışı, yasak olmamalı")
	}
}

func TestBlockAlwaysAndTargetMatch(t *testing.T) {
	e := New(Bundle{Rules: []Rule{{ID: "x", Type: RuleAppBlockAlways, Target: "torrent.exe"}}})
	// Tam yol da dosya adıyla eşleşmeli.
	if !e.EvaluateProcess("D:\\apps\\torrent.exe", at(2026, 8, 28, 3, 0)).Blocked {
		t.Error("tam yol hedef dosya adıyla eşleşmeliydi")
	}
	// Alakasız süreç eşleşmemeli.
	if e.EvaluateProcess("notepad.exe", at(2026, 8, 28, 3, 0)).Blocked {
		t.Error("alakasız süreç yasaklanmamalı")
	}
}
