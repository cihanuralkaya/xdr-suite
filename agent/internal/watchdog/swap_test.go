package watchdog

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFileSwapperSwapAndRollback(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "agent")
	stageDir := filepath.Join(dir, "updates")
	if err := os.MkdirAll(stageDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bin, []byte("ESKI-SURUM"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stageDir, "agent-staged"), []byte("YENI-SURUM"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stageDir, "agent-staged.version"), []byte("2.0.0"), 0o644); err != nil {
		t.Fatal(err)
	}

	sw := NewFileSwapper(bin, stageDir)

	ver, _, ok := sw.PendingStaged()
	if !ok || ver != "2.0.0" {
		t.Fatalf("bekleyen staged güncelleme bulunmalıydı: ver=%q ok=%v", ver, ok)
	}

	// Swap: ikili yeni sürüm olmalı, yedek eski sürümü tutmalı.
	if err := sw.Swap(); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(bin); string(b) != "YENI-SURUM" {
		t.Fatalf("swap sonrası ikili yeni sürüm olmalı: %q", b)
	}
	if b, _ := os.ReadFile(bin + ".bak"); string(b) != "ESKI-SURUM" {
		t.Fatalf("yedek eski sürümü tutmalı: %q", b)
	}
	// Staged tüketilmiş olmalı.
	if _, _, ok := sw.PendingStaged(); ok {
		t.Fatal("swap sonrası bekleyen staged kalmamalı")
	}

	// Rollback: ikili tekrar eski sürüm olmalı.
	if err := sw.Rollback(); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(bin); string(b) != "ESKI-SURUM" {
		t.Fatalf("rollback sonrası ikili eski sürüm olmalı: %q", b)
	}
}

func TestFileSwapperNoPending(t *testing.T) {
	dir := t.TempDir()
	sw := NewFileSwapper(filepath.Join(dir, "agent"), filepath.Join(dir, "updates"))
	if _, _, ok := sw.PendingStaged(); ok {
		t.Fatal("staged yokken pending false olmalı")
	}
}
