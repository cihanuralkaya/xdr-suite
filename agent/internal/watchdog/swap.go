// Package watchdog, ajanı canlı tutan gözetmen sürecin çekirdeğidir: süreç
// gözetimi + yeniden başlatma (backoff'lu) ve OTA staged güncellemesinin
// swap/rollback'i.
//
// NOT (tamper koruması, inceleme #5): Bu, kaza sonucu sonlanmalara ve basit
// müdahalelere karşı İLK savunmadır. SYSTEM/root yetkili bir kullanıcıya karşı
// gerçek koruma ayrı bir fazda (MiniFilter sürücüsü + PPL/ELAM) gelir.
package watchdog

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// FileSwapper, staging'deki yeni ikiliyi ajan ikilisiyle değiştirir; eskisini
// yedekler ve rollback edebilir. Swap DAİMA ajan durmuşken yapılır (Supervisor
// çalıştırmalar arasında çağırır), bu yüzden çalışan ikiliyi ezme sorunu olmaz.
type FileSwapper struct {
	binaryPath string // ajan ikilisinin yolu
	stageDir   string // update.Prepare'in yazdığı dizin
}

// NewFileSwapper oluşturur.
func NewFileSwapper(binaryPath, stageDir string) *FileSwapper {
	return &FileSwapper{binaryPath: binaryPath, stageDir: stageDir}
}

func (s *FileSwapper) stagedPath() string  { return filepath.Join(s.stageDir, "agent-staged") }
func (s *FileSwapper) versionPath() string { return s.stagedPath() + ".version" }
func (s *FileSwapper) backupPath() string  { return s.binaryPath + ".bak" }

// PendingStaged, bekleyen bir staged güncelleme olup olmadığını döner.
func (s *FileSwapper) PendingStaged() (version, path string, ok bool) {
	if !exists(s.stagedPath()) {
		return "", "", false
	}
	ver, _ := os.ReadFile(s.versionPath())
	return string(ver), s.stagedPath(), true
}

// Swap, mevcut ikiliyi yedekler ve staged ikiliyi yerine koyar.
func (s *FileSwapper) Swap() error {
	staged := s.stagedPath()
	if exists(s.binaryPath) {
		if err := copyFile(s.binaryPath, s.backupPath(), 0o755); err != nil {
			return fmt.Errorf("watchdog: yedek alma: %w", err)
		}
	}
	if err := os.Rename(staged, s.binaryPath); err != nil {
		// Farklı disk bölümü olabilir; kopyala-sil ile dene.
		if err2 := copyFile(staged, s.binaryPath, 0o755); err2 != nil {
			return fmt.Errorf("watchdog: swap: %w", err)
		}
		_ = os.Remove(staged)
	}
	_ = os.Remove(s.versionPath())
	return nil
}

// Rollback, yedekten geri döner (yeni sürüm çabuk çökerse).
func (s *FileSwapper) Rollback() error {
	if !exists(s.backupPath()) {
		return fmt.Errorf("watchdog: rollback için yedek yok")
	}
	if err := copyFile(s.backupPath(), s.binaryPath, 0o755); err != nil {
		return fmt.Errorf("watchdog: rollback: %w", err)
	}
	return nil
}

func exists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

func copyFile(src, dst string, perm os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}
