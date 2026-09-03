//go:build linux

package enforce

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// linuxController, Linux'ta /proc üzerinden süreç listeleme ve sinyal ile
// sonlandırma sağlar.
type linuxController struct{}

// NewProcessController, mevcut platform için süreç kontrolcüsü döner.
func NewProcessController() ProcessController { return linuxController{} }

// List, /proc altındaki sayısal dizinleri tarayarak çalışan süreçleri listeler.
func (linuxController) List() ([]Process, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}
	var procs []Process
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue // sayısal olmayan (ör. /proc/self) atla
		}
		base := filepath.Join("/proc", e.Name())
		name := readComm(filepath.Join(base, "comm"))
		path, _ := os.Readlink(filepath.Join(base, "exe")) // başka kullanıcıda başarısız olabilir
		ppid := readPPID(filepath.Join(base, "stat"))
		procs = append(procs, Process{PID: uint32(pid), PPID: ppid, Name: name, Path: path})
	}
	return procs, nil
}

// Kill, verilen PID'li süreci SIGKILL ile sonlandırır.
func (linuxController) Kill(pid uint32) error {
	return syscall.Kill(int(pid), syscall.SIGKILL)
}

func readComm(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// readPPID, /proc/<pid>/stat dosyasından ebeveyn PID'ini okur. Ayrıştırma
// parsePPIDStat'ta (test edilebilir, platform-bağımsız). Okunamazsa 0.
func readPPID(statPath string) uint32 {
	b, err := os.ReadFile(statPath)
	if err != nil {
		return 0
	}
	return parsePPIDStat(string(b))
}
