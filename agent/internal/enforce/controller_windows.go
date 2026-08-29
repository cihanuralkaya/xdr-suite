//go:build windows

package enforce

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

// winController, Windows'ta süreç listeleme/sonlandırma sağlar.
type winController struct{}

// NewProcessController, mevcut platform için süreç kontrolcüsü döner.
func NewProcessController() ProcessController { return winController{} }

// List, çalışan süreçleri Toolhelp anlık görüntüsüyle listeler.
func (winController) List() ([]Process, error) {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(snap)

	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))

	var procs []Process
	err = windows.Process32First(snap, &entry)
	for err == nil {
		pid := entry.ProcessID
		procs = append(procs, Process{
			PID:  pid,
			Name: windows.UTF16ToString(entry.ExeFile[:]),
			Path: processPath(pid),
		})
		err = windows.Process32Next(snap, &entry)
	}
	if err == windows.ERROR_NO_MORE_FILES {
		err = nil
	}
	return procs, err
}

// Kill, verilen PID'li süreci sonlandırır.
func (winController) Kill(pid uint32) error {
	h, err := windows.OpenProcess(windows.PROCESS_TERMINATE, false, pid)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(h)
	return windows.TerminateProcess(h, 1)
}

// processPath, sürecin tam görüntü yolunu döner (erişilemezse boş string).
func processPath(pid uint32) string {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return ""
	}
	defer windows.CloseHandle(h)

	buf := make([]uint16, windows.MAX_PATH)
	size := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(h, 0, &buf[0], &size); err != nil {
		return ""
	}
	return windows.UTF16ToString(buf[:size])
}
