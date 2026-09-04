//go:build windows

package resource

import (
	"os/exec"
	"time"
)

type winCollector struct{}

// NewCollector, mevcut platform için kaynak toplayıcısı döner.
func NewCollector() Collector { return winCollector{} }

// psScript, tek PowerShell çağrısında bellek/disk/boot değerlerini key=value
// biçiminde döndürür (wmic Windows 11'de kaldırıldığı için CIM kullanılır).
const psScript = `$os=Get-CimInstance Win32_OperatingSystem;` +
	`$d=Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='$env:SystemDrive'";` +
	`Write-Output ('mem_total_kb='+$os.TotalVisibleMemorySize);` +
	`Write-Output ('mem_free_kb='+$os.FreePhysicalMemory);` +
	`Write-Output ('disk_total='+$d.Size);` +
	`Write-Output ('disk_free='+$d.FreeSpace);` +
	`Write-Output ('boot='+$os.LastBootUpTime.ToString('o'))`

// Snapshot, CIM üzerinden bellek/disk/uptime toplar.
func (winCollector) Snapshot() Snapshot {
	out, err := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", psScript).Output()
	if err != nil {
		return Snapshot{}
	}
	kv := parseKV(string(out))
	var uptimeSec int64
	if bt, err := time.Parse(time.RFC3339, kv["boot"]); err == nil {
		if d := time.Since(bt); d > 0 {
			uptimeSec = int64(d.Seconds())
		}
	}
	return computeSnapshot(atoi64(kv["mem_total_kb"]), atoi64(kv["mem_free_kb"]),
		atoi64(kv["disk_total"]), atoi64(kv["disk_free"]), uptimeSec)
}
