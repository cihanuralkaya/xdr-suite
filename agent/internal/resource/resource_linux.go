//go:build linux

package resource

import (
	"os"
	"syscall"
)

type linuxCollector struct{}

// NewCollector, mevcut platform için kaynak toplayıcısı döner.
func NewCollector() Collector { return linuxCollector{} }

// Snapshot, /proc/meminfo (bellek), statfs("/") (disk) ve /proc/uptime (uptime)
// üzerinden kaynak kullanımını toplar. Herhangi biri alınamazsa o alan 0 kalır.
func (linuxCollector) Snapshot() Snapshot {
	var memTotal, memAvail int64
	if b, err := os.ReadFile("/proc/meminfo"); err == nil {
		memTotal, memAvail = parseMeminfo(string(b))
	}
	var diskTotal, diskFree int64
	var st syscall.Statfs_t
	if err := syscall.Statfs("/", &st); err == nil {
		diskTotal = int64(st.Blocks) * int64(st.Bsize)
		diskFree = int64(st.Bavail) * int64(st.Bsize)
	}
	var uptimeSec int64
	if b, err := os.ReadFile("/proc/uptime"); err == nil {
		uptimeSec = parseUptimeProc(string(b))
	}
	return computeSnapshot(memTotal, memAvail, diskTotal, diskFree, uptimeSec)
}
