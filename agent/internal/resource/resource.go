// Package resource, uç noktanın kaynak kullanımı anlık görüntüsünü (bellek/disk
// kullanımı + uptime) toplar — uç-nokta sağlığı görünürlüğü (EDR). OS-özel
// sorgular exec/proc ile yapılır; hesaplama ve ayrıştırma platform-bağımsız ve
// test edilebilir tutulur (compliance/inventory ile aynı desen).
package resource

import (
	"strconv"
	"strings"
)

// Snapshot, bir anlık kaynak kullanımı görüntüsüdür. OK=false ise veri alınamadı.
type Snapshot struct {
	MemTotalMB  int  `json:"mem_total_mb"`
	MemUsedPct  int  `json:"mem_used_pct"`
	DiskTotalGB int  `json:"disk_total_gb"`
	DiskUsedPct int  `json:"disk_used_pct"`
	UptimeHours int  `json:"uptime_hours"`
	OK          bool `json:"-"`
}

// Collector, OS-özel kaynak anlık görüntüsü sağlar.
type Collector interface {
	// Snapshot, mevcut kaynak kullanımını döner. Alınamazsa OK=false.
	Snapshot() Snapshot
}

// Collect, mevcut platformun kaynak anlık görüntüsünü döner.
func Collect() Snapshot { return NewCollector().Snapshot() }

// computeSnapshot, ham ölçümlerden yüzdeleri hesaplar (platform-bağımsız çekirdek).
// memTotalKB/memAvailKB kilobayt; disk baytlar; uptimeSec saniye.
func computeSnapshot(memTotalKB, memAvailKB, diskTotal, diskFree, uptimeSec int64) Snapshot {
	s := Snapshot{OK: true}
	if memTotalKB > 0 {
		s.MemTotalMB = int(memTotalKB / 1024)
		used := memTotalKB - memAvailKB
		if used < 0 {
			used = 0
		}
		s.MemUsedPct = int(used * 100 / memTotalKB)
	}
	if diskTotal > 0 {
		s.DiskTotalGB = int(diskTotal / (1024 * 1024 * 1024))
		used := diskTotal - diskFree
		if used < 0 {
			used = 0
		}
		s.DiskUsedPct = int(used * 100 / diskTotal)
	}
	if uptimeSec > 0 {
		s.UptimeHours = int(uptimeSec / 3600)
	}
	return s
}

// parseKV, "key=value" satırlarından bir harita çıkarır (Windows PowerShell
// çıktısı için). Boş/hatalı satırlar atlanır.
func parseKV(out string) map[string]string {
	m := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		i := strings.IndexByte(line, '=')
		if i <= 0 {
			continue
		}
		m[strings.TrimSpace(line[:i])] = strings.TrimSpace(line[i+1:])
	}
	return m
}

// parseMeminfo, Linux /proc/meminfo içeriğinden MemTotal ve MemAvailable
// (kilobayt) değerlerini çıkarır. Satır biçimi "MemTotal:  16384 kB".
func parseMeminfo(out string) (total, avail int64) {
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		v, _ := strconv.ParseInt(fields[1], 10, 64)
		switch fields[0] {
		case "MemTotal:":
			total = v
		case "MemAvailable:":
			avail = v
		}
	}
	return total, avail
}

// parseUptimeProc, Linux /proc/uptime ilk alanından (saniye, ondalık) uptime'ı
// tamsayı saniye olarak döner.
func parseUptimeProc(out string) int64 {
	fields := strings.Fields(out)
	if len(fields) == 0 {
		return 0
	}
	sec, _ := strconv.ParseFloat(fields[0], 64)
	if sec < 0 {
		return 0
	}
	return int64(sec)
}

// atoi64, güvenli string→int64 (hata/boşluk → 0).
func atoi64(s string) int64 {
	v, _ := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	return v
}
