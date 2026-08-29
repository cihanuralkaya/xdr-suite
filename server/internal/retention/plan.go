// Package retention, KVKK saklama politikasını uygular: event_logs'un aylık
// (RANGE) partition'larından saklama süresi dolanları DROP eder ve gelecek aylar
// için partition'ları önceden oluşturur (bkz. docs/kvkk.md).
//
// Planlama saf/deterministik bir fonksiyondur ve DB olmadan test edilebilir;
// DDL yürütme Store arayüzünün arkasındadır.
package retention

import (
	"fmt"
	"sort"
	"time"
)

// MonthStart, verilen zamanın ait olduğu ayın ilk gününü (UTC) döner.
func MonthStart(t time.Time) time.Time {
	t = t.UTC()
	return time.Date(t.Year(), t.Month(), 1, 0, 0, 0, 0, time.UTC)
}

// PartitionName, bir ay-başlangıcı için partition tablo adını döner.
func PartitionName(monthStart time.Time) string {
	m := monthStart.UTC()
	return fmt.Sprintf("event_logs_%04d_%02d", m.Year(), int(m.Month()))
}

// PlanPartitions, mevcut ay-partition listesine göre oluşturulacak ve
// düşürülecek partition'ları hesaplar.
//   - drop: aralığı (ay) tamamen saklama kesim tarihinden (now - retentionDays)
//     önce kalan partition'lar.
//   - create: [bu ay .. bu ay + aheadMonths] arası, henüz olmayan partition'lar.
func PlanPartitions(now time.Time, retentionDays, aheadMonths int, existing []time.Time) (create, drop []time.Time) {
	cutoff := now.UTC().AddDate(0, 0, -retentionDays)

	existSet := make(map[time.Time]bool, len(existing))
	for _, e := range existing {
		existSet[MonthStart(e)] = true
	}

	// Drop: partition sonu (bir sonraki ay başı) kesim tarihinden sonra DEĞİLSE
	// (yani tüm aralık kesimden eski), düşür.
	for m := range existSet {
		end := m.AddDate(0, 1, 0)
		if !end.After(cutoff) {
			drop = append(drop, m)
		}
	}

	// Create: bu ay ve sonraki aheadMonths ay.
	cur := MonthStart(now)
	for i := 0; i <= aheadMonths; i++ {
		m := cur.AddDate(0, i, 0)
		if !existSet[m] {
			create = append(create, m)
		}
	}

	sort.Slice(create, func(i, j int) bool { return create[i].Before(create[j]) })
	sort.Slice(drop, func(i, j int) bool { return drop[i].Before(drop[j]) })
	return create, drop
}
