package retention

import (
	"testing"
	"time"
)

func month(y int, m time.Month) time.Time {
	return time.Date(y, m, 1, 0, 0, 0, 0, time.UTC)
}

func TestPartitionName(t *testing.T) {
	if got := PartitionName(month(2026, time.August)); got != "event_logs_2026_08" {
		t.Fatalf("ad yanlış: %s", got)
	}
}

func TestPlanDropsOldKeepsRecent(t *testing.T) {
	now := time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)
	// 90 gün saklama. Kesim ~ 2026-05-30. Mayıs partition'ı (sonu 1 Haziran) kesimden
	// sonra bitmiyor mu? 1 Haziran > 30 Mayıs → Mayıs KALIR. Nisan (sonu 1 Mayıs) düşer.
	existing := []time.Time{
		month(2026, time.March), month(2026, time.April), month(2026, time.May),
		month(2026, time.June), month(2026, time.July), month(2026, time.August),
	}
	_, drop := PlanPartitions(now, 90, 2, existing)

	dropSet := map[string]bool{}
	for _, d := range drop {
		dropSet[PartitionName(d)] = true
	}
	if !dropSet["event_logs_2026_03"] || !dropSet["event_logs_2026_04"] {
		t.Fatalf("Mart ve Nisan düşmeliydi: %v", dropSet)
	}
	if dropSet["event_logs_2026_05"] || dropSet["event_logs_2026_08"] {
		t.Fatalf("Mayıs/Ağustos düşmemeliydi: %v", dropSet)
	}
}

func TestPlanCreatesFutureMonths(t *testing.T) {
	now := time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)
	// Ağustos var; Eylül/Ekim yok → oluşturulmalı (aheadMonths=2).
	existing := []time.Time{month(2026, time.August)}
	create, _ := PlanPartitions(now, 90, 2, existing)

	names := map[string]bool{}
	for _, c := range create {
		names[PartitionName(c)] = true
	}
	if names["event_logs_2026_08"] {
		t.Fatal("var olan Ağustos tekrar oluşturulmamalı")
	}
	if !names["event_logs_2026_09"] || !names["event_logs_2026_10"] {
		t.Fatalf("Eylül ve Ekim oluşturulmalıydı: %v", names)
	}
}

func TestPlanYearBoundary(t *testing.T) {
	now := time.Date(2026, 12, 15, 0, 0, 0, 0, time.UTC)
	create, _ := PlanPartitions(now, 90, 2, nil)
	names := map[string]bool{}
	for _, c := range create {
		names[PartitionName(c)] = true
	}
	// Aralık 2026 + Ocak/Şubat 2027.
	if !names["event_logs_2026_12"] || !names["event_logs_2027_01"] || !names["event_logs_2027_02"] {
		t.Fatalf("yıl sınırı yanlış: %v", names)
	}
}
