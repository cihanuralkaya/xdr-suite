package retention

import (
	"context"
	"testing"
	"time"
)

type memStore struct {
	existing    []time.Time
	created     []string
	dropped     []string
	purgeCutoff time.Time // PurgeArtifactsOlderThan'a geçirilen cutoff
	purgeReturn int       // döndürülecek silme sayısı
	purgeCalls  int
}

func (m *memStore) ListPartitions(context.Context) ([]time.Time, error) { return m.existing, nil }
func (m *memStore) CreatePartition(_ context.Context, ms time.Time) error {
	m.created = append(m.created, PartitionName(ms))
	return nil
}
func (m *memStore) DropPartition(_ context.Context, ms time.Time) error {
	m.dropped = append(m.dropped, PartitionName(ms))
	return nil
}
func (m *memStore) PurgeArtifactsOlderThan(_ context.Context, cutoff time.Time) (int, error) {
	m.purgeCalls++
	m.purgeCutoff = cutoff
	return m.purgeReturn, nil
}

func TestServiceRunCreatesThenDrops(t *testing.T) {
	now := time.Date(2026, 8, 28, 0, 0, 0, 0, time.UTC)
	store := &memStore{existing: []time.Time{
		month(2026, time.March), month(2026, time.August),
	}}
	svc := NewService(store, 90, 2, nil)
	if err := svc.Run(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	// Eylül/Ekim oluşturulmalı; Mart düşmeli.
	if !contains(store.created, "event_logs_2026_09") || !contains(store.created, "event_logs_2026_10") {
		t.Fatalf("gelecek partition'lar oluşturulmalıydı: %v", store.created)
	}
	if !contains(store.dropped, "event_logs_2026_03") {
		t.Fatalf("eski partition düşürülmeliydi: %v", store.dropped)
	}
	if contains(store.dropped, "event_logs_2026_08") {
		t.Fatal("güncel partition düşürülmemeli")
	}
}

// Run, saklama penceresinden (now - retentionDays) eski artefaktları budamalı.
func TestServiceRunPurgesOldArtifacts(t *testing.T) {
	now := time.Date(2026, 8, 28, 0, 0, 0, 0, time.UTC)
	store := &memStore{purgeReturn: 4}
	svc := NewService(store, 90, 2, nil)
	if err := svc.Run(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	if store.purgeCalls != 1 {
		t.Fatalf("artefakt budama tam 1 kez çağrılmalıydı, çağrı: %d", store.purgeCalls)
	}
	wantCutoff := now.AddDate(0, 0, -90)
	if !store.purgeCutoff.Equal(wantCutoff) {
		t.Fatalf("cutoff now-90gün olmalı: beklenen %v, gelen %v", wantCutoff, store.purgeCutoff)
	}
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}
