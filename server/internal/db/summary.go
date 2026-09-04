package db

import (
	"context"
	"fmt"
	"time"

	"xdr.corp/suite/server/internal/adminread"
)

// DeviceStatusCounts, cihazları durumuna göre gruplayıp (status -> adet) döner.
func (s *Store) DeviceStatusCounts(ctx context.Context) (map[string]int, error) {
	const q = `SELECT status::text, count(*) FROM devices GROUP BY status`
	rows, err := s.pool.Query(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("db: cihaz durum sayımı: %w", err)
	}
	defer rows.Close()

	out := map[string]int{}
	for rows.Next() {
		var status string
		var n int
		if err := rows.Scan(&status, &n); err != nil {
			return nil, fmt.Errorf("db: cihaz durum okuma: %w", err)
		}
		out[status] = n
	}
	return out, rows.Err()
}

// EventSeverityCounts, since'ten bu yana olayları önem seviyesine göre sayar.
func (s *Store) EventSeverityCounts(ctx context.Context, since time.Time) (map[string]int, error) {
	const q = `SELECT severity::text, count(*) FROM event_logs WHERE created_at >= $1 GROUP BY severity`
	return s.eventCounts(ctx, q, since, "olay önem sayımı")
}

// EventCategoryCounts, since'ten bu yana olayları kategoriye göre sayar.
func (s *Store) EventCategoryCounts(ctx context.Context, since time.Time) (map[string]int, error) {
	const q = `SELECT category::text, count(*) FROM event_logs WHERE created_at >= $1 GROUP BY category`
	return s.eventCounts(ctx, q, since, "olay kategori sayımı")
}

// LatestComplianceByDevice, uyum verisi (disk_encryption/firewall) taşıyan her
// cihazın EN SON durumunu döner. DISTINCT ON ile cihaz başına en yeni uyum-olayı
// seçilir; JSONB alanları metne çıkarılır.
func (s *Store) LatestComplianceByDevice(ctx context.Context) (map[string]adminread.ComplianceStatus, error) {
	const q = `
		SELECT DISTINCT ON (device_id) device_id::text,
		       COALESCE(details->>'disk_encryption',''), COALESCE(details->>'firewall','')
		  FROM event_logs
		 WHERE details ? 'disk_encryption' OR details ? 'firewall'
		 ORDER BY device_id, created_at DESC`
	rows, err := s.pool.Query(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("db: uyum durumu sorgusu: %w", err)
	}
	defer rows.Close()

	out := map[string]adminread.ComplianceStatus{}
	for rows.Next() {
		var id, enc, fw string
		if err := rows.Scan(&id, &enc, &fw); err != nil {
			return nil, fmt.Errorf("db: uyum durumu okuma: %w", err)
		}
		out[id] = adminread.ComplianceStatus{Enc: enc, Fw: fw}
	}
	return out, rows.Err()
}

// eventCounts, tek anahtar+adet dönen GROUP BY sorgularını çalıştırır.
func (s *Store) eventCounts(ctx context.Context, q string, since time.Time, what string) (map[string]int, error) {
	rows, err := s.pool.Query(ctx, q, since)
	if err != nil {
		return nil, fmt.Errorf("db: %s: %w", what, err)
	}
	defer rows.Close()

	out := map[string]int{}
	for rows.Next() {
		var key string
		var n int
		if err := rows.Scan(&key, &n); err != nil {
			return nil, fmt.Errorf("db: %s okuma: %w", what, err)
		}
		out[key] = n
	}
	return out, rows.Err()
}
