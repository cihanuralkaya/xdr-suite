package db

import (
	"context"
	"fmt"
	"time"

	"xdr.corp/suite/server/internal/adminread"
)

// Derleme-zamanı arayüz kontrolü.
var _ adminread.Store = (*Store)(nil)

// ListDevices, cihazları son görülmeye göre listeler (okuma API'si).
func (s *Store) ListDevices(ctx context.Context, limit int) ([]adminread.DeviceRow, error) {
	const q = `
		SELECT id::text, status::text, COALESCE(agent_version,''),
		       COALESCE(os_platform,''), COALESCE(last_seen, 'epoch'::timestamptz),
		       hostname_encrypted, mac_address_encrypted
		  FROM devices
		 ORDER BY last_seen DESC NULLS LAST
		 LIMIT $1`
	rows, err := s.pool.Query(ctx, q, limit)
	if err != nil {
		return nil, fmt.Errorf("db: cihaz listesi: %w", err)
	}
	defer rows.Close()

	var out []adminread.DeviceRow
	for rows.Next() {
		var d adminread.DeviceRow
		var lastSeen time.Time
		if err := rows.Scan(&d.ID, &d.Status, &d.AgentVersion, &d.OSPlatform,
			&lastSeen, &d.HostnameEnc, &d.MACEnc); err != nil {
			return nil, fmt.Errorf("db: cihaz okuma: %w", err)
		}
		d.LastSeen = lastSeen
		out = append(out, d)
	}
	return out, rows.Err()
}

// ListEvents, olay loglarını (deviceID boşsa tümünü) en yeniden eskiye listeler.
func (s *Store) ListEvents(ctx context.Context, deviceID string, limit int) ([]adminread.EventRow, error) {
	const q = `
		SELECT id::text, category::text, severity::text, message, occurred_at, created_at
		  FROM event_logs
		 WHERE ($1 = '' OR device_id = NULLIF($1,'')::uuid)
		 ORDER BY created_at DESC
		 LIMIT $2`
	rows, err := s.pool.Query(ctx, q, deviceID, limit)
	if err != nil {
		return nil, fmt.Errorf("db: olay listesi: %w", err)
	}
	defer rows.Close()

	var out []adminread.EventRow
	for rows.Next() {
		var e adminread.EventRow
		if err := rows.Scan(&e.ID, &e.Category, &e.Severity, &e.Message, &e.OccurredAt, &e.CreatedAt); err != nil {
			return nil, fmt.Errorf("db: olay okuma: %w", err)
		}
		out = append(out, e)
	}
	return out, rows.Err()
}
