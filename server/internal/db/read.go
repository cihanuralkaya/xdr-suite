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
// severity ve category boş ("") değilse ilgili ENUM sütununa göre sunucu-tarafında
// filtre uygulanır. details, ham JSON metni olarak okunur (yoksa nil).
func (s *Store) ListEvents(ctx context.Context, deviceID, severity, category string, limit int) ([]adminread.EventRow, error) {
	const q = `
		SELECT id::text, category::text, severity::text, message, occurred_at, created_at,
		       COALESCE(details::text, '')
		  FROM event_logs
		 WHERE ($1 = '' OR device_id = NULLIF($1,'')::uuid)
		   AND ($2 = '' OR severity = $2::severity)
		   AND ($3 = '' OR category = $3::event_category)
		 ORDER BY created_at DESC
		 LIMIT $4`
	rows, err := s.pool.Query(ctx, q, deviceID, severity, category, limit)
	if err != nil {
		return nil, fmt.Errorf("db: olay listesi: %w", err)
	}
	defer rows.Close()

	var out []adminread.EventRow
	for rows.Next() {
		var e adminread.EventRow
		var details string
		if err := rows.Scan(&e.ID, &e.Category, &e.Severity, &e.Message, &e.OccurredAt, &e.CreatedAt, &details); err != nil {
			return nil, fmt.Errorf("db: olay okuma: %w", err)
		}
		if details != "" {
			e.Details = []byte(details)
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// ListAudit, denetim izini (audit_log) admin e-postasıyla birlikte en yeniden
// eskiye listeler. Admin silinmiş/eşleşmemişse e-posta boş döner (LEFT JOIN).
func (s *Store) ListAudit(ctx context.Context, limit int) ([]adminread.AuditRow, error) {
	const q = `
		SELECT a.id, COALESCE(ad.email,''), a.action::text,
		       COALESCE(a.target_type,''), COALESCE(a.target_id::text,''), a.created_at
		  FROM audit_log a
		  LEFT JOIN admins ad ON ad.id = a.admin_id
		 ORDER BY a.created_at DESC
		 LIMIT $1`
	rows, err := s.pool.Query(ctx, q, limit)
	if err != nil {
		return nil, fmt.Errorf("db: denetim izi listesi: %w", err)
	}
	defer rows.Close()

	var out []adminread.AuditRow
	for rows.Next() {
		var a adminread.AuditRow
		if err := rows.Scan(&a.ID, &a.AdminEmail, &a.Action, &a.TargetType, &a.TargetID, &a.CreatedAt); err != nil {
			return nil, fmt.Errorf("db: denetim izi okuma: %w", err)
		}
		out = append(out, a)
	}
	return out, rows.Err()
}
