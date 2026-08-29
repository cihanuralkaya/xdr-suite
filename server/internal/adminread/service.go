// Package adminread, yönetim konsolu için okuma (görünürlük) sorgularını sağlar.
// Cihaz kayıtlarındaki şifreli alanları (hostname, mac) sunucu tarafında (ana
// anahtar RAM'de) deşifre eder; olay logları zaten düz metindir (sorgulanabilir
// olması için, bkz. db şema notu).
package adminread

import (
	"context"
	"time"

	"xdr.corp/suite/server/internal/security"
)

// DeviceRow, DB'den okunan ham cihaz satırıdır (şifreli alanlar dahil).
type DeviceRow struct {
	ID           string
	Status       string
	AgentVersion string
	OSPlatform   string
	LastSeen     time.Time
	HostnameEnc  []byte
	MACEnc       []byte
}

// EventRow, DB'den okunan ham olay satırıdır (şifresiz).
type EventRow struct {
	ID         string
	Category   string
	Severity   string
	Message    string
	OccurredAt time.Time
	CreatedAt  time.Time
}

// AuditRow, DB'den okunan ham denetim izi satırıdır (admin e-postası çözülmüş).
type AuditRow struct {
	ID         int64
	AdminEmail string
	Action     string
	TargetType string
	TargetID   string
	CreatedAt  time.Time
}

// Store, okuma sorgularının kalıcılık kaynağıdır.
type Store interface {
	ListDevices(ctx context.Context, limit int) ([]DeviceRow, error)
	ListEvents(ctx context.Context, deviceID string, limit int) ([]EventRow, error)
	ListAudit(ctx context.Context, limit int) ([]AuditRow, error)
}

// DeviceDTO, konsola dönen deşifre edilmiş cihaz görünümüdür.
type DeviceDTO struct {
	ID           string    `json:"id"`
	Hostname     string    `json:"hostname"`
	MAC          string    `json:"mac"`
	Status       string    `json:"status"`
	AgentVersion string    `json:"agent_version"`
	OSPlatform   string    `json:"os_platform"`
	LastSeen     time.Time `json:"last_seen"`
}

// EventDTO, konsola dönen olay görünümüdür.
type EventDTO struct {
	ID         string    `json:"id"`
	Category   string    `json:"category"`
	Severity   string    `json:"severity"`
	Message    string    `json:"message"`
	OccurredAt time.Time `json:"occurred_at"`
	CreatedAt  time.Time `json:"created_at"`
}

// AuditDTO, konsola dönen denetim izi görünümüdür.
type AuditDTO struct {
	ID         int64     `json:"id"`
	AdminEmail string    `json:"admin_email"`
	Action     string    `json:"action"`
	TargetType string    `json:"target_type"`
	TargetID   string    `json:"target_id"`
	CreatedAt  time.Time `json:"created_at"`
}

// Service, okuma sorgularını yürütür ve şifreli alanları deşifre eder.
type Service struct {
	store  Store
	cipher *security.FieldCipher
}

// NewService oluşturur.
func NewService(store Store, cipher *security.FieldCipher) *Service {
	return &Service{store: store, cipher: cipher}
}

// Devices, cihaz listesini (deşifre edilmiş) döner.
func (s *Service) Devices(ctx context.Context, limit int) ([]DeviceDTO, error) {
	rows, err := s.store.ListDevices(ctx, clampLimit(limit))
	if err != nil {
		return nil, err
	}
	out := make([]DeviceDTO, 0, len(rows))
	for _, r := range rows {
		out = append(out, DeviceDTO{
			ID:           r.ID,
			Hostname:     s.decrypt(r.HostnameEnc),
			MAC:          s.decrypt(r.MACEnc),
			Status:       r.Status,
			AgentVersion: r.AgentVersion,
			OSPlatform:   r.OSPlatform,
			LastSeen:     r.LastSeen,
		})
	}
	return out, nil
}

// Events, bir cihazın (deviceID boşsa tümünün) olaylarını döner.
func (s *Service) Events(ctx context.Context, deviceID string, limit int) ([]EventDTO, error) {
	rows, err := s.store.ListEvents(ctx, deviceID, clampLimit(limit))
	if err != nil {
		return nil, err
	}
	out := make([]EventDTO, 0, len(rows))
	for _, r := range rows {
		out = append(out, EventDTO{
			ID:         r.ID,
			Category:   r.Category,
			Severity:   r.Severity,
			Message:    r.Message,
			OccurredAt: r.OccurredAt,
			CreatedAt:  r.CreatedAt,
		})
	}
	return out, nil
}

// Audit, denetim izi kayıtlarını en yeniden eskiye döner.
func (s *Service) Audit(ctx context.Context, limit int) ([]AuditDTO, error) {
	rows, err := s.store.ListAudit(ctx, clampLimit(limit))
	if err != nil {
		return nil, err
	}
	out := make([]AuditDTO, 0, len(rows))
	for _, r := range rows {
		out = append(out, AuditDTO{
			ID:         r.ID,
			AdminEmail: r.AdminEmail,
			Action:     r.Action,
			TargetType: r.TargetType,
			TargetID:   r.TargetID,
			CreatedAt:  r.CreatedAt,
		})
	}
	return out, nil
}

func (s *Service) decrypt(blob []byte) string {
	if len(blob) == 0 {
		return ""
	}
	v, err := s.cipher.DecryptString(blob)
	if err != nil {
		return "(çözülemedi)"
	}
	return v
}

func clampLimit(n int) int {
	if n <= 0 {
		return 100
	}
	if n > 1000 {
		return 1000
	}
	return n
}
