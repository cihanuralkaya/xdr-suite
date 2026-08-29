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

// CertRow, DB'den okunan ham sertifika satırıdır. Fingerprint hex-kodlu döner.
type CertRow struct {
	Serial      string
	Fingerprint string // SHA-256(DER), hex
	NotBefore   time.Time
	NotAfter    time.Time
	Revoked     bool
}

// CmdRow, DB'den okunan ham komut geçmişi satırıdır. DeliveredAt nil ise komut
// henüz teslim edilmemiştir (bekliyor).
type CmdRow struct {
	Type        string
	IssuedBy    string
	CreatedAt   time.Time
	DeliveredAt *time.Time
}

// Store, okuma sorgularının kalıcılık kaynağıdır.
type Store interface {
	ListDevices(ctx context.Context, limit int) ([]DeviceRow, error)
	ListEvents(ctx context.Context, deviceID string, limit int) ([]EventRow, error)
	DeviceByID(ctx context.Context, id string) (DeviceRow, bool, error)
	CertsByDevice(ctx context.Context, id string) ([]CertRow, error)
	CommandHistory(ctx context.Context, id string) ([]CmdRow, error)
	AssignedPolicy(ctx context.Context, id string) (policyID, version string, err error)
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

// CertView, konsola dönen sertifika görünümüdür.
type CertView struct {
	Serial      string    `json:"serial"`
	Fingerprint string    `json:"fingerprint"`
	NotBefore   time.Time `json:"not_before"`
	NotAfter    time.Time `json:"not_after"`
	Revoked     bool      `json:"revoked"`
}

// CmdView, konsola dönen komut geçmişi görünümüdür. DeliveredAt nil ise JSON'da
// null olur (komut bekliyor).
type CmdView struct {
	Type        string     `json:"type"`
	IssuedBy    string     `json:"issued_by"`
	CreatedAt   time.Time  `json:"created_at"`
	DeliveredAt *time.Time `json:"delivered_at"`
}

// DeviceDetailDTO, tek bir cihazın tam görünümüdür (deşifre edilmiş cihaz alanları
// + sertifikalar + komut geçmişi + atanmış politika).
type DeviceDetailDTO struct {
	Device                DeviceDTO  `json:"device"`
	Certs                 []CertView `json:"certs"`
	Commands              []CmdView  `json:"commands"`
	AssignedPolicyID      string     `json:"assigned_policy_id"`
	AssignedPolicyVersion string     `json:"assigned_policy_version"`
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

// DeviceDetail, tek bir cihazın tam görünümünü döner. Cihaz bulunamazsa
// ok=false döner. Şifreli alanlar (hostname, mac) sunucuda deşifre edilir.
func (s *Service) DeviceDetail(ctx context.Context, id string) (DeviceDetailDTO, bool, error) {
	row, ok, err := s.store.DeviceByID(ctx, id)
	if err != nil || !ok {
		return DeviceDetailDTO{}, ok, err
	}
	certRows, err := s.store.CertsByDevice(ctx, id)
	if err != nil {
		return DeviceDetailDTO{}, false, err
	}
	cmdRows, err := s.store.CommandHistory(ctx, id)
	if err != nil {
		return DeviceDetailDTO{}, false, err
	}
	policyID, policyVersion, err := s.store.AssignedPolicy(ctx, id)
	if err != nil {
		return DeviceDetailDTO{}, false, err
	}

	certs := make([]CertView, 0, len(certRows))
	for _, c := range certRows {
		certs = append(certs, CertView{
			Serial:      c.Serial,
			Fingerprint: c.Fingerprint,
			NotBefore:   c.NotBefore,
			NotAfter:    c.NotAfter,
			Revoked:     c.Revoked,
		})
	}
	commands := make([]CmdView, 0, len(cmdRows))
	for _, c := range cmdRows {
		commands = append(commands, CmdView{
			Type:        c.Type,
			IssuedBy:    c.IssuedBy,
			CreatedAt:   c.CreatedAt,
			DeliveredAt: c.DeliveredAt,
		})
	}

	return DeviceDetailDTO{
		Device: DeviceDTO{
			ID:           row.ID,
			Hostname:     s.decrypt(row.HostnameEnc),
			MAC:          s.decrypt(row.MACEnc),
			Status:       row.Status,
			AgentVersion: row.AgentVersion,
			OSPlatform:   row.OSPlatform,
			LastSeen:     row.LastSeen,
		},
		Certs:                 certs,
		Commands:              commands,
		AssignedPolicyID:      policyID,
		AssignedPolicyVersion: policyVersion,
	}, true, nil
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
