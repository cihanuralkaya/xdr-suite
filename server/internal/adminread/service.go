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
	// DeviceStatusCounts, cihaz durumuna göre (status -> adet) sayımları döner.
	DeviceStatusCounts(ctx context.Context) (map[string]int, error)
	// EventSeverityCounts, since'ten bu yana olayları önem seviyesine göre sayar.
	EventSeverityCounts(ctx context.Context, since time.Time) (map[string]int, error)
	// EventCategoryCounts, since'ten bu yana olayları kategoriye göre sayar.
	EventCategoryCounts(ctx context.Context, since time.Time) (map[string]int, error)
	ListAudit(ctx context.Context, limit int) ([]AuditRow, error)
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

// SummaryDTO, yönetim panosu için özet/KPI sayaçlarıdır.
type SummaryDTO struct {
	DevicesTotal       int            `json:"devices_total"`
	DevicesOnline      int            `json:"devices_online"`
	DevicesOffline     int            `json:"devices_offline"`
	DevicesQuarantined int            `json:"devices_quarantined"`
	EventsBySeverity   map[string]int `json:"events_by_severity"` // INFO/LOW/MEDIUM/HIGH/CRITICAL
	EventsByCategory   map[string]int `json:"events_by_category"`
	Since              time.Time      `json:"since"` // sayımların kapsadığı pencerenin başı (RFC3339)
}

// summaryWindow, özet olay sayımlarının kapsadığı zaman penceresidir (son 24 saat).
const summaryWindow = 24 * time.Hour

// onlineWindow, bir cihazın "çevrimiçi" sayılması için son görülme eşiğidir.
const onlineWindow = 30 * time.Second

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

// Summary, yönetim panosu için özet/KPI sayaçlarını hesaplar. Cihazlar duruma
// göre gruplanır; olaylar son 24 saatlik pencerede önem ve kategoriye göre
// sayılır. "online", cihaz listesinden son görülme (< onlineWindow) üzerinden
// hesaplanır (duruma ek, best-effort).
func (s *Service) Summary(ctx context.Context) (SummaryDTO, error) {
	now := time.Now()
	since := now.Add(-summaryWindow)

	statusCounts, err := s.store.DeviceStatusCounts(ctx)
	if err != nil {
		return SummaryDTO{}, err
	}
	sevCounts, err := s.store.EventSeverityCounts(ctx, since)
	if err != nil {
		return SummaryDTO{}, err
	}
	catCounts, err := s.store.EventCategoryCounts(ctx, since)
	if err != nil {
		return SummaryDTO{}, err
	}

	total := 0
	for _, n := range statusCounts {
		total += n
	}

	// online: cihaz listesinden son görülmesi eşiğin altında olanları say.
	rows, err := s.store.ListDevices(ctx, clampLimit(0))
	if err != nil {
		return SummaryDTO{}, err
	}
	online := 0
	for _, r := range rows {
		if now.Sub(r.LastSeen) < onlineWindow {
			online++
		}
	}
	offline := total - online
	if offline < 0 {
		offline = 0
	}

	if sevCounts == nil {
		sevCounts = map[string]int{}
	}
	if catCounts == nil {
		catCounts = map[string]int{}
	}

	return SummaryDTO{
		DevicesTotal:       total,
		DevicesOnline:      online,
		DevicesOffline:     offline,
		DevicesQuarantined: statusCounts["QUARANTINED"],
		EventsBySeverity:   sevCounts,
		EventsByCategory:   catCounts,
		Since:              since,
	}, nil
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
