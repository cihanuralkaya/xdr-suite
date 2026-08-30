// Package memstore, C2'nin ihtiyaç duyduğu tüm depolama arayüzlerini bellek-içi
// karşılayan bir DEMO/TEST deposudur. PostgreSQL olmadan sistemi uçtan uca canlı
// çalıştırmak için kullanılır; KALICILIK YOKTUR (süreç kapanınca veri kaybolur).
//
// Üretimde db.Store kullanılır; memstore yalnız geliştirme/gösterim içindir.
package memstore

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	xdrv1 "xdr.corp/suite/gen/xdr/v1"
	"xdr.corp/suite/server/internal/admin"
	"xdr.corp/suite/server/internal/adminread"
	"xdr.corp/suite/server/internal/enroll"
	"xdr.corp/suite/server/internal/model"
)

type device struct {
	id            string
	hostnameEnc   []byte
	macEnc        []byte
	osEnc         []byte
	macBidx       []byte
	osPlatform    string
	agentVersion  string
	status        string
	policyVersion string
	policyID      string
	lastSeen      time.Time
}

type tokenInfo struct {
	createdBy string
	expiresAt time.Time
	used      bool
	boundDev  string
}

type certRec struct {
	deviceID    string
	serial      string
	fingerprint []byte
	notBefore   time.Time
	notAfter    time.Time
	revoked     bool
}

// cmdRec, komut geçmişi kaydıdır. PendingCommands teslimde bekleyen kuyruğu
// temizlediğinden, geçmiş kaybolmasın diye ayrı tutulur.
type cmdRec struct {
	deviceID    string
	cmdType     string
	issuedBy    string
	createdAt   time.Time
	deliveredAt *time.Time
}

type policyRule struct {
	id, typ, target, start, end string
	activeDays                  []uint32
}

type policyRec struct {
	id, name, version string
	rules             []policyRule
}

type eventRec struct {
	deviceID   string
	category   string
	severity   string
	message    string
	occurredAt time.Time
	createdAt  time.Time
	details    string // serbest biçimli JSON metni ("" = ayrıntı yok)
}

type adminRec struct {
	id, email, passwordHash string
	role                    admin.Role
}

type auditRec struct {
	id         int64
	adminEmail string
	action     string
	targetType string
	targetID   string
	createdAt  time.Time
}

// Store, tüm C2 depolama arayüzlerini bellek-içi karşılar.
type Store struct {
	mu         sync.Mutex
	devices    map[string]*device          // deviceID -> device
	tokens     map[string]*tokenInfo       // tokenIndex(hex) -> token
	certs      []certRec                   // sertifikalar (iptal takibi)
	commands   map[string][]*xdrv1.Command // deviceID -> bekleyen komutlar
	cmdHistory []cmdRec                    // komut geçmişi (teslimde temizlenmez)
	policies   map[string]*policyRec       // policyID -> politika
	events     []eventRec                  // olay logları
	admins     map[string]*adminRec        // email -> admin
	adminsByID map[string]*adminRec        // id -> admin
	audit      []auditRec                  // denetim izi (en eskiden yeniye eklenir)
	auditSeq   int64                       // audit_log identity taklidi
	seq        int
}

// New, boş bir bellek-içi depo oluşturur.
func New() *Store {
	return &Store{
		devices:    map[string]*device{},
		tokens:     map[string]*tokenInfo{},
		commands:   map[string][]*xdrv1.Command{},
		policies:   map[string]*policyRec{},
		admins:     map[string]*adminRec{},
		adminsByID: map[string]*adminRec{},
	}
}

func randID(prefix string) string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return prefix + hex.EncodeToString(b)
}

// --- Tohumlama (demo kurulum) ---

// SeedAdmin, bir yönetici ekler ve id'sini döner.
func (s *Store) SeedAdmin(email, passwordHash string, role admin.Role) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	id := randID("admin-")
	rec := &adminRec{id: id, email: email, passwordHash: passwordHash, role: role}
	s.admins[email] = rec
	s.adminsByID[id] = rec
	return id
}

// SeedDemoPolicy, kural içeren bir demo politikası ekler (konsolda kural editörü
// olmadığından). Hedef zararsız bir sentinel'dir; gerçek bir süreci öldürmez.
func (s *Store) SeedDemoPolicy() (id, version string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	id = randID("pol-")
	version = "demo-1"
	s.policies[id] = &policyRec{
		id: id, name: "Demo Politika", version: version,
		rules: []policyRule{{
			id: "r1", typ: "APP_BLOCK_ALWAYS", target: "xdr-demo-blocked.exe",
		}},
	}
	return id, version
}

// --- enroll.Store ---

func (s *Store) ConsumeEnrollmentToken(_ context.Context, tokenIndex []byte, now time.Time) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.tokens[hex.EncodeToString(tokenIndex)]
	if !ok || t.used || now.After(t.expiresAt) {
		return "", enroll.ErrInvalidToken
	}
	t.used = true
	return t.boundDev, nil
}

func (s *Store) UpsertEnrollingDevice(_ context.Context, in enroll.DeviceEnrollment) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	id := in.PreferredDeviceID
	if id == "" {
		// mac bidx eşleşen cihaz varsa onu güncelle (yeniden kayıt).
		for _, d := range s.devices {
			if len(d.macBidx) > 0 && string(d.macBidx) == string(in.MACBlindIndex) {
				id = d.id
				break
			}
		}
	}
	if id == "" {
		id = randID("dev-")
	}
	s.devices[id] = &device{
		id: id, hostnameEnc: in.HostnameEnc, macEnc: in.MACEnc, osEnc: in.OSInfoEnc,
		macBidx: in.MACBlindIndex, osPlatform: in.OSPlatform, agentVersion: in.AgentVersion,
		status: "ACTIVE", lastSeen: time.Now(),
	}
	return id, nil
}

func (s *Store) SaveCertificate(_ context.Context, c enroll.CertRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.certs = append(s.certs, certRec{
		deviceID: c.DeviceID, serial: c.Serial, fingerprint: c.Fingerprint,
		notBefore: c.NotBefore, notAfter: c.NotAfter,
	})
	return nil
}

// --- DeviceRegistry ---

func (s *Store) TouchHeartbeat(_ context.Context, deviceID, agentVersion string, at time.Time) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	d, ok := s.devices[deviceID]
	if !ok {
		return "", nil // demo: bilinmeyen cihazı sessiz geç
	}
	d.lastSeen = at
	if agentVersion != "" {
		d.agentVersion = agentVersion
	}
	if d.status == "OFFLINE" {
		d.status = "ACTIVE"
	}
	return d.policyVersion, nil
}

// MarkStaleOffline, last_seen'i olderThan'dan eski olan ACTIVE cihazları
// OFFLINE işaretler ve etkilenen sayıyı döner (db.Store ile eşdeğer davranış).
func (s *Store) MarkStaleOffline(_ context.Context, olderThan time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, d := range s.devices {
		if d.status == "ACTIVE" && d.lastSeen.Before(olderThan) {
			d.status = "OFFLINE"
			n++
		}
	}
	return n, nil
}

// SetDeviceStatus, cihaz durumunu doğrudan ayarlar (admin aksiyonu yansıması).
// Bilinmeyen cihaz sessizce yok sayılır (db UPDATE'in 0 satır etkilemesi gibi).
func (s *Store) SetDeviceStatus(_ context.Context, deviceID, status string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if d, ok := s.devices[deviceID]; ok {
		d.status = status
	}
	return nil
}

func (s *Store) PendingCommands(_ context.Context, deviceID string) ([]*xdrv1.Command, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := s.commands[deviceID]
	s.commands[deviceID] = nil
	// Bekleyen komutlar teslim edildi: geçmişteki teslim edilmemiş kayıtları
	// işaretle (geçmiş listesi ayrı tutulur, temizlenmez).
	if len(out) > 0 {
		now := time.Now()
		for i := range s.cmdHistory {
			if s.cmdHistory[i].deviceID == deviceID && s.cmdHistory[i].deliveredAt == nil {
				t := now
				s.cmdHistory[i].deliveredAt = &t
			}
		}
	}
	return out, nil
}

// --- EventSink ---

func (s *Store) SaveEvents(_ context.Context, deviceID string, evs []model.Event) (uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var last uint64
	now := time.Now()
	for _, e := range evs {
		s.events = append(s.events, eventRec{
			deviceID: deviceID, category: e.Category, severity: e.Severity,
			message: e.Message, occurredAt: e.OccurredAt, createdAt: now,
			details: e.Details,
		})
		if e.Sequence > last {
			last = e.Sequence
		}
	}
	// Bellek şişmesini önlemek için son 5000 olayı tut.
	if len(s.events) > 5000 {
		s.events = s.events[len(s.events)-5000:]
	}
	return last, nil
}

// --- PolicyProvider ---

func (s *Store) CurrentPolicy(_ context.Context, deviceID string) (*xdrv1.PolicyBundle, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	d, ok := s.devices[deviceID]
	if !ok || d.policyID == "" {
		return nil, nil
	}
	p, ok := s.policies[d.policyID]
	if !ok {
		return nil, nil
	}
	var rules []*xdrv1.PolicyRule
	for _, r := range p.rules {
		rules = append(rules, &xdrv1.PolicyRule{
			RuleId: r.id, Type: ruleTypeToProto(r.typ), TargetValue: r.target,
			StartTime: r.start, EndTime: r.end, ActiveDays: r.activeDays,
		})
	}
	return &xdrv1.PolicyBundle{PolicyVersion: p.version, Rules: rules, IssuedAt: timestamppb.Now()}, nil
}

// --- UpdateProvider ---

func (s *Store) LatestUpdate(_ context.Context, _, _, _ string) (*xdrv1.UpdateManifest, error) {
	return nil, nil // demo: OTA sürümü yok
}

// --- admin.Store ---

func (s *Store) AdminRole(_ context.Context, adminID string) (admin.Role, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if a, ok := s.adminsByID[adminID]; ok {
		return a.role, nil
	}
	return admin.Role(""), nil
}

func (s *Store) SaveEnrollmentToken(_ context.Context, tokenIndex []byte, createdBy string, expiresAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokens[hex.EncodeToString(tokenIndex)] = &tokenInfo{createdBy: createdBy, expiresAt: expiresAt}
	return nil
}

func (s *Store) EnqueueCommand(_ context.Context, deviceID, cmdType, issuedBy string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.commands[deviceID] = append(s.commands[deviceID], &xdrv1.Command{
		CommandId: randID("cmd-"), Type: commandTypeToProto(cmdType),
	})
	// Geçmişe de ekle (bekleyen kuyruk teslimde temizlense de geçmiş kalır).
	s.cmdHistory = append(s.cmdHistory, cmdRec{
		deviceID: deviceID, cmdType: cmdType, issuedBy: issuedBy, createdAt: time.Now(),
	})
	return nil
}

func (s *Store) RevokeDeviceCerts(_ context.Context, deviceID, _ string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.certs {
		if s.certs[i].deviceID == deviceID {
			s.certs[i].revoked = true
		}
	}
	return nil
}

// WriteAudit, denetim izine bir kayıt ekler. Admin e-postası adminsByID'den
// çözülür (eşleşmezse boş kalır — db LEFT JOIN davranışını taklit eder).
func (s *Store) WriteAudit(_ context.Context, adminID, action, targetType, targetID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var email string
	if a, ok := s.adminsByID[adminID]; ok {
		email = a.email
	}
	s.auditSeq++
	s.audit = append(s.audit, auditRec{
		id: s.auditSeq, adminEmail: email, action: action,
		targetType: targetType, targetID: targetID, createdAt: time.Now(),
	})
	return nil
}

func (s *Store) CreatePolicy(_ context.Context, name, version string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	id := randID("pol-")
	s.policies[id] = &policyRec{id: id, name: name, version: version}
	return id, nil
}

func (s *Store) AssignPolicy(_ context.Context, deviceID, policyID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	d, ok := s.devices[deviceID]
	if !ok {
		return nil
	}
	if p, ok := s.policies[policyID]; ok {
		d.policyID = policyID
		d.policyVersion = p.version
	}
	return nil
}

func (s *Store) AddPolicyRule(_ context.Context, policyID string, in admin.RuleInput) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.policies[policyID]
	if !ok {
		return nil
	}
	days := make([]uint32, 0, len(in.ActiveDays))
	for _, d := range in.ActiveDays {
		if d >= 0 {
			days = append(days, uint32(d))
		}
	}
	if len(days) == 0 {
		days = []uint32{1, 2, 3, 4, 5, 6, 0}
	}
	p.rules = append(p.rules, policyRule{
		id: randID("r-"), typ: in.Type, target: in.Target,
		start: in.Start, end: in.End, activeDays: days,
	})
	return nil
}

// BumpPolicyVersion, politikanın sürümünü yeni bir zaman-damgası etiketine
// yükseltir ve o politikaya atanmış cihazların policyVersion'ını da günceller
// (heartbeat eden ajanlar yeni sürümü görüp yeni paketi çeker).
func (s *Store) BumpPolicyVersion(_ context.Context, policyID string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.policies[policyID]
	if !ok {
		return "", nil
	}
	nv := time.Now().UTC().Format("20060102150405.000000000")
	p.version = nv
	for _, d := range s.devices {
		if d.policyID == policyID {
			d.policyVersion = nv
		}
	}
	return nv, nil
}

func (s *Store) DevicesForPolicy(_ context.Context, policyID string) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for _, d := range s.devices {
		if d.policyID == policyID {
			out = append(out, d.id)
		}
	}
	return out, nil
}

func (s *Store) ListPolicyRules(_ context.Context, policyID string) ([]admin.RuleView, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.policies[policyID]
	if !ok {
		return nil, nil
	}
	var out []admin.RuleView
	for _, r := range p.rules {
		days := make([]int32, 0, len(r.activeDays))
		for _, d := range r.activeDays {
			days = append(days, int32(d))
		}
		out = append(out, admin.RuleView{
			ID: r.id, Type: r.typ, Target: r.target,
			Start: r.start, End: r.end, ActiveDays: days,
		})
	}
	return out, nil
}

// --- adminread.Store ---

// Derleme-zamanı arayüz kontrolü.
var _ adminread.Store = (*Store)(nil)

func (s *Store) ListDevices(_ context.Context, limit int) ([]adminread.DeviceRow, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []adminread.DeviceRow
	for _, d := range s.devices {
		out = append(out, adminread.DeviceRow{
			ID: d.id, Status: d.status, AgentVersion: d.agentVersion, OSPlatform: d.osPlatform,
			LastSeen: d.lastSeen, HostnameEnc: d.hostnameEnc, MACEnc: d.macEnc,
		})
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	return out, nil
}

func (s *Store) ListEvents(_ context.Context, deviceID, severity, category string, limit int) ([]adminread.EventRow, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []adminread.EventRow
	// En yeniden eskiye.
	for i := len(s.events) - 1; i >= 0; i-- {
		e := s.events[i]
		if deviceID != "" && e.deviceID != deviceID {
			continue
		}
		if severity != "" && e.severity != severity {
			continue
		}
		if category != "" && e.category != category {
			continue
		}
		var details []byte
		if e.details != "" {
			details = []byte(e.details)
		}
		out = append(out, adminread.EventRow{
			ID: randID("evt-"), Category: e.category, Severity: e.severity,
			Message: e.message, OccurredAt: e.occurredAt, CreatedAt: e.createdAt,
			Details: details,
		})
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	return out, nil
}

func (s *Store) DeviceStatusCounts(_ context.Context) (map[string]int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[string]int{}
	for _, d := range s.devices {
		out[d.status]++
	}
	return out, nil
}

func (s *Store) EventSeverityCounts(_ context.Context, since time.Time) (map[string]int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[string]int{}
	for _, e := range s.events {
		if e.createdAt.Before(since) {
			continue
		}
		out[e.severity]++
	}
	return out, nil
}

func (s *Store) EventCategoryCounts(_ context.Context, since time.Time) (map[string]int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[string]int{}
	for _, e := range s.events {
		if e.createdAt.Before(since) {
			continue
		}
		out[e.category]++
	}
	return out, nil
}

func (s *Store) ListAudit(_ context.Context, limit int) ([]adminread.AuditRow, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []adminread.AuditRow
	// En yeniden eskiye.
	for i := len(s.audit) - 1; i >= 0; i-- {
		a := s.audit[i]
		out = append(out, adminread.AuditRow{
			ID: a.id, AdminEmail: a.adminEmail, Action: a.action,
			TargetType: a.targetType, TargetID: a.targetID, CreatedAt: a.createdAt,
		})
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	return out, nil
}

func (s *Store) DeviceByID(_ context.Context, id string) (adminread.DeviceRow, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	d, ok := s.devices[id]
	if !ok {
		return adminread.DeviceRow{}, false, nil
	}
	return adminread.DeviceRow{
		ID: d.id, Status: d.status, AgentVersion: d.agentVersion, OSPlatform: d.osPlatform,
		LastSeen: d.lastSeen, HostnameEnc: d.hostnameEnc, MACEnc: d.macEnc,
	}, true, nil
}

func (s *Store) CertsByDevice(_ context.Context, id string) ([]adminread.CertRow, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []adminread.CertRow
	for _, c := range s.certs {
		if c.deviceID != id {
			continue
		}
		out = append(out, adminread.CertRow{
			Serial:      c.serial,
			Fingerprint: hex.EncodeToString(c.fingerprint),
			NotBefore:   c.notBefore,
			NotAfter:    c.notAfter,
			Revoked:     c.revoked,
		})
	}
	return out, nil
}

func (s *Store) CommandHistory(_ context.Context, id string) ([]adminread.CmdRow, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []adminread.CmdRow
	// En yeniden eskiye.
	for i := len(s.cmdHistory) - 1; i >= 0; i-- {
		c := s.cmdHistory[i]
		if c.deviceID != id {
			continue
		}
		out = append(out, adminread.CmdRow{
			Type: c.cmdType, IssuedBy: c.issuedBy, CreatedAt: c.createdAt, DeliveredAt: c.deliveredAt,
		})
	}
	return out, nil
}

func (s *Store) AssignedPolicy(_ context.Context, id string) (string, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	d, ok := s.devices[id]
	if !ok {
		return "", "", nil
	}
	return d.policyID, d.policyVersion, nil
}

// --- revocation.Source ---

func (s *Store) RevokedFingerprints(_ context.Context) ([][]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out [][]byte
	for _, c := range s.certs {
		if c.revoked {
			out = append(out, c.fingerprint)
		}
	}
	return out, nil
}

// --- retention.Store (bellek-içi: no-op) ---

func (s *Store) ListPartitions(context.Context) ([]time.Time, error) { return nil, nil }
func (s *Store) CreatePartition(context.Context, time.Time) error    { return nil }
func (s *Store) DropPartition(context.Context, time.Time) error      { return nil }

// --- adminapi.AuthStore ---

func (s *Store) LookupAdmin(_ context.Context, email string) (string, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if a, ok := s.admins[email]; ok {
		return a.id, a.passwordHash, nil
	}
	return "", "", nil
}

func ruleTypeToProto(t string) xdrv1.PolicyRule_RuleType {
	switch t {
	case "APP_TIME_BLOCK":
		return xdrv1.PolicyRule_RULE_TYPE_APP_TIME_BLOCK
	case "APP_BLOCK_ALWAYS":
		return xdrv1.PolicyRule_RULE_TYPE_APP_BLOCK_ALWAYS
	case "NETWORK_RULE":
		return xdrv1.PolicyRule_RULE_TYPE_NETWORK_RULE
	default:
		return xdrv1.PolicyRule_RULE_TYPE_UNSPECIFIED
	}
}

func commandTypeToProto(t string) xdrv1.Command_CommandType {
	switch t {
	case "QUARANTINE":
		return xdrv1.Command_COMMAND_TYPE_QUARANTINE
	case "UNQUARANTINE":
		return xdrv1.Command_COMMAND_TYPE_UNQUARANTINE
	case "RUN_SIGNED_SCRIPT":
		return xdrv1.Command_COMMAND_TYPE_RUN_SIGNED_SCRIPT
	case "UNINSTALL":
		return xdrv1.Command_COMMAND_TYPE_UNINSTALL
	case "COLLECT_DIAGNOSTICS":
		return xdrv1.Command_COMMAND_TYPE_COLLECT_DIAGNOSTICS
	default:
		return xdrv1.Command_COMMAND_TYPE_UNSPECIFIED
	}
}
