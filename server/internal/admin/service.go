// Package admin, yönetici işlemlerinin iş mantığıdır: RBAC ile korunmuş
// enrollment token üretimi, karantina komutu verme ve politika yönetimi.
// Her hassas işlem denetim izine (audit_log) yazılır (#10).
//
// Transport'tan (HTTP/gRPC) ve DB'den bağımsızdır: depolama Store arayüzünün
// arkasındadır ve gerçek bir veritabanı olmadan test edilebilir.
package admin

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"errors"
	"time"

	"xdr.corp/suite/server/internal/security"
)

// Role, yönetici yetki seviyesidir.
type Role string

const (
	RoleViewer   Role = "VIEWER"
	RoleOperator Role = "OPERATOR"
	RoleAdmin    Role = "ADMIN"
)

func rank(r Role) int {
	switch r {
	case RoleViewer:
		return 1
	case RoleOperator:
		return 2
	case RoleAdmin:
		return 3
	default:
		return 0
	}
}

// ErrForbidden, çağıran yöneticinin yetkisi yetersiz olduğunda döner.
var ErrForbidden = errors.New("admin: yetki yetersiz")

// ErrInvalidRule, kural girdisi doğrulamayı geçemediğinde döner (istemci hatası).
var ErrInvalidRule = errors.New("admin: geçersiz kural")

// RuleInput, bir politikaya eklenecek kuralın girdisidir.
type RuleInput struct {
	Type       string  // APP_TIME_BLOCK | APP_BLOCK_ALWAYS | NETWORK_RULE
	Target     string  // hedef (uygulama adı / ağ hedefi)
	Start      string  // "HH:MM" (APP_TIME_BLOCK için zorunlu; aksi halde boş)
	End        string  // "HH:MM"
	ActiveDays []int32 // 0=Pazar .. 6=Cumartesi (boşsa depoda varsayılan uygulanır)
}

// RuleView, bir politika kuralının okunabilir görünümüdür.
type RuleView struct {
	ID         string  `json:"id"`
	Type       string  `json:"type"`
	Target     string  `json:"target"`
	Start      string  `json:"start"`
	End        string  `json:"end"`
	ActiveDays []int32 `json:"active_days"`
}

// Store, admin işlemlerinin ihtiyaç duyduğu kalıcılıktır.
type Store interface {
	AdminRole(ctx context.Context, adminID string) (Role, error)
	SaveEnrollmentToken(ctx context.Context, tokenIndex []byte, createdBy string, expiresAt time.Time) error
	// RevokeEnrollmentToken, kullanılmamış bir enrollment token'ı iptal eder
	// (used_at damgalar). Zaten kullanılmış/yok token için sessizdir (no-op).
	RevokeEnrollmentToken(ctx context.Context, tokenID string) error
	EnqueueCommand(ctx context.Context, deviceID, cmdType, issuedBy string) error
	// SetDeviceStatus, cihazın durum sütununu doğrudan ayarlar (komut kuyruğa
	// girdikten sonra durumun UI'da yansıması için).
	SetDeviceStatus(ctx context.Context, deviceID, status string) error
	RevokeDeviceCerts(ctx context.Context, deviceID, reason string) error
	// EraseDeviceData, KVKK veri silme talebi için cihazın davranışsal/telemetri
	// verisini (olay logları, komut geçmişi) siler ve sertifikalarını iptal eder
	// (kalıcı erişim engeli). Denetim izi KORUNUR (işleme kaydı). Silinen olay/komut
	// ve iptal edilen sertifika sayısını döner.
	EraseDeviceData(ctx context.Context, deviceID string) (events, commands, certs int, err error)
	WriteAudit(ctx context.Context, adminID, action, targetType, targetID string) error
	CreatePolicy(ctx context.Context, name, version string) (policyID string, err error)
	AssignPolicy(ctx context.Context, deviceID, policyID string) error
	// AddPolicyRule, politikaya yeni bir kural ekler.
	AddPolicyRule(ctx context.Context, policyID string, in RuleInput) error
	// BumpPolicyVersion, politikanın sürümünü yükseltir ve yeni sürümü döner.
	BumpPolicyVersion(ctx context.Context, policyID string) (newVersion string, err error)
	// DevicesForPolicy, politikaya atanmış cihaz id'lerini döner (republish için).
	DevicesForPolicy(ctx context.Context, policyID string) ([]string, error)
	// ListPolicyRules, politikanın kurallarını döner.
	ListPolicyRules(ctx context.Context, policyID string) ([]RuleView, error)
	// CreateAdmin, yeni bir yönetici ekler ve id'sini döner. passwordHash zaten
	// Argon2id ile hash'lenmiştir (depo düz metin görmez).
	CreateAdmin(ctx context.Context, email, passwordHash string, role Role) (string, error)
	// SetAdminRole, bir yöneticinin rolünü değiştirir.
	SetAdminRole(ctx context.Context, id string, role Role) error
	// DeactivateAdmin, bir yöneticiyi pasifleştirir (is_active=false).
	DeactivateAdmin(ctx context.Context, id string) error
	// ListAdmins, tüm yöneticileri döner (parola hash'i olmadan).
	ListAdmins(ctx context.Context) ([]AdminInfo, error)
}

// validRuleType, kabul edilen kural tiplerini doğrular.
func validRuleType(t string) bool {
	switch t {
	case "APP_TIME_BLOCK", "APP_BLOCK_ALWAYS", "NETWORK_RULE":
		return true
	default:
		return false
	}
}

// Publisher, bir cihaza politika atandığında anlık push tetiklemek için
// kullanılır (opsiyonel; nil ise push tetiklenmez).
type Publisher interface {
	Publish(deviceID string)
}

// Service, admin işlemlerini yürütür.
type Service struct {
	store    Store
	bidx     *security.BlindIndexer
	tokenTTL time.Duration
	now      func() time.Time
	genToken func() (string, error)
	pub      Publisher
}

// NewService oluşturur.
func NewService(store Store, bidx *security.BlindIndexer, tokenTTL time.Duration) *Service {
	return &Service{
		store:    store,
		bidx:     bidx,
		tokenTTL: tokenTTL,
		now:      time.Now,
		genToken: defaultGenToken,
	}
}

// SetPublisher, politika atamalarında anlık push için bir yayıncı bağlar.
func (s *Service) SetPublisher(p Publisher) { s.pub = p }

// require, adminID'nin en az min yetkiye sahip olduğunu doğrular.
func (s *Service) require(ctx context.Context, adminID string, min Role) error {
	role, err := s.store.AdminRole(ctx, adminID)
	if err != nil {
		return err
	}
	if rank(role) < rank(min) {
		return ErrForbidden
	}
	return nil
}

// IssueEnrollmentToken, tek kullanımlık bir kayıt token'ı üretir (OPERATOR+).
// Ham token YALNIZ burada döner (bir kez gösterilir); DB'de HMAC indeksi saklanır.
func (s *Service) IssueEnrollmentToken(ctx context.Context, adminID string) (string, error) {
	if err := s.require(ctx, adminID, RoleOperator); err != nil {
		return "", err
	}
	token, err := s.genToken()
	if err != nil {
		return "", err
	}
	idx := s.bidx.Compute("enroll-token:" + token)
	if err := s.store.SaveEnrollmentToken(ctx, idx, adminID, s.now().Add(s.tokenTTL)); err != nil {
		return "", err
	}
	_ = s.store.WriteAudit(ctx, adminID, "ISSUE_ENROLLMENT_TOKEN", "device", "")
	return token, nil
}

// QuarantineDevice, cihazı karantinaya alma komutu kuyruğa ekler (OPERATOR+) ve
// durum sütununu QUARANTINED olarak yansıtır.
// RevokeEnrollmentToken, henüz kullanılmamış bir enrollment token'ı iptal eder
// (OPERATOR+). İptal edilen token bir sonraki kayıt denemesinde reddedilir.
func (s *Service) RevokeEnrollmentToken(ctx context.Context, adminID, tokenID string) error {
	if err := s.require(ctx, adminID, RoleOperator); err != nil {
		return err
	}
	if err := s.store.RevokeEnrollmentToken(ctx, tokenID); err != nil {
		return err
	}
	_ = s.store.WriteAudit(ctx, adminID, "REVOKE_ENROLLMENT_TOKEN", "token", tokenID)
	return nil
}

// QuarantineDevice, cihazı karantinaya alma komutu kuyruğa ekler (OPERATOR+).
func (s *Service) QuarantineDevice(ctx context.Context, adminID, deviceID string) error {
	return s.command(ctx, adminID, deviceID, "QUARANTINE", "QUARANTINED")
}

// ReleaseDevice, karantinayı kaldırma komutu kuyruğa ekler (OPERATOR+) ve durum
// sütununu ACTIVE olarak geri yansıtır.
func (s *Service) ReleaseDevice(ctx context.Context, adminID, deviceID string) error {
	return s.command(ctx, adminID, deviceID, "UNQUARANTINE", "ACTIVE")
}

// CollectDiagnostics, cihazdan tanılama toplama komutu kuyruğa ekler (OPERATOR+).
// Durum değiştirmez — zararsız, salt-toplama bir işlemdir.
func (s *Service) CollectDiagnostics(ctx context.Context, adminID, deviceID string) error {
	return s.command(ctx, adminID, deviceID, "COLLECT_DIAGNOSTICS", "")
}

// command, RBAC kontrolü sonrası komutu kuyruğa ekler, denetim izine yazar ve
// (reflectStatus boş değilse) cihazın durum sütununu günceller. Durum güncelleme
// hatası akışı BOZMAZ: komut zaten kuyruğa girmiştir; hata yutulur (best-effort
// yansıma), çünkü asıl doğruluk kaynağı komut kuyruğudur.
func (s *Service) command(ctx context.Context, adminID, deviceID, cmdType, reflectStatus string) error {
	if err := s.require(ctx, adminID, RoleOperator); err != nil {
		return err
	}
	if err := s.store.EnqueueCommand(ctx, deviceID, cmdType, adminID); err != nil {
		return err
	}
	_ = s.store.WriteAudit(ctx, adminID, cmdType, "device", deviceID)
	if reflectStatus != "" {
		// Best-effort: komut kuyruğa girdiği için hata olsa da akışı bozma.
		_ = s.store.SetDeviceStatus(ctx, deviceID, reflectStatus)
	}
	return nil
}

// ErasureReport, bir KVKK veri silme işleminin sonucudur.
type ErasureReport struct {
	EventsDeleted   int `json:"events_deleted"`
	CommandsDeleted int `json:"commands_deleted"`
	CertsRevoked    int `json:"certs_revoked"`
}

// EraseDevice, KVKK veri sahibi SİLME talebini uygular (ADMIN). Cihazın
// davranışsal/telemetri verisini siler ve sertifikalarını iptal eder; işlemin
// kendisi denetim izine ("DATA_ERASURE") yazılır (silme kaydı korunur).
func (s *Service) EraseDevice(ctx context.Context, adminID, deviceID string) (ErasureReport, error) {
	if err := s.require(ctx, adminID, RoleAdmin); err != nil {
		return ErasureReport{}, err
	}
	ev, cmd, cert, err := s.store.EraseDeviceData(ctx, deviceID)
	if err != nil {
		return ErasureReport{}, err
	}
	_ = s.store.WriteAudit(ctx, adminID, "DATA_ERASURE", "device", deviceID)
	return ErasureReport{EventsDeleted: ev, CommandsDeleted: cmd, CertsRevoked: cert}, nil
}

// AuthorizeExport, KVKK veri sahibi ERİŞİM (dışa aktarma) talebini yetkilendirir
// (ADMIN) ve denetim izine ("DATA_EXPORT") yazar. Asıl veri toplama okuma
// servisinde yapılır; bu yalnız RBAC + denetim kapısıdır.
func (s *Service) AuthorizeExport(ctx context.Context, adminID, deviceID string) error {
	if err := s.require(ctx, adminID, RoleAdmin); err != nil {
		return err
	}
	_ = s.store.WriteAudit(ctx, adminID, "DATA_EXPORT", "device", deviceID)
	return nil
}

// RevokeDevice, cihazın sertifikalarını iptal eder (OPERATOR+). İptal edilen
// ajan bir sonraki mTLS el sıkışmasında reddedilir.
func (s *Service) RevokeDevice(ctx context.Context, adminID, deviceID string) error {
	if err := s.require(ctx, adminID, RoleOperator); err != nil {
		return err
	}
	if err := s.store.RevokeDeviceCerts(ctx, deviceID, "admin_revoke"); err != nil {
		return err
	}
	_ = s.store.WriteAudit(ctx, adminID, "REVOKE_CERT", "device", deviceID)
	return nil
}

// CreatePolicy, yeni bir politika oluşturur (ADMIN).
func (s *Service) CreatePolicy(ctx context.Context, adminID, name, version string) (string, error) {
	if err := s.require(ctx, adminID, RoleAdmin); err != nil {
		return "", err
	}
	id, err := s.store.CreatePolicy(ctx, name, version)
	if err != nil {
		return "", err
	}
	_ = s.store.WriteAudit(ctx, adminID, "CREATE_POLICY", "policy", id)
	return id, nil
}

// AssignPolicy, bir politikayı cihaza atar (ADMIN).
func (s *Service) AssignPolicy(ctx context.Context, adminID, deviceID, policyID string) error {
	if err := s.require(ctx, adminID, RoleAdmin); err != nil {
		return err
	}
	if err := s.store.AssignPolicy(ctx, deviceID, policyID); err != nil {
		return err
	}
	_ = s.store.WriteAudit(ctx, adminID, "ASSIGN_POLICY", "device", deviceID)
	// Cihazın açık politika akışını uyandır (anlık push).
	if s.pub != nil {
		s.pub.Publish(deviceID)
	}
	return nil
}

// AddPolicyRule, bir politikaya yeni bir kural ekler (ADMIN). Kuralı ekler,
// politikanın sürümünü yükseltir, denetim izine yazar ve politikaya atanmış her
// cihaza anlık push tetikler (açık StreamPolicies akışını uyandırır).
func (s *Service) AddPolicyRule(ctx context.Context, adminID, policyID string, in RuleInput) error {
	if err := s.require(ctx, adminID, RoleAdmin); err != nil {
		return err
	}
	// Doğrulama: tip geçerli olmalı; APP_TIME_BLOCK ise Start ve End zorunlu.
	if !validRuleType(in.Type) {
		return ErrInvalidRule
	}
	if in.Type == "APP_TIME_BLOCK" && (in.Start == "" || in.End == "") {
		return ErrInvalidRule
	}
	if err := s.store.AddPolicyRule(ctx, policyID, in); err != nil {
		return err
	}
	// Kural değişti; ajanların yeni paketi çekmesi için sürümü yükselt.
	if _, err := s.store.BumpPolicyVersion(ctx, policyID); err != nil {
		return err
	}
	_ = s.store.WriteAudit(ctx, adminID, "ADD_POLICY_RULE", "policy", policyID)
	// Politikaya atanmış her cihazın açık akışını uyandır (anlık push).
	if s.pub != nil {
		devices, err := s.store.DevicesForPolicy(ctx, policyID)
		if err != nil {
			return err
		}
		for _, deviceID := range devices {
			s.pub.Publish(deviceID)
		}
	}
	return nil
}

// ListPolicyRules, bir politikanın kurallarını döner (OPERATOR+).
func (s *Service) ListPolicyRules(ctx context.Context, adminID, policyID string) ([]RuleView, error) {
	if err := s.require(ctx, adminID, RoleOperator); err != nil {
		return nil, err
	}
	return s.store.ListPolicyRules(ctx, policyID)
}

// defaultGenToken, 20 baytlık rastgele, okunabilir (base32) bir token üretir.
func defaultGenToken() (string, error) {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b), nil
}
