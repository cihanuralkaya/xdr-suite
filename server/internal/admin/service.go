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

// Store, admin işlemlerinin ihtiyaç duyduğu kalıcılıktır.
type Store interface {
	AdminRole(ctx context.Context, adminID string) (Role, error)
	SaveEnrollmentToken(ctx context.Context, tokenIndex []byte, createdBy string, expiresAt time.Time) error
	EnqueueCommand(ctx context.Context, deviceID, cmdType, issuedBy string) error
	RevokeDeviceCerts(ctx context.Context, deviceID, reason string) error
	WriteAudit(ctx context.Context, adminID, action, targetType, targetID string) error
	CreatePolicy(ctx context.Context, name, version string) (policyID string, err error)
	AssignPolicy(ctx context.Context, deviceID, policyID string) error
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

// QuarantineDevice, cihazı karantinaya alma komutu kuyruğa ekler (OPERATOR+).
func (s *Service) QuarantineDevice(ctx context.Context, adminID, deviceID string) error {
	return s.command(ctx, adminID, deviceID, "QUARANTINE")
}

// ReleaseDevice, karantinayı kaldırma komutu kuyruğa ekler (OPERATOR+).
func (s *Service) ReleaseDevice(ctx context.Context, adminID, deviceID string) error {
	return s.command(ctx, adminID, deviceID, "UNQUARANTINE")
}

func (s *Service) command(ctx context.Context, adminID, deviceID, cmdType string) error {
	if err := s.require(ctx, adminID, RoleOperator); err != nil {
		return err
	}
	if err := s.store.EnqueueCommand(ctx, deviceID, cmdType, adminID); err != nil {
		return err
	}
	_ = s.store.WriteAudit(ctx, adminID, cmdType, "device", deviceID)
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

// defaultGenToken, 20 baytlık rastgele, okunabilir (base32) bir token üretir.
func defaultGenToken() (string, error) {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b), nil
}
