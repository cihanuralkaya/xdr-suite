package admin

import (
	"context"
	"crypto/rand"
	"testing"
	"time"

	"xdr.corp/suite/server/internal/security"
)

// memStore, admin testleri için bellek-içi Store.
type memStore struct {
	roles     map[string]Role
	tokens    map[string]string // tokenIndex(hex) -> createdBy
	commands  []cmd
	audits    []audit
	policies  map[string]string      // id -> name
	versions  map[string]string      // id -> version
	rules     map[string][]RuleInput // id -> kurallar
	assigned  map[string]string      // deviceID -> policyID
	nextPolID int
}

type cmd struct{ deviceID, cmdType, issuedBy string }
type audit struct{ adminID, action, targetType, targetID string }

func newMemStore() *memStore {
	return &memStore{
		roles:    map[string]Role{},
		tokens:   map[string]string{},
		policies: map[string]string{},
		versions: map[string]string{},
		rules:    map[string][]RuleInput{},
		assigned: map[string]string{},
	}
}

// fakePublisher, Publish çağrılarını kaydeder (anlık push doğrulaması için).
type fakePublisher struct{ published []string }

func (p *fakePublisher) Publish(deviceID string) { p.published = append(p.published, deviceID) }

func (m *memStore) AdminRole(_ context.Context, adminID string) (Role, error) {
	return m.roles[adminID], nil
}
func (m *memStore) SaveEnrollmentToken(_ context.Context, idx []byte, createdBy string, _ time.Time) error {
	m.tokens[string(idx)] = createdBy
	return nil
}
func (m *memStore) EnqueueCommand(_ context.Context, deviceID, cmdType, issuedBy string) error {
	m.commands = append(m.commands, cmd{deviceID, cmdType, issuedBy})
	return nil
}
func (m *memStore) RevokeDeviceCerts(_ context.Context, deviceID, _ string) error {
	m.commands = append(m.commands, cmd{deviceID, "REVOKE", ""})
	return nil
}
func (m *memStore) WriteAudit(_ context.Context, adminID, action, targetType, targetID string) error {
	m.audits = append(m.audits, audit{adminID, action, targetType, targetID})
	return nil
}
func (m *memStore) CreatePolicy(_ context.Context, name, version string) (string, error) {
	m.nextPolID++
	id := "pol-" + string(rune('0'+m.nextPolID))
	m.policies[id] = name
	m.versions[id] = version
	return id, nil
}
func (m *memStore) AssignPolicy(_ context.Context, deviceID, policyID string) error {
	m.assigned[deviceID] = policyID
	return nil
}
func (m *memStore) AddPolicyRule(_ context.Context, policyID string, in RuleInput) error {
	m.rules[policyID] = append(m.rules[policyID], in)
	return nil
}
func (m *memStore) BumpPolicyVersion(_ context.Context, policyID string) (string, error) {
	nv := m.versions[policyID] + "+1"
	m.versions[policyID] = nv
	return nv, nil
}
func (m *memStore) DevicesForPolicy(_ context.Context, policyID string) ([]string, error) {
	var out []string
	for dev, pol := range m.assigned {
		if pol == policyID {
			out = append(out, dev)
		}
	}
	return out, nil
}
func (m *memStore) ListPolicyRules(_ context.Context, policyID string) ([]RuleView, error) {
	var out []RuleView
	for i, r := range m.rules[policyID] {
		out = append(out, RuleView{
			ID: "r-" + string(rune('0'+i)), Type: r.Type, Target: r.Target,
			Start: r.Start, End: r.End, ActiveDays: r.ActiveDays,
		})
	}
	return out, nil
}

func newService(t *testing.T, store Store) (*Service, *security.BlindIndexer) {
	t.Helper()
	master := make([]byte, 32)
	if _, err := rand.Read(master); err != nil {
		t.Fatal(err)
	}
	bidx := security.NewBlindIndexer(security.DeriveKey(master, security.LabelBlindIndex))
	return NewService(store, bidx, time.Hour), bidx
}

func TestRBACQuarantineRequiresOperator(t *testing.T) {
	store := newMemStore()
	store.roles["viewer1"] = RoleViewer
	store.roles["op1"] = RoleOperator
	svc, _ := newService(t, store)

	// VIEWER reddedilmeli.
	if err := svc.QuarantineDevice(context.Background(), "viewer1", "dev-1"); err != ErrForbidden {
		t.Fatalf("VIEWER karantina yapamamalı, dönen: %v", err)
	}
	if len(store.commands) != 0 {
		t.Fatal("reddedilen işlem komut üretmemeli")
	}

	// OPERATOR başarılı olmalı ve komut + audit üretmeli.
	if err := svc.QuarantineDevice(context.Background(), "op1", "dev-1"); err != nil {
		t.Fatal(err)
	}
	if len(store.commands) != 1 || store.commands[0].cmdType != "QUARANTINE" || store.commands[0].deviceID != "dev-1" {
		t.Fatalf("QUARANTINE komutu kuyruğa eklenmeliydi: %+v", store.commands)
	}
	if len(store.audits) != 1 || store.audits[0].action != "QUARANTINE" {
		t.Fatalf("denetim izi yazılmalıydı: %+v", store.audits)
	}
}

func TestCreatePolicyRequiresAdmin(t *testing.T) {
	store := newMemStore()
	store.roles["op1"] = RoleOperator
	store.roles["admin1"] = RoleAdmin
	svc, _ := newService(t, store)

	if _, err := svc.CreatePolicy(context.Background(), "op1", "P", "v1"); err != ErrForbidden {
		t.Fatalf("OPERATOR politika oluşturamamalı, dönen: %v", err)
	}
	id, err := svc.CreatePolicy(context.Background(), "admin1", "Mesai Politikası", "v1")
	if err != nil || id == "" {
		t.Fatalf("ADMIN politika oluşturabilmeli: %v", err)
	}
}

func TestAddPolicyRuleRBACAndPush(t *testing.T) {
	store := newMemStore()
	store.roles["op1"] = RoleOperator
	store.roles["admin1"] = RoleAdmin
	svc, _ := newService(t, store)
	pub := &fakePublisher{}
	svc.SetPublisher(pub)

	// Bir politika oluştur ve iki cihaza ata.
	id, err := store.CreatePolicy(context.Background(), "Mesai", "v1")
	if err != nil {
		t.Fatal(err)
	}
	store.assigned["dev-1"] = id
	store.assigned["dev-2"] = id
	store.assigned["dev-other"] = "başka-politika"

	// OPERATOR kural ekleyememeli (403).
	if err := svc.AddPolicyRule(context.Background(), "op1", id,
		RuleInput{Type: "APP_BLOCK_ALWAYS", Target: "oyun.exe"}); err != ErrForbidden {
		t.Fatalf("OPERATOR kural ekleyememeli, dönen: %v", err)
	}
	if len(store.rules[id]) != 0 {
		t.Fatal("reddedilen işlem kural eklememeli")
	}

	// APP_TIME_BLOCK'ta Start/End yoksa geçersiz kural hatası.
	if err := svc.AddPolicyRule(context.Background(), "admin1", id,
		RuleInput{Type: "APP_TIME_BLOCK", Target: "oyun.exe"}); err != ErrInvalidRule {
		t.Fatalf("zaman aralığı olmadan APP_TIME_BLOCK reddedilmeli, dönen: %v", err)
	}

	// Geçersiz tip reddedilmeli.
	if err := svc.AddPolicyRule(context.Background(), "admin1", id,
		RuleInput{Type: "BOGUS", Target: "x"}); err != ErrInvalidRule {
		t.Fatalf("geçersiz tip reddedilmeli, dönen: %v", err)
	}

	// ADMIN geçerli kural ekleyebilmeli.
	verBefore := store.versions[id]
	if err := svc.AddPolicyRule(context.Background(), "admin1", id,
		RuleInput{Type: "APP_TIME_BLOCK", Target: "oyun.exe", Start: "09:00", End: "18:00", ActiveDays: []int32{1, 2, 3, 4, 5}}); err != nil {
		t.Fatalf("ADMIN kural ekleyebilmeli: %v", err)
	}
	if len(store.rules[id]) != 1 {
		t.Fatalf("kural eklenmiş olmalı: %+v", store.rules[id])
	}
	// Sürüm yükseltilmeli.
	if store.versions[id] == verBefore {
		t.Fatalf("politika sürümü yükseltilmeliydi (önce=%q, sonra=%q)", verBefore, store.versions[id])
	}
	// Yalnız bu politikaya atanmış cihazlar push almalı (dev-1, dev-2; dev-other DEĞİL).
	if len(pub.published) != 2 {
		t.Fatalf("atanmış 2 cihaz push almalıydı: %v", pub.published)
	}
	for _, d := range pub.published {
		if d != "dev-1" && d != "dev-2" {
			t.Fatalf("beklenmeyen cihaz push aldı: %q", d)
		}
	}
	// Audit yazılmalı.
	var found bool
	for _, a := range store.audits {
		if a.action == "ADD_POLICY_RULE" && a.targetType == "policy" && a.targetID == id {
			found = true
		}
	}
	if !found {
		t.Fatalf("ADD_POLICY_RULE denetim izi yazılmalıydı: %+v", store.audits)
	}
}

func TestIssueEnrollmentTokenStoresHMACIndex(t *testing.T) {
	store := newMemStore()
	store.roles["op1"] = RoleOperator
	svc, bidx := newService(t, store)

	token, err := svc.IssueEnrollmentToken(context.Background(), "op1")
	if err != nil {
		t.Fatal(err)
	}
	if token == "" {
		t.Fatal("ham token dönmeliydi")
	}
	// DB'de saklanan indeks, ham token'ın HMAC'i olmalı (ham token DEĞİL).
	wantIdx := string(bidx.Compute("enroll-token:" + token))
	if _, ok := store.tokens[wantIdx]; !ok {
		t.Fatal("token HMAC indeksi saklanmadı (ham token asla saklanmamalı)")
	}
	if len(store.audits) != 1 || store.audits[0].action != "ISSUE_ENROLLMENT_TOKEN" {
		t.Fatal("token üretimi denetim izine yazılmalıydı")
	}
}

// Bu token, enroll servisinin ConsumeEnrollmentToken'ıyla uyumlu indeks üretir:
// aynı "enroll-token:" ön eki ve aynı blind index anahtarı kullanılır.
func TestTokenIndexPrefixMatchesEnrollFlow(t *testing.T) {
	store := newMemStore()
	store.roles["op1"] = RoleOperator
	svc, bidx := newService(t, store)
	token, _ := svc.IssueEnrollmentToken(context.Background(), "op1")
	// enroll tarafı da tokenIndex = bidx.Compute("enroll-token:"+token) hesaplar.
	if _, ok := store.tokens[string(bidx.Compute("enroll-token:"+token))]; !ok {
		t.Fatal("admin ve enroll aynı indeks şemasını kullanmalı")
	}
}
