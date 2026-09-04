package adminapi

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"xdr.corp/suite/server/internal/admin"
	"xdr.corp/suite/server/internal/adminread"
	"xdr.corp/suite/server/internal/eventbus"
	"xdr.corp/suite/server/internal/security"
)

// memStore, hem admin.Store hem adminapi.AuthStore'u karşılar.
type memStore struct {
	roles      map[string]admin.Role
	emails     map[string]adminRec // email -> (id, hash)
	commands   []string            // "deviceID:type"
	cipher     *security.FieldCipher
	devRows    []adminread.DeviceRow
	evtRows    []adminread.EventRow
	auditRows  []adminread.AuditRow
	certRows   []adminread.CertRow
	cmdRows    []adminread.CmdRow
	tokenRows  []adminread.EnrollmentTokenRow
	tokenSeq   int
	polID      string
	polVer     string
	rules      map[string][]admin.RuleInput // policyID -> kurallar
	assigned   map[string]string            // deviceID -> policyID
	statuses   map[string]string            // deviceID -> son ayarlanan durum
	adminInfos map[string]*admin.AdminInfo  // id -> yönetici görünümü
	nextAdmID  int
	mfa        map[string]*mfaRec // adminID -> MFA durumu
}

type adminRec struct{ id, hash string }

type mfaRec struct {
	secret   string
	enrolled bool
}

func newMemStore() *memStore {
	return &memStore{
		roles:      map[string]admin.Role{},
		emails:     map[string]adminRec{},
		rules:      map[string][]admin.RuleInput{},
		assigned:   map[string]string{},
		adminInfos: map[string]*admin.AdminInfo{},
	}
}

// admin.Store
func (m *memStore) AdminRole(_ context.Context, id string) (admin.Role, error) {
	return m.roles[id], nil
}
func (m *memStore) SaveEnrollmentToken(_ context.Context, _ []byte, createdBy string, expiresAt time.Time) error {
	m.tokenSeq++
	// createdBy admin id'sini e-postaya çöz (db LEFT JOIN davranışını taklit et).
	var email string
	for e, r := range m.emails {
		if r.id == createdBy {
			email = e
			break
		}
	}
	m.tokenRows = append([]adminread.EnrollmentTokenRow{{
		ID: "etok-" + strconv.Itoa(m.tokenSeq), CreatedByEmail: email,
		ExpiresAt: expiresAt, Used: false, CreatedAt: time.Now(),
	}}, m.tokenRows...)
	return nil
}
func (m *memStore) RevokeEnrollmentToken(_ context.Context, tokenID string) error {
	for i := range m.tokenRows {
		if m.tokenRows[i].ID == tokenID && !m.tokenRows[i].Used {
			m.tokenRows[i].Used = true
			break
		}
	}
	return nil
}
func (m *memStore) ListEnrollmentTokens(_ context.Context, _ int) ([]adminread.EnrollmentTokenRow, error) {
	return m.tokenRows, nil
}

func (m *memStore) ListPolicies(_ context.Context, _ int) ([]adminread.PolicyRow, error) {
	counts := map[string]int{}
	for _, pid := range m.assigned {
		counts[pid]++
	}
	var out []adminread.PolicyRow
	for id, rules := range m.rules {
		ver := ""
		if id == m.polID {
			ver = m.polVer
		}
		out = append(out, adminread.PolicyRow{
			ID: id, Name: id, Version: ver,
			RuleCount: len(rules), DeviceCount: counts[id],
		})
	}
	return out, nil
}
func (m *memStore) EnqueueCommand(_ context.Context, deviceID, cmdType, _ string) error {
	m.commands = append(m.commands, deviceID+":"+cmdType)
	return nil
}
func (m *memStore) SetDeviceStatus(_ context.Context, deviceID, status string) error {
	if m.statuses == nil {
		m.statuses = map[string]string{}
	}
	m.statuses[deviceID] = status
	return nil
}
func (m *memStore) SetDeviceTags(_ context.Context, deviceID string, tags []string) error {
	for i := range m.devRows {
		if m.devRows[i].ID == deviceID {
			m.devRows[i].Tags = tags
		}
	}
	return nil
}
func (m *memStore) RevokeDeviceCerts(_ context.Context, deviceID, _ string) error {
	m.commands = append(m.commands, deviceID+":REVOKE")
	return nil
}
func (m *memStore) EraseDeviceData(_ context.Context, deviceID string) (int, int, int, error) {
	m.commands = append(m.commands, deviceID+":ERASE")
	// Bu cihaza ait olayları temizle (device-scoped alan yoksa tümünü temsilen).
	n := len(m.evtRows)
	m.evtRows = nil
	return n, 0, 1, nil
}
func (m *memStore) WriteAudit(_ context.Context, adminID, action, targetType, targetID string) error {
	m.auditRows = append([]adminread.AuditRow{{
		ID: int64(len(m.auditRows) + 1), AdminEmail: adminID, Action: action,
		TargetType: targetType, TargetID: targetID, CreatedAt: time.Now(),
	}}, m.auditRows...)
	return nil
}
func (m *memStore) CreatePolicy(_ context.Context, _, _ string) (string, error) {
	return "pol-1", nil
}
func (m *memStore) AssignPolicy(_ context.Context, deviceID, policyID string) error {
	m.assigned[deviceID] = policyID
	return nil
}
func (m *memStore) AddPolicyRule(_ context.Context, policyID string, in admin.RuleInput) error {
	m.rules[policyID] = append(m.rules[policyID], in)
	return nil
}
func (m *memStore) BumpPolicyVersion(_ context.Context, _ string) (string, error) {
	return "v2", nil
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
func (m *memStore) ListPolicyRules(_ context.Context, policyID string) ([]admin.RuleView, error) {
	var out []admin.RuleView
	for i, r := range m.rules[policyID] {
		out = append(out, admin.RuleView{
			ID: "r-" + string(rune('0'+i)), Type: r.Type, Target: r.Target,
			Start: r.Start, End: r.End, ActiveDays: r.ActiveDays,
		})
	}
	return out, nil
}

func (m *memStore) CreateAdmin(_ context.Context, email, passwordHash string, role admin.Role) (string, error) {
	m.nextAdmID++
	id := "adm-" + string(rune('0'+m.nextAdmID))
	m.roles[id] = role
	m.emails[email] = adminRec{id: id, hash: passwordHash}
	m.adminInfos[id] = &admin.AdminInfo{ID: id, Email: email, Role: role, Active: true}
	return id, nil
}
func (m *memStore) SetAdminRole(_ context.Context, id string, role admin.Role) error {
	m.roles[id] = role
	if a, ok := m.adminInfos[id]; ok {
		a.Role = role
	}
	return nil
}
func (m *memStore) DeactivateAdmin(_ context.Context, id string) error {
	if a, ok := m.adminInfos[id]; ok {
		a.Active = false
	}
	// Gerçek db/memstore davranışı: pasif admin için AdminRole boş döner (WHERE
	// is_active). authed'in aktiflik teyidini (SEC-003) test edebilmek için taklit.
	delete(m.roles, id)
	return nil
}
func (m *memStore) ListAdmins(_ context.Context) ([]admin.AdminInfo, error) {
	var out []admin.AdminInfo
	for _, a := range m.adminInfos {
		out = append(out, *a)
	}
	return out, nil
}

// adminapi.AuthStore
func (m *memStore) LookupAdmin(_ context.Context, email string) (string, string, error) {
	r := m.emails[email]
	return r.id, r.hash, nil
}

// admin.Store + adminapi.MFAStore (MFA)
func (m *memStore) ensureMFA() {
	if m.mfa == nil {
		m.mfa = map[string]*mfaRec{}
	}
}
func (m *memStore) SetPendingMFASecret(_ context.Context, id, secret string) error {
	m.ensureMFA()
	m.mfa[id] = &mfaRec{secret: secret, enrolled: false}
	return nil
}
func (m *memStore) LookupMFA(_ context.Context, id string) (string, bool, error) {
	m.ensureMFA()
	if r, ok := m.mfa[id]; ok {
		return r.secret, r.enrolled, nil
	}
	return "", false, nil
}
func (m *memStore) ActivateMFA(_ context.Context, id string) error {
	m.ensureMFA()
	if r, ok := m.mfa[id]; ok && r.secret != "" {
		r.enrolled = true
	}
	return nil
}
func (m *memStore) DisableMFA(_ context.Context, id string) error {
	m.ensureMFA()
	delete(m.mfa, id)
	return nil
}

// adminread.Store
func (m *memStore) ListDevices(_ context.Context, _ int) ([]adminread.DeviceRow, error) {
	return m.devRows, nil
}
func (m *memStore) ListEvents(_ context.Context, deviceID, severity, category string, _ int) ([]adminread.EventRow, error) {
	var out []adminread.EventRow
	for _, e := range m.evtRows {
		if severity != "" && e.Severity != severity {
			continue
		}
		if category != "" && e.Category != category {
			continue
		}
		out = append(out, e)
	}
	return out, nil
}
func (m *memStore) DeviceStatusCounts(_ context.Context) (map[string]int, error) {
	out := map[string]int{}
	for _, d := range m.devRows {
		out[d.Status]++
	}
	return out, nil
}
func (m *memStore) EventSeverityCounts(_ context.Context, since time.Time) (map[string]int, error) {
	out := map[string]int{}
	for _, e := range m.evtRows {
		if e.CreatedAt.Before(since) {
			continue
		}
		out[e.Severity]++
	}
	return out, nil
}
func (m *memStore) EventCategoryCounts(_ context.Context, since time.Time) (map[string]int, error) {
	out := map[string]int{}
	for _, e := range m.evtRows {
		if e.CreatedAt.Before(since) {
			continue
		}
		out[e.Category]++
	}
	return out, nil
}
func (m *memStore) ListAudit(_ context.Context, _ int) ([]adminread.AuditRow, error) {
	return m.auditRows, nil
}
func (m *memStore) DeviceByID(_ context.Context, id string) (adminread.DeviceRow, bool, error) {
	for _, d := range m.devRows {
		if d.ID == id {
			return d, true, nil
		}
	}
	return adminread.DeviceRow{}, false, nil
}
func (m *memStore) CertsByDevice(_ context.Context, _ string) ([]adminread.CertRow, error) {
	return m.certRows, nil
}
func (m *memStore) CommandHistory(_ context.Context, _ string) ([]adminread.CmdRow, error) {
	return m.cmdRows, nil
}
func (m *memStore) AssignedPolicy(_ context.Context, _ string) (string, string, error) {
	return m.polID, m.polVer, nil
}

func newServer(t *testing.T) (*Server, *memStore) {
	t.Helper()
	store := newMemStore()

	master := make([]byte, 32)
	if _, err := rand.Read(master); err != nil {
		t.Fatal(err)
	}
	bidx := security.NewBlindIndexer(security.DeriveKey(master, security.LabelBlindIndex))
	sessions := security.NewSessionSigner(security.DeriveKey(master, security.LabelSessionToken))
	cipher, err := security.NewFieldCipher(security.DeriveKey(master, security.LabelFieldEncryption))
	if err != nil {
		t.Fatal(err)
	}
	store.cipher = cipher
	adminSvc := admin.NewService(store, bidx, time.Hour)
	reader := adminread.NewService(store, cipher)
	return New(adminSvc, reader, store, sessions, time.Hour), store
}

func setup(t *testing.T) (*httptest.Server, *memStore) {
	t.Helper()
	srv, store := newServer(t)
	return httptest.NewServer(srv.Handler()), store
}

func setupStream(t *testing.T) (*httptest.Server, *memStore, *eventbus.Bus) {
	t.Helper()
	srv, store := newServer(t)
	bus := eventbus.New()
	srv.SetStream(bus)
	return httptest.NewServer(srv.Handler()), store, bus
}

func addAdmin(t *testing.T, store *memStore, id, email, password string, role admin.Role) {
	t.Helper()
	hash, err := security.HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}
	store.roles[id] = role
	store.emails[email] = adminRec{id: id, hash: hash}
	store.adminInfos[id] = &admin.AdminInfo{ID: id, Email: email, Role: role, Active: true}
}

func post(t *testing.T, url, token string, body any) (int, map[string]string) {
	t.Helper()
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest("POST", url, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]string
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

// MFA (2FA) uçtan uca: kayıt → etkinleştir → sonraki girişlerde TOTP kodu zorunlu.
func TestLoginEnforcesMFAWhenEnrolled(t *testing.T) {
	ts, store := setup(t)
	defer ts.Close()
	addAdmin(t, store, "op1", "op@x", "secret", admin.RoleOperator)

	// İlk giriş (MFA yok) → token.
	_, body := post(t, ts.URL+"/api/login", "", map[string]string{"email": "op@x", "password": "secret"})
	token := body["token"]
	if token == "" {
		t.Fatal("ilk giriş token vermeliydi")
	}
	// MFA kaydını başlat → sır döner.
	code, eb := post(t, ts.URL+"/api/mfa/enroll", token, map[string]string{})
	if code != http.StatusOK || eb["secret"] == "" {
		t.Fatalf("mfa enroll başarısız: %d %v", code, eb)
	}
	secret := eb["secret"]
	// Doğru kod ile etkinleştir.
	otp, _ := security.TOTPAt(secret, time.Now())
	if c, _ := post(t, ts.URL+"/api/mfa/activate", token, map[string]string{"code": otp}); c != http.StatusOK {
		t.Fatalf("mfa activate başarısız: %d", c)
	}
	// Artık kodsuz giriş token VERMEMELİ (mfa_required).
	_, nb := post(t, ts.URL+"/api/login", "", map[string]string{"email": "op@x", "password": "secret"})
	if nb["token"] != "" {
		t.Fatal("MFA etkinken kodsuz giriş token vermemeliydi")
	}
	// Yanlış kod → 401.
	if c, _ := post(t, ts.URL+"/api/login", "", map[string]string{"email": "op@x", "password": "secret", "code": "000000"}); c != http.StatusUnauthorized {
		t.Fatalf("yanlış MFA kodu 401 dönmeliydi, %d", c)
	}
	// Doğru kod → token.
	otp2, _ := security.TOTPAt(secret, time.Now())
	_, okBody := post(t, ts.URL+"/api/login", "", map[string]string{"email": "op@x", "password": "secret", "code": otp2})
	if okBody["token"] == "" {
		t.Fatal("doğru MFA kodu ile giriş token vermeliydi")
	}
}

func TestLoginAndQuarantine(t *testing.T) {
	ts, store := setup(t)
	defer ts.Close()
	addAdmin(t, store, "op1", "op@x", "secret", admin.RoleOperator)

	// Yanlış parola → 401.
	if code, _ := post(t, ts.URL+"/api/login", "", map[string]string{"email": "op@x", "password": "yanlis"}); code != http.StatusUnauthorized {
		t.Fatalf("yanlış parola 401 dönmeliydi, %d", code)
	}

	// Doğru parola → token.
	code, body := post(t, ts.URL+"/api/login", "", map[string]string{"email": "op@x", "password": "secret"})
	if code != http.StatusOK || body["token"] == "" {
		t.Fatalf("login başarısız: code=%d body=%v", code, body)
	}
	token := body["token"]

	// Token'sız karantina → 401.
	if code, _ := post(t, ts.URL+"/api/devices/quarantine", "", map[string]string{"device_id": "dev-1"}); code != http.StatusUnauthorized {
		t.Fatalf("token'sız istek 401 dönmeliydi, %d", code)
	}

	// Token'lı karantina → 200 + komut kuyruğa eklenmeli.
	if code, _ := post(t, ts.URL+"/api/devices/quarantine", token, map[string]string{"device_id": "dev-1"}); code != http.StatusOK {
		t.Fatalf("yetkili karantina 200 dönmeliydi, %d", code)
	}
	if len(store.commands) != 1 || store.commands[0] != "dev-1:QUARANTINE" {
		t.Fatalf("QUARANTINE komutu kuyruğa eklenmeliydi: %v", store.commands)
	}
}

func TestServesConsole(t *testing.T) {
	ts, _ := setup(t)
	defer ts.Close()
	resp, err := http.Get(ts.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("konsol 200 dönmeliydi, %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Fatalf("konsol HTML olmalı, %q", ct)
	}
	buf := make([]byte, 1024)
	n, _ := resp.Body.Read(buf)
	if !strings.Contains(string(buf[:n]), "XDR Komuta Merkezi") {
		t.Fatal("konsol içeriği beklenen başlığı taşımıyor")
	}
}

func TestListDevicesDecrypted(t *testing.T) {
	ts, store := setup(t)
	defer ts.Close()
	addAdmin(t, store, "op1", "op@x", "secret", admin.RoleOperator)

	hostEnc, _ := store.cipher.EncryptString("WS-07")
	macEnc, _ := store.cipher.EncryptString("aa:bb:cc:dd:ee:ff")
	store.devRows = []adminread.DeviceRow{{ID: "dev-1", Status: "ACTIVE", HostnameEnc: hostEnc, MACEnc: macEnc}}

	_, body := post(t, ts.URL+"/api/login", "", map[string]string{"email": "op@x", "password": "secret"})
	token := body["token"]

	req, _ := http.NewRequest("GET", ts.URL+"/api/devices", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("200 beklenirdi, %d", resp.StatusCode)
	}
	var out struct {
		Devices []struct {
			Hostname string `json:"hostname"`
			MAC      string `json:"mac"`
			Status   string `json:"status"`
		} `json:"devices"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if len(out.Devices) != 1 || out.Devices[0].Hostname != "WS-07" || out.Devices[0].MAC != "aa:bb:cc:dd:ee:ff" {
		t.Fatalf("cihaz deşifre edilip listelenmişti olmalı: %+v", out.Devices)
	}

	// Token'sız erişim reddedilmeli.
	if r2, _ := http.Get(ts.URL + "/api/devices"); r2.StatusCode != http.StatusUnauthorized {
		t.Fatalf("token'sız liste 401 dönmeliydi, %d", r2.StatusCode)
	}
}

func TestRevokeRequiresOperator(t *testing.T) {
	ts, store := setup(t)
	defer ts.Close()
	addAdmin(t, store, "v1", "viewer@x", "secret", admin.RoleViewer)
	addAdmin(t, store, "op1", "op@x", "secret", admin.RoleOperator)

	_, vBody := post(t, ts.URL+"/api/login", "", map[string]string{"email": "viewer@x", "password": "secret"})
	if code, _ := post(t, ts.URL+"/api/devices/revoke", vBody["token"], map[string]string{"device_id": "d1"}); code != http.StatusForbidden {
		t.Fatalf("VIEWER iptal edememeli, %d", code)
	}
	_, opBody := post(t, ts.URL+"/api/login", "", map[string]string{"email": "op@x", "password": "secret"})
	if code, _ := post(t, ts.URL+"/api/devices/revoke", opBody["token"], map[string]string{"device_id": "d1"}); code != http.StatusOK {
		t.Fatalf("OPERATOR iptal edebilmeli, %d", code)
	}
	if !contains(store.commands, "d1:REVOKE") {
		t.Fatalf("iptal komutu store'a yansımalıydı: %v", store.commands)
	}
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

func TestSecurityHeaders(t *testing.T) {
	ts, _ := setup(t)
	defer ts.Close()
	resp, err := http.Get(ts.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Error("nosniff başlığı eksik")
	}
	if resp.Header.Get("X-Frame-Options") != "DENY" {
		t.Error("X-Frame-Options DENY eksik (clickjacking)")
	}
	if resp.Header.Get("Content-Security-Policy") == "" {
		t.Error("konsolda CSP eksik")
	}
}

func TestViewerForbidden(t *testing.T) {
	ts, store := setup(t)
	defer ts.Close()
	addAdmin(t, store, "v1", "viewer@x", "secret", admin.RoleViewer)

	_, body := post(t, ts.URL+"/api/login", "", map[string]string{"email": "viewer@x", "password": "secret"})
	token := body["token"]

	code, _ := post(t, ts.URL+"/api/devices/quarantine", token, map[string]string{"device_id": "dev-1"})
	if code != http.StatusForbidden {
		t.Fatalf("VIEWER karantina 403 dönmeliydi, %d", code)
	}
	if len(store.commands) != 0 {
		t.Fatal("reddedilen istek komut üretmemeli")
	}
}

func TestPolicyRuleEditorHTTP(t *testing.T) {
	ts, store := setup(t)
	defer ts.Close()
	addAdmin(t, store, "ad1", "admin@x", "secret", admin.RoleAdmin)

	_, adBody := post(t, ts.URL+"/api/login", "", map[string]string{"email": "admin@x", "password": "secret"})
	token := adBody["token"]

	// Politika oluştur.
	code, body := post(t, ts.URL+"/api/policies", token, map[string]string{"name": "Mesai", "version": "v1"})
	if code != http.StatusOK || body["policy_id"] == "" {
		t.Fatalf("politika oluşturulmalı: code=%d body=%v", code, body)
	}
	policyID := body["policy_id"]

	// Kural ekle.
	code, _ = post(t, ts.URL+"/api/policies/"+policyID+"/rules", token, map[string]any{
		"type": "APP_TIME_BLOCK", "target": "oyun.exe", "start": "09:00", "end": "18:00",
		"active_days": []int{1, 2, 3, 4, 5},
	})
	if code != http.StatusOK {
		t.Fatalf("kural eklenebilmeli, code=%d", code)
	}

	// Kuralları listele.
	req, _ := http.NewRequest("GET", ts.URL+"/api/policies/"+policyID+"/rules", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("kural listesi 200 dönmeliydi, %d", resp.StatusCode)
	}
	var out struct {
		Rules []struct {
			Type       string  `json:"type"`
			Target     string  `json:"target"`
			Start      string  `json:"start"`
			End        string  `json:"end"`
			ActiveDays []int32 `json:"active_days"`
		} `json:"rules"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if len(out.Rules) != 1 || out.Rules[0].Type != "APP_TIME_BLOCK" || out.Rules[0].Target != "oyun.exe" ||
		out.Rules[0].Start != "09:00" || out.Rules[0].End != "18:00" {
		t.Fatalf("eklenen kural listede dönmeliydi: %+v", out.Rules)
	}

	// Geçersiz kural (APP_TIME_BLOCK ama zaman aralığı yok) → 400.
	code, _ = post(t, ts.URL+"/api/policies/"+policyID+"/rules", token, map[string]any{
		"type": "APP_TIME_BLOCK", "target": "x",
	})
	if code != http.StatusBadRequest {
		t.Fatalf("geçersiz kural 400 dönmeliydi, %d", code)
	}
}

func TestAdminUserManagementHTTP(t *testing.T) {
	ts, store := setup(t)
	defer ts.Close()
	addAdmin(t, store, "ad1", "admin@x", "secret", admin.RoleAdmin)

	_, adBody := post(t, ts.URL+"/api/login", "", map[string]string{"email": "admin@x", "password": "secret"})
	token := adBody["token"]

	// Kısa parola → 400.
	if code, _ := post(t, ts.URL+"/api/admins", token, map[string]string{
		"email": "kisa@x", "password": "123", "role": "VIEWER",
	}); code != http.StatusBadRequest {
		t.Fatalf("kısa parola 400 dönmeliydi, %d", code)
	}

	// Yeni yönetici oluştur.
	code, body := post(t, ts.URL+"/api/admins", token, map[string]string{
		"email": "yeni@x", "password": "parola12", "role": "OPERATOR",
	})
	if code != http.StatusOK || body["admin_id"] == "" {
		t.Fatalf("yönetici oluşturulmalı: code=%d body=%v", code, body)
	}
	newID := body["admin_id"]

	// Listede yeni yönetici görünmeli (parola hash'i JSON'da OLMAMALI).
	resp, err := authedGET(t, ts.URL+"/api/admins", token)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("liste 200 dönmeliydi, %d", resp.StatusCode)
	}
	raw, _ := io.ReadAll(resp.Body)
	if bytes.Contains(bytes.ToLower(raw), []byte("hash")) || bytes.Contains(raw, []byte("password")) {
		t.Fatalf("yönetici listesi parola hash'i sızdırmamalı: %s", raw)
	}
	var out struct {
		Admins []struct {
			ID     string `json:"id"`
			Email  string `json:"email"`
			Role   string `json:"role"`
			Active bool   `json:"active"`
		} `json:"admins"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, a := range out.Admins {
		if a.ID == newID {
			found = true
			if a.Email != "yeni@x" || a.Role != "OPERATOR" || !a.Active {
				t.Fatalf("yeni yönetici alanları hatalı: %+v", a)
			}
		}
	}
	if !found {
		t.Fatalf("yeni yönetici listede görünmeliydi: %+v", out.Admins)
	}

	// Rol değiştir → ADMIN.
	if code, _ := post(t, ts.URL+"/api/admins/"+newID+"/role", token, map[string]string{"role": "ADMIN"}); code != http.StatusOK {
		t.Fatalf("rol değiştirme 200 dönmeliydi, %d", code)
	}
	if store.roles[newID] != admin.RoleAdmin {
		t.Fatalf("rol ADMIN olmalıydı: %v", store.roles[newID])
	}

	// Pasifleştir.
	if code, _ := post(t, ts.URL+"/api/admins/"+newID+"/deactivate", token, map[string]string{}); code != http.StatusOK {
		t.Fatalf("pasifleştirme 200 dönmeliydi, %d", code)
	}
	if store.adminInfos[newID].Active {
		t.Fatal("yönetici pasifleştirilmiş olmalıydı")
	}
}

func TestListAdminsRequiresOperatorHTTP(t *testing.T) {
	ts, store := setup(t)
	defer ts.Close()
	addAdmin(t, store, "op1", "op@x", "secret", admin.RoleOperator)

	// OPERATOR listeleyebilmeli.
	_, opBody := post(t, ts.URL+"/api/login", "", map[string]string{"email": "op@x", "password": "secret"})
	resp, err := authedGET(t, ts.URL+"/api/admins", opBody["token"])
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("OPERATOR yönetici listeleyebilmeli, %d", resp.StatusCode)
	}

	// OPERATOR yeni yönetici oluşturamamalı (ADMIN gerekir) → 403.
	if code, _ := post(t, ts.URL+"/api/admins", opBody["token"], map[string]string{
		"email": "x@x", "password": "parola12", "role": "VIEWER",
	}); code != http.StatusForbidden {
		t.Fatalf("OPERATOR admin oluşturamamalı, %d", code)
	}
}

func TestCreatePolicyRequiresAdminHTTP(t *testing.T) {
	ts, store := setup(t)
	defer ts.Close()
	addAdmin(t, store, "op1", "op@x", "secret", admin.RoleOperator)
	addAdmin(t, store, "ad1", "admin@x", "secret", admin.RoleAdmin)

	_, opBody := post(t, ts.URL+"/api/login", "", map[string]string{"email": "op@x", "password": "secret"})
	if code, _ := post(t, ts.URL+"/api/policies", opBody["token"], map[string]string{"name": "P", "version": "v1"}); code != http.StatusForbidden {
		t.Fatalf("OPERATOR politika oluşturamamalı, %d", code)
	}

	_, adBody := post(t, ts.URL+"/api/login", "", map[string]string{"email": "admin@x", "password": "secret"})
	code, body := post(t, ts.URL+"/api/policies", adBody["token"], map[string]string{"name": "P", "version": "v1"})
	if code != http.StatusOK || body["policy_id"] == "" {
		t.Fatalf("ADMIN politika oluşturabilmeli: code=%d body=%v", code, body)
	}
}

// Tespit kuralı test aracı (dry-run): örnek olay motora verilir, eşleşen
// kurallar döner. Salt-okunur — herhangi bir kimliği doğrulanmış kullanıcı
// erişebilir; eşleşme yoksa boş liste döner.
func TestDetectionTestEndpoint(t *testing.T) {
	ts, store := setup(t)
	defer ts.Close()
	addAdmin(t, store, "v1", "viewer@x", "secret", admin.RoleViewer)

	_, lb := post(t, ts.URL+"/api/login", "", map[string]string{"email": "viewer@x", "password": "secret"})
	token := lb["token"]
	if token == "" {
		t.Fatal("login token alınamadı")
	}

	// Token'sız → 401.
	if code, _ := post(t, ts.URL+"/api/detections/test", "", map[string]string{"category": "SECURITY", "message": "kurcalama"}); code != http.StatusUnauthorized {
		t.Fatalf("token'sız istek 401 dönmeliydi, %d", code)
	}

	do := func(category, message string) (int, int, string) {
		b, _ := json.Marshal(map[string]string{"category": category, "message": message})
		req, _ := http.NewRequest("POST", ts.URL+"/api/detections/test", bytes.NewReader(b))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var out struct {
			Matched int `json:"matched"`
			Matches []struct {
				RuleID string `json:"rule_id"`
			} `json:"matches"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&out)
		first := ""
		if len(out.Matches) > 0 {
			first = out.Matches[0].RuleID
		}
		return resp.StatusCode, out.Matched, first
	}

	// "kurcalama" + SECURITY → XDR-0001 eşleşir.
	if code, n, first := do("SECURITY", "ajan kurcalama girişimi tespit edildi"); code != http.StatusOK || n < 1 || first != "XDR-0001" {
		t.Fatalf("kurcalama eşleşmeliydi: code=%d matched=%d first=%q", code, n, first)
	}

	// Eşleşmeyen içerik → boş.
	if code, n, _ := do("SECURITY", "sıradan bilgilendirme mesajı"); code != http.StatusOK || n != 0 {
		t.Fatalf("eşleşme olmamalıydı: code=%d matched=%d", code, n)
	}

	// Kategori kapsamı: "kurcalama" SECURITY kuralında tanımlı; kuralı olmayan
	// bir kategoride (INFO) aynı metin eşleşmemeli.
	if code, n, _ := do("INFO", "kurcalama"); code != http.StatusOK || n != 0 {
		t.Fatalf("kategori kapsamı: eşleşme olmamalıydı: code=%d matched=%d", code, n)
	}
}

// İstek gövdesi boyut sınırı: devasa JSON gövdesi 413 ile reddedilmeli (DoS
// koruması). decode() tüm JSON POST uçlarında MaxBytesReader uygular.
func TestRequestBodySizeLimit(t *testing.T) {
	ts, store := setup(t)
	defer ts.Close()
	addAdmin(t, store, "ad1", "ad@x", "secret", admin.RoleAdmin)
	_, lb := post(t, ts.URL+"/api/login", "", map[string]string{"email": "ad@x", "password": "secret"})
	token := lb["token"]
	if token == "" {
		t.Fatal("login token alınamadı")
	}

	// ~2 MiB'lik geçerli-JSON gövde (sınır 1 MiB) → 413.
	big := make([]byte, 2<<20)
	for i := range big {
		big[i] = 'a'
	}
	body := []byte(`{"name":"`)
	body = append(body, big...)
	body = append(body, []byte(`"}`)...)
	req, _ := http.NewRequest("POST", ts.URL+"/api/policies", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("devasa gövde 413 dönmeliydi, %d", resp.StatusCode)
	}

	// Normal küçük gövde hâlâ çalışmalı.
	if code, b := post(t, ts.URL+"/api/policies", token, map[string]string{"name": "P", "version": "v1"}); code != http.StatusOK || b["policy_id"] == "" {
		t.Fatalf("normal gövde 200 dönmeliydi: code=%d", code)
	}
}
