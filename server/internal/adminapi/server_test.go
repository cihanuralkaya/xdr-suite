package adminapi

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"xdr.corp/suite/server/internal/admin"
	"xdr.corp/suite/server/internal/adminread"
	"xdr.corp/suite/server/internal/security"
)

// memStore, hem admin.Store hem adminapi.AuthStore'u karşılar.
type memStore struct {
	roles     map[string]admin.Role
	emails    map[string]adminRec // email -> (id, hash)
	commands  []string            // "deviceID:type"
	cipher    *security.FieldCipher
	devRows   []adminread.DeviceRow
	evtRows   []adminread.EventRow
	auditRows []adminread.AuditRow
	certRows  []adminread.CertRow
	cmdRows   []adminread.CmdRow
	polID     string
	polVer    string
	rules     map[string][]admin.RuleInput // policyID -> kurallar
	assigned  map[string]string            // deviceID -> policyID
	statuses  map[string]string            // deviceID -> son ayarlanan durum
}

type adminRec struct{ id, hash string }

func newMemStore() *memStore {
	return &memStore{
		roles:    map[string]admin.Role{},
		emails:   map[string]adminRec{},
		rules:    map[string][]admin.RuleInput{},
		assigned: map[string]string{},
	}
}

// admin.Store
func (m *memStore) AdminRole(_ context.Context, id string) (admin.Role, error) {
	return m.roles[id], nil
}
func (m *memStore) SaveEnrollmentToken(_ context.Context, _ []byte, _ string, _ time.Time) error {
	return nil
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
func (m *memStore) RevokeDeviceCerts(_ context.Context, deviceID, _ string) error {
	m.commands = append(m.commands, deviceID+":REVOKE")
	return nil
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

// adminapi.AuthStore
func (m *memStore) LookupAdmin(_ context.Context, email string) (string, string, error) {
	r := m.emails[email]
	return r.id, r.hash, nil
}

// adminread.Store
func (m *memStore) ListDevices(_ context.Context, _ int) ([]adminread.DeviceRow, error) {
	return m.devRows, nil
}
func (m *memStore) ListEvents(_ context.Context, _ string, _ int) ([]adminread.EventRow, error) {
	return m.evtRows, nil
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

func setup(t *testing.T) (*httptest.Server, *memStore) {
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

	srv := New(adminSvc, reader, store, sessions, time.Hour)
	return httptest.NewServer(srv.Handler()), store
}

func addAdmin(t *testing.T, store *memStore, id, email, password string, role admin.Role) {
	t.Helper()
	hash, err := security.HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}
	store.roles[id] = role
	store.emails[email] = adminRec{id: id, hash: hash}
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
