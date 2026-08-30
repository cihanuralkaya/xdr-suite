package adminapi

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"xdr.corp/suite/server/internal/admin"
	"xdr.corp/suite/server/internal/adminread"
)

func authedGET(t *testing.T, url, token string) (*http.Response, error) {
	t.Helper()
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	return http.DefaultClient.Do(req)
}

func TestSummaryEndpoint(t *testing.T) {
	ts, store := setup(t)
	defer ts.Close()
	addAdmin(t, store, "op1", "op@x", "secret", admin.RoleOperator)

	now := time.Now()
	store.devRows = []adminread.DeviceRow{
		{ID: "d1", Status: "ACTIVE", LastSeen: now},
		{ID: "d2", Status: "QUARANTINED", LastSeen: now.Add(-time.Hour)},
	}
	store.evtRows = []adminread.EventRow{
		{Severity: "HIGH", Category: "SECURITY", CreatedAt: now},
		{Severity: "LOW", Category: "SYSTEM", CreatedAt: now},
	}
	_, body := post(t, ts.URL+"/api/login", "", map[string]string{"email": "op@x", "password": "secret"})
	token := body["token"]

	resp, err := authedGET(t, ts.URL+"/api/summary", token)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("200 beklenirdi, %d", resp.StatusCode)
	}
	var out struct {
		Summary struct {
			DevicesTotal       int            `json:"devices_total"`
			DevicesOnline      int            `json:"devices_online"`
			DevicesOffline     int            `json:"devices_offline"`
			DevicesQuarantined int            `json:"devices_quarantined"`
			EventsBySeverity   map[string]int `json:"events_by_severity"`
			EventsByCategory   map[string]int `json:"events_by_category"`
			Since              time.Time      `json:"since"`
		} `json:"summary"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	s := out.Summary
	if s.DevicesTotal != 2 || s.DevicesOnline != 1 || s.DevicesOffline != 1 || s.DevicesQuarantined != 1 {
		t.Fatalf("cihaz sayaçları hatalı: %+v", s)
	}
	if s.EventsBySeverity["HIGH"] != 1 || s.EventsByCategory["SECURITY"] != 1 {
		t.Fatalf("olay sayaçları hatalı: %+v", s)
	}
	if s.Since.IsZero() {
		t.Fatal("since doldurulmalıydı")
	}
	if r2, _ := http.Get(ts.URL + "/api/summary"); r2.StatusCode != http.StatusUnauthorized {
		t.Fatalf("token'sız özet 401 dönmeliydi, %d", r2.StatusCode)
	}
}

func TestListAudit(t *testing.T) {
	ts, store := setup(t)
	defer ts.Close()
	addAdmin(t, store, "op1", "op@x", "secret", admin.RoleOperator)
	store.auditRows = []adminread.AuditRow{
		{ID: 1, AdminEmail: "op@x", Action: "QUARANTINE", TargetType: "device", TargetID: "dev-1", CreatedAt: time.Now()},
	}

	_, body := post(t, ts.URL+"/api/login", "", map[string]string{"email": "op@x", "password": "secret"})
	token := body["token"]

	resp, err := authedGET(t, ts.URL+"/api/audit", token)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out struct {
		Audit []struct {
			Action     string `json:"action"`
			TargetID   string `json:"target_id"`
			TargetType string `json:"target_type"`
		} `json:"audit"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if len(out.Audit) != 1 || out.Audit[0].Action != "QUARANTINE" || out.Audit[0].TargetID != "dev-1" {
		t.Fatalf("denetim izi beklenen kaydı taşımıyor: %+v", out.Audit)
	}
	if r2, _ := http.Get(ts.URL + "/api/audit"); r2.StatusCode != http.StatusUnauthorized {
		t.Fatalf("token'sız denetim izi 401 dönmeliydi, %d", r2.StatusCode)
	}
}

func TestListEventsFilter(t *testing.T) {
	ts, store := setup(t)
	defer ts.Close()
	addAdmin(t, store, "op1", "op@x", "secret", admin.RoleOperator)

	now := time.Now()
	store.evtRows = []adminread.EventRow{
		{ID: "e1", Category: "SECURITY", Severity: "HIGH", Message: "yüksek", OccurredAt: now, CreatedAt: now,
			Details: json.RawMessage(`{"pid":42}`)},
		{ID: "e2", Category: "SYSTEM", Severity: "INFO", Message: "bilgi", OccurredAt: now, CreatedAt: now},
	}

	_, body := post(t, ts.URL+"/api/login", "", map[string]string{"email": "op@x", "password": "secret"})
	token := body["token"]

	resp, err := authedGET(t, ts.URL+"/api/events?severity=HIGH", token)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("200 beklenirdi, %d", resp.StatusCode)
	}
	var out struct {
		Events []struct {
			ID       string          `json:"id"`
			Severity string          `json:"severity"`
			Details  json.RawMessage `json:"details"`
		} `json:"events"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if len(out.Events) != 1 || out.Events[0].ID != "e1" || out.Events[0].Severity != "HIGH" {
		t.Fatalf("severity=HIGH filtresi yalnız e1 dönmeliydi: %+v", out.Events)
	}
	if string(out.Events[0].Details) != `{"pid":42}` {
		t.Fatalf("details ham JSON olarak dönmeliydi: %q", string(out.Events[0].Details))
	}

	// Token'sız erişim reddedilmeli.
	if r2, _ := http.Get(ts.URL + "/api/events"); r2.StatusCode != http.StatusUnauthorized {
		t.Fatalf("token'sız olay listesi 401 dönmeliydi, %d", r2.StatusCode)
	}
}

func TestDeviceDetailEndpoint(t *testing.T) {
	ts, store := setup(t)
	defer ts.Close()
	addAdmin(t, store, "op1", "op@x", "secret", admin.RoleOperator)

	hostEnc, _ := store.cipher.EncryptString("WS-07")
	macEnc, _ := store.cipher.EncryptString("aa:bb:cc:dd:ee:ff")
	store.devRows = []adminread.DeviceRow{{ID: "dev-1", Status: "ACTIVE", HostnameEnc: hostEnc, MACEnc: macEnc}}
	store.certRows = []adminread.CertRow{{Serial: "42", Fingerprint: "abcd"}}
	store.cmdRows = []adminread.CmdRow{{Type: "QUARANTINE", IssuedBy: "op1", CreatedAt: time.Now()}}
	store.polID, store.polVer = "pol-1", "v3"

	_, body := post(t, ts.URL+"/api/login", "", map[string]string{"email": "op@x", "password": "secret"})
	token := body["token"]

	if r0, _ := http.Get(ts.URL + "/api/devices/dev-1"); r0.StatusCode != http.StatusUnauthorized {
		t.Fatalf("token'sız detay 401 dönmeliydi, %d", r0.StatusCode)
	}

	resp, err := authedGET(t, ts.URL+"/api/devices/dev-1", token)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("200 beklenirdi, %d", resp.StatusCode)
	}
	var out struct {
		DeviceDetail struct {
			Device struct {
				Hostname string `json:"hostname"`
				MAC      string `json:"mac"`
			} `json:"device"`
			Certs                 []adminread.CertView `json:"certs"`
			Commands              []adminread.CmdView  `json:"commands"`
			AssignedPolicyID      string               `json:"assigned_policy_id"`
			AssignedPolicyVersion string               `json:"assigned_policy_version"`
		} `json:"device_detail"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	d := out.DeviceDetail
	if d.Device.Hostname != "WS-07" || d.Device.MAC != "aa:bb:cc:dd:ee:ff" {
		t.Fatalf("cihaz alanları deşifre edilmeliydi: %+v", d.Device)
	}
	if len(d.Certs) != 1 || d.Certs[0].Serial != "42" {
		t.Fatalf("sertifikalar dönmeliydi: %+v", d.Certs)
	}
	if len(d.Commands) != 1 || d.Commands[0].Type != "QUARANTINE" {
		t.Fatalf("komut geçmişi dönmeliydi: %+v", d.Commands)
	}
	if d.AssignedPolicyID != "pol-1" || d.AssignedPolicyVersion != "v3" {
		t.Fatalf("atanmış politika dönmeliydi: %+v", d)
	}

	resp2, err := authedGET(t, ts.URL+"/api/devices/yok", token)
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusNotFound {
		t.Fatalf("bilinmeyen cihaz 404 dönmeliydi, %d", resp2.StatusCode)
	}
}
