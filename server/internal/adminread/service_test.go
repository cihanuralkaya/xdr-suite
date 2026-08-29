package adminread

import (
	"context"
	"crypto/rand"
	"testing"
	"time"

	"xdr.corp/suite/server/internal/security"
)

type memStore struct {
	devices  []DeviceRow
	events   []EventRow
	certs    []CertRow
	commands []CmdRow
	polID    string
	polVer   string
}

func (m *memStore) ListDevices(_ context.Context, _ int) ([]DeviceRow, error) {
	return m.devices, nil
}
func (m *memStore) ListEvents(_ context.Context, _ string, _ int) ([]EventRow, error) {
	return m.events, nil
}
func (m *memStore) DeviceByID(_ context.Context, id string) (DeviceRow, bool, error) {
	for _, d := range m.devices {
		if d.ID == id {
			return d, true, nil
		}
	}
	return DeviceRow{}, false, nil
}
func (m *memStore) CertsByDevice(_ context.Context, _ string) ([]CertRow, error) {
	return m.certs, nil
}
func (m *memStore) CommandHistory(_ context.Context, _ string) ([]CmdRow, error) {
	return m.commands, nil
}
func (m *memStore) AssignedPolicy(_ context.Context, _ string) (string, string, error) {
	return m.polID, m.polVer, nil
}

func newCipher(t *testing.T) *security.FieldCipher {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	c, err := security.NewFieldCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestDevicesDecrypted(t *testing.T) {
	cipher := newCipher(t)
	hostEnc, _ := cipher.EncryptString("WORKSTATION-07")
	macEnc, _ := cipher.EncryptString("aa:bb:cc:dd:ee:ff")

	store := &memStore{devices: []DeviceRow{{
		ID: "dev-1", Status: "ACTIVE", AgentVersion: "0.1.0", OSPlatform: "windows",
		LastSeen: time.Now(), HostnameEnc: hostEnc, MACEnc: macEnc,
	}}}
	svc := NewService(store, cipher)

	dtos, err := svc.Devices(context.Background(), 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(dtos) != 1 {
		t.Fatalf("1 cihaz beklenirdi, %d", len(dtos))
	}
	if dtos[0].Hostname != "WORKSTATION-07" || dtos[0].MAC != "aa:bb:cc:dd:ee:ff" {
		t.Fatalf("şifreli alanlar deşifre edilmeliydi: %+v", dtos[0])
	}
}

func TestDevicesBadCiphertext(t *testing.T) {
	cipher := newCipher(t)
	store := &memStore{devices: []DeviceRow{{ID: "d", HostnameEnc: []byte("bozuk-veri")}}}
	svc := NewService(store, cipher)
	dtos, _ := svc.Devices(context.Background(), 0)
	if dtos[0].Hostname != "(çözülemedi)" {
		t.Fatalf("bozuk şifreli veri güvenli işlenmeliydi: %q", dtos[0].Hostname)
	}
}

func TestDeviceDetail(t *testing.T) {
	cipher := newCipher(t)
	hostEnc, _ := cipher.EncryptString("WORKSTATION-07")
	macEnc, _ := cipher.EncryptString("aa:bb:cc:dd:ee:ff")

	delivered := time.Now()
	store := &memStore{
		devices: []DeviceRow{{
			ID: "dev-1", Status: "ACTIVE", AgentVersion: "0.1.0", OSPlatform: "windows",
			LastSeen: time.Now(), HostnameEnc: hostEnc, MACEnc: macEnc,
		}},
		certs: []CertRow{{
			Serial: "42", Fingerprint: "abcd", NotBefore: time.Now(), NotAfter: time.Now(), Revoked: false,
		}},
		commands: []CmdRow{
			{Type: "QUARANTINE", IssuedBy: "op1", CreatedAt: time.Now(), DeliveredAt: &delivered},
			{Type: "COLLECT_DIAGNOSTICS", IssuedBy: "op1", CreatedAt: time.Now(), DeliveredAt: nil},
		},
		polID:  "pol-1",
		polVer: "v3",
	}
	svc := NewService(store, cipher)

	detail, ok, err := svc.DeviceDetail(context.Background(), "dev-1")
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("cihaz bulunmalıydı")
	}
	if detail.Device.Hostname != "WORKSTATION-07" || detail.Device.MAC != "aa:bb:cc:dd:ee:ff" {
		t.Fatalf("şifreli alanlar deşifre edilmeliydi: %+v", detail.Device)
	}
	if len(detail.Certs) != 1 || detail.Certs[0].Serial != "42" || detail.Certs[0].Fingerprint != "abcd" {
		t.Fatalf("sertifikalar birleştirilmeliydi: %+v", detail.Certs)
	}
	if len(detail.Commands) != 2 || detail.Commands[0].Type != "QUARANTINE" {
		t.Fatalf("komut geçmişi birleştirilmeliydi: %+v", detail.Commands)
	}
	if detail.Commands[0].DeliveredAt == nil || detail.Commands[1].DeliveredAt != nil {
		t.Fatalf("delivered_at teslim durumunu yansıtmalı: %+v", detail.Commands)
	}
	if detail.AssignedPolicyID != "pol-1" || detail.AssignedPolicyVersion != "v3" {
		t.Fatalf("atanmış politika dönmeliydi: %+v", detail)
	}
}

func TestDeviceDetailNotFound(t *testing.T) {
	store := &memStore{}
	svc := NewService(store, newCipher(t))
	_, ok, err := svc.DeviceDetail(context.Background(), "yok")
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("bulunamayan cihaz için ok=false beklenirdi")
	}
}

func TestEventsPassthrough(t *testing.T) {
	store := &memStore{events: []EventRow{
		{ID: "e1", Category: "SECURITY", Severity: "HIGH", Message: "test", OccurredAt: time.Now()},
	}}
	svc := NewService(store, newCipher(t))
	dtos, err := svc.Events(context.Background(), "", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(dtos) != 1 || dtos[0].Message != "test" || dtos[0].Severity != "HIGH" {
		t.Fatalf("olaylar aynen dönmeliydi: %+v", dtos)
	}
}
