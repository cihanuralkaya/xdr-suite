package adminread

import (
	"context"
	"crypto/rand"
	"testing"
	"time"

	"xdr.corp/suite/server/internal/security"
)

type memStore struct {
	devices []DeviceRow
	events  []EventRow
}

func (m *memStore) ListDevices(_ context.Context, _ int) ([]DeviceRow, error) {
	return m.devices, nil
}
func (m *memStore) ListEvents(_ context.Context, _ string, _ int) ([]EventRow, error) {
	return m.events, nil
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
