package main

import (
	"errors"
	"testing"

	"xdr.corp/suite/agent/internal/collector"
)

// Güvenli-mod AÇIKKEN yıkıcı MDM eylemi (LOCK/RESTART/WIPE) gerçek OS fonksiyonunu
// ASLA çağırmamalı — yalnız bir INFO olayı üretmeli. Bu, demo/test sırasında
// cihazın kilitlenmesini/yeniden başlamasını/silinmesini önleyen kritik güvenlik
// garantisidir; kırılırsa gerçek yıkıcı eylem tetiklenebilir.
func TestDoDeviceActionSafeModeDoesNotInvoke(t *testing.T) {
	buf := collector.NewBuffer(16)
	called := false
	doDeviceAction(buf, true /*safeMode*/, "WIPE", "veri silme", func() error {
		called = true // gerçek yıkıcı eylem — çağrılmamalı
		return nil
	})
	if called {
		t.Fatal("güvenli modda gerçek eylem fonksiyonu çağrıldı — YIKICI eylem tetiklenebilirdi")
	}
	evs := buf.Pending(10)
	if len(evs) != 1 {
		t.Fatalf("tam olarak 1 olay beklendi, bulunan: %d", len(evs))
	}
	e := evs[0]
	if e.Category != "SYSTEM" || e.Severity != "INFO" {
		t.Fatalf("güvenli-mod olayı SYSTEM/INFO olmalı, bulunan: %s/%s", e.Category, e.Severity)
	}
	if sm, _ := e.Details["safe_mode"].(bool); !sm {
		t.Fatalf("olay details.safe_mode=true taşımalı: %+v", e.Details)
	}
}

// Güvenli-mod KAPALIYKEN eylem fonksiyonu çağrılmalı; başarı INFO olay üretmeli.
func TestDoDeviceActionAppliesWhenNotSafeMode(t *testing.T) {
	buf := collector.NewBuffer(16)
	called := false
	doDeviceAction(buf, false, "LOCK", "ekran kilitleme", func() error {
		called = true
		return nil
	})
	if !called {
		t.Fatal("güvenli-mod kapalıyken eylem fonksiyonu çağrılmalıydı")
	}
	evs := buf.Pending(10)
	if len(evs) != 1 || evs[0].Severity != "INFO" {
		t.Fatalf("başarı için 1 INFO olay beklendi: %+v", evs)
	}
	if _, ok := evs[0].Details["error"]; ok {
		t.Fatalf("başarı olayı error detayı taşımamalı: %+v", evs[0].Details)
	}
}

// Eylem fonksiyonu hata dönerse MEDIUM olay + error detayı üretilmeli.
func TestDoDeviceActionReportsFailure(t *testing.T) {
	buf := collector.NewBuffer(16)
	doDeviceAction(buf, false, "RESTART", "yeniden başlatma", func() error {
		return errors.New("boom")
	})
	evs := buf.Pending(10)
	if len(evs) != 1 {
		t.Fatalf("1 olay beklendi: %d", len(evs))
	}
	if evs[0].Severity != "MEDIUM" {
		t.Fatalf("başarısızlık olayı MEDIUM olmalı, bulunan: %s", evs[0].Severity)
	}
	if es, _ := evs[0].Details["error"].(string); es != "boom" {
		t.Fatalf("olay details.error='boom' taşımalı: %+v", evs[0].Details)
	}
}
