package detect

import (
	"testing"

	"xdr.corp/suite/server/internal/model"
)

func TestEvaluateDefaultRules(t *testing.T) {
	e := NewEngine(nil) // yerleşik kurallar

	cases := []struct {
		cat, msg   string
		wantRule   string
		wantSev    string
		wantTechID string
	}{
		{"SECURITY", "watchdog kurcalama tespit edildi", "XDR-0001", "CRITICAL", "T1562"},
		{"SECURITY", "imzasız/sahte script reddedildi: cmd-9", "XDR-0002", "HIGH", "T1059"},
		{"SECURITY", "sahte/bozuk güncelleme reddedildi", "XDR-0003", "HIGH", "T1195"},
		{"SECURITY", "anomali: olağandışı süreç davranışı", "XDR-0004", "HIGH", "T1055"},
		{"POLICY_VIOLATION", "yasaklı süreç sonlandırıldı: game.exe", "XDR-0005", "HIGH", "T1204"},
		{"NETWORK_DISCOVERY", "10 komşu bulundu", "XDR-0006", "LOW", "T1046"},
	}
	for _, c := range cases {
		dets := e.Evaluate(model.Event{Category: c.cat, Message: c.msg})
		if len(dets) == 0 {
			t.Errorf("(%q,%q) tespit üretmeliydi", c.cat, c.msg)
			continue
		}
		d := dets[0]
		if d.RuleID != c.wantRule || d.Severity != c.wantSev || d.Technique.ID != c.wantTechID {
			t.Errorf("(%q,%q) → %s/%s/%s beklenen %s/%s/%s",
				c.cat, c.msg, d.RuleID, d.Severity, d.Technique.ID, c.wantRule, c.wantSev, c.wantTechID)
		}
	}
}

func TestEvaluateNoMatch(t *testing.T) {
	e := NewEngine(nil)
	if d := e.Evaluate(model.Event{Category: "SYSTEM", Message: "ajan başladı"}); len(d) != 0 {
		t.Fatalf("SYSTEM olayı tespit üretmemeliydi: %v", d)
	}
	// Doğru kategori ama örüntü uymuyor → eşleşmez.
	if d := e.Evaluate(model.Event{Category: "SECURITY", Message: "alakasız mesaj"}); len(d) != 0 {
		t.Fatalf("örüntü uymayan SECURITY olayı eşleşmemeliydi: %v", d)
	}
}

func TestContainsIsAND(t *testing.T) {
	e := NewEngine([]Rule{{ID: "R1", Name: "iki-parça", Contains: []string{"foo", "bar"}, Severity: "HIGH"}})
	if d := e.Evaluate(model.Event{Message: "sadece foo"}); len(d) != 0 {
		t.Fatal("tek parça eşleşmemeliydi (AND)")
	}
	if d := e.Evaluate(model.Event{Message: "foo ve bar birlikte"}); len(d) != 1 {
		t.Fatal("iki parça da geçince eşleşmeliydi")
	}
}

func TestRulesCatalogCopy(t *testing.T) {
	e := NewEngine(nil)
	r := e.Rules()
	if len(r) == 0 {
		t.Fatal("katalog boş")
	}
	r[0].ID = "DEĞİŞTİRİLDİ" // dönen kopya iç durumu bozmamalı
	if e.Rules()[0].ID == "DEĞİŞTİRİLDİ" {
		t.Fatal("Rules() iç kurallara referans sızdırdı")
	}
}
