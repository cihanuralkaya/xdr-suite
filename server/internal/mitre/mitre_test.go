package mitre

import "testing"

func TestClassify(t *testing.T) {
	cases := []struct {
		cat, msg string
		wantID   string
		wantOK   bool
	}{
		{"NETWORK_DISCOVERY", "12 komşu bulundu", "T1046", true},
		{"POLICY_VIOLATION", "yasaklı süreç sonlandırıldı: game.exe", "T1204", true},
		{"SECURITY", "sahte/bozuk güncelleme reddedildi: 2.0.0", "T1195", true},
		{"SECURITY", "imzasız/sahte script reddedildi: cmd-9", "T1059", true},
		{"SECURITY", "anomali: olağandışı süreç davranışı: x.exe", "T1055", true},
		{"SECURITY", "watchdog kurcalama tespit edildi", "T1562", true},
		{"SECURITY", "tanımsız güvenlik olayı", "T1562", true}, // default
		{"SYSTEM", "ajan başladı", "", false},
		{"AGENT_UPDATE", "güncellendi", "", false},
	}
	for _, c := range cases {
		got, ok := Classify(c.cat, c.msg)
		if ok != c.wantOK {
			t.Errorf("Classify(%q,%q) ok=%v beklenen=%v", c.cat, c.msg, ok, c.wantOK)
			continue
		}
		if ok && got.ID != c.wantID {
			t.Errorf("Classify(%q,%q) id=%s beklenen=%s", c.cat, c.msg, got.ID, c.wantID)
		}
	}
}

func TestCatalogUnique(t *testing.T) {
	seen := map[string]bool{}
	cat := Catalog()
	if len(cat) == 0 {
		t.Fatal("katalog boş")
	}
	for _, tq := range cat {
		if tq.ID == "" || tq.Name == "" || tq.Tactic == "" {
			t.Errorf("eksik alan: %+v", tq)
		}
		if seen[tq.ID] {
			t.Errorf("yinelenen teknik: %s", tq.ID)
		}
		seen[tq.ID] = true
	}
}
