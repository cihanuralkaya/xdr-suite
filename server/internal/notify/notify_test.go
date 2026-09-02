package notify

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestWebhookNotifierDeliversHighSeverity(t *testing.T) {
	got := make(chan Alert, 4)
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var a Alert
		_ = json.NewDecoder(r.Body).Decode(&a)
		got <- a
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	n, err := NewWebhookNotifier(ts.URL, "HIGH")
	if err != nil {
		t.Fatal(err)
	}
	n.client = ts.Client() // test TLS sertifikasına güven

	// INFO eşik altında → gönderilmez.
	n.Notify(Alert{DeviceID: "d1", Severity: "INFO", Message: "rutin"})
	// HIGH → iletilir.
	n.Notify(Alert{DeviceID: "d2", Severity: "HIGH", Message: "şüpheli süreç", Category: "PROCESS"})

	select {
	case a := <-got:
		if a.Severity != "HIGH" || a.DeviceID != "d2" {
			t.Fatalf("beklenmeyen uyarı: %+v", a)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("HIGH uyarı 2 sn içinde teslim edilmedi")
	}
	// INFO teslim edilmemeli (eşik filtresi).
	select {
	case a := <-got:
		t.Fatalf("INFO filtrelenmeliydi ama teslim edildi: %+v", a)
	case <-time.After(250 * time.Millisecond):
	}
}

func TestWebhookNotifierRejectsInsecureURL(t *testing.T) {
	if _, err := NewWebhookNotifier("http://insecure.example/hook", "HIGH"); err == nil {
		t.Fatal("http (TLS'siz) URL reddedilmeliydi")
	}
	if _, err := NewWebhookNotifier("bu bir url değil", "HIGH"); err == nil {
		t.Fatal("geçersiz URL reddedilmeliydi")
	}
}

func TestSevRankOrdering(t *testing.T) {
	if !(sevRank("CRITICAL") > sevRank("HIGH") && sevRank("HIGH") > sevRank("MEDIUM") &&
		sevRank("MEDIUM") > sevRank("LOW") && sevRank("LOW") > sevRank("INFO") && sevRank("INFO") > sevRank("bilinmeyen")) {
		t.Fatal("önem düzeyi sıralaması yanlış")
	}
}
