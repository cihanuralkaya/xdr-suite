package discovery

import (
	"testing"
	"time"
)

func TestObserveReportsOnlyNew(t *testing.T) {
	tr := NewTracker([]string{"aa:bb:cc:dd:ee:ff"})
	now := time.Now()

	first := tr.Observe([]Host{
		{MAC: "aa:bb:cc:dd:ee:ff", IP: "192.168.1.1"},
		{MAC: "00:11:22:33:44:55", IP: "192.168.1.20"},
	}, now)
	if len(first) != 2 {
		t.Fatalf("ilk taramada 2 yeni cihaz beklenirdi, %d", len(first))
	}

	// İkinci tarama aynı cihazlar + bir yeni: yalnız yeni raporlanmalı.
	second := tr.Observe([]Host{
		{MAC: "aa:bb:cc:dd:ee:ff", IP: "192.168.1.1"},
		{MAC: "00:11:22:33:44:55", IP: "192.168.1.20"},
		{MAC: "de:ad:be:ef:00:01", IP: "192.168.1.99"},
	}, now.Add(time.Minute))
	if len(second) != 1 || second[0].Host.MAC != "de:ad:be:ef:00:01" {
		t.Fatalf("yalnız yeni cihaz raporlanmalıydı, %+v", second)
	}
	if tr.Count() != 3 {
		t.Fatalf("3 benzersiz cihaz beklenirdi, %d", tr.Count())
	}
}

func TestAuthorizedFlag(t *testing.T) {
	tr := NewTracker([]string{"AA:BB:CC:DD:EE:FF"}) // allowlist büyük harf
	got := tr.Observe([]Host{
		{MAC: "aa:bb:cc:dd:ee:ff", IP: "10.0.0.1"}, // yetkili
		{MAC: "00:11:22:33:44:55", IP: "10.0.0.2"}, // yetkisiz
	}, time.Now())

	auth := map[string]bool{}
	for _, d := range got {
		auth[d.Host.MAC] = d.Authorized
	}
	if !auth["aa:bb:cc:dd:ee:ff"] {
		t.Error("allowlist'teki cihaz yetkili olmalı")
	}
	if auth["00:11:22:33:44:55"] {
		t.Error("allowlist dışı cihaz yetkisiz olmalı")
	}
}
