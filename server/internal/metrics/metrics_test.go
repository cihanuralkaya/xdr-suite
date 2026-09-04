package metrics

import (
	"strings"
	"testing"
)

func TestWriteExposition(t *testing.T) {
	SetBuildVersion("1.2.3")
	IncLoginSuccess()
	IncLoginFailure()
	IncLoginFailure()
	AddEventsIngested(5)
	AddDetections(3)
	IncAlertRaised()
	IncAutoQuarantine()
	IncIocHit()
	IncClusterPublished()
	IncClusterPublished()
	IncClusterReceived()
	IncClusterFallback()

	var sb strings.Builder
	Write(&sb, Snapshot{
		DevicesTotal:       10,
		DevicesOnline:      7,
		DevicesOffline:     3,
		DevicesQuarantined: 1,
		EventsBySeverity:   map[string]int{"HIGH": 4, "INFO": 20},
		SSEConnections:     2,
	})
	out := sb.String()

	wants := []string{
		`xdr_build_info{version="1.2.3"} 1`,
		"xdr_login_success_total 1",
		"xdr_login_failure_total 2",
		"xdr_events_ingested_total 5",
		"xdr_detections_total 3",
		"xdr_alerts_raised_total 1",
		"xdr_auto_quarantine_total 1",
		"xdr_ioc_hits_total 1",
		`xdr_cluster_notices_total{direction="published"} 2`,
		`xdr_cluster_notices_total{direction="received"} 1`,
		`xdr_cluster_notices_total{direction="fallback"} 1`,
		`xdr_devices{state="total"} 10`,
		`xdr_devices{state="online"} 7`,
		`xdr_devices{state="quarantined"} 1`,
		`xdr_events_by_severity{severity="HIGH"} 4`,
		`xdr_events_by_severity{severity="INFO"} 20`,
		"xdr_sse_connections 2",
		"xdr_uptime_seconds ",
		"xdr_goroutines ",
		"xdr_memory_alloc_bytes ",
		"# TYPE xdr_login_failure_total counter",
	}
	for _, w := range wants {
		if !strings.Contains(out, w) {
			t.Errorf("exposition %q satırını içermeliydi.\n---\n%s", w, out)
		}
	}
	// Önem düzeyi satırları deterministik (alfabetik) sırada olmalı: HIGH < INFO.
	if strings.Index(out, `severity="HIGH"`) > strings.Index(out, `severity="INFO"`) {
		t.Error("önem düzeyi satırları alfabetik sıralı değil")
	}
}
