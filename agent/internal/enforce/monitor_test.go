package enforce

import (
	"errors"
	"strings"
	"testing"
	"time"

	"xdr.corp/suite/agent/internal/agentclock"
	"xdr.corp/suite/agent/internal/anomaly"
	"xdr.corp/suite/agent/internal/collector"
	"xdr.corp/suite/agent/internal/policy"
)

func TestMonitorEmitsAnomalyEvent(t *testing.T) {
	// Önceden eğitilmiş detektör: normal mesai-saati taban çizgisi.
	det := anomaly.NewDetector(0.7, nil)
	for i := 0; i < 18; i++ {
		det.Observe(anomaly.ProcessObservation{Name: "chrome.exe", Path: `C:\pf\chrome.exe`, Hour: 13 + i%3})
	}

	ctrl := &fakeCtrl{procs: []Process{{PID: 500, Name: "mimikatz.exe", Path: `C:\Temp\mimikatz.exe`}}}
	buf := collector.NewBuffer(100)
	threeAM := time.Date(2026, 8, 28, 3, 0, 0, 0, time.UTC) // gece yarısı, taban çizgisi dışı
	mon := NewMonitor(ctrl, fixedClock(threeAM), buf, 42)
	mon.SetAnomalyDetector(det)

	// Kural yok → sonlandırma yok; yalnız anomali skorlama çalışmalı.
	if _, err := mon.Tick(policy.New(policy.Bundle{})); err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, e := range buf.Pending(10) {
		if e.Category == "SECURITY" && strings.Contains(e.Message, "anomali") {
			found = true
		}
	}
	if !found {
		t.Fatal("aykırı süreç için SECURITY 'anomali' olayı beklenirdi")
	}

	// Detektör ayarlanmamışsa (geriye uyumlu) anomali olayı üretilmemeli.
	buf2 := collector.NewBuffer(100)
	mon2 := NewMonitor(ctrl, fixedClock(threeAM), buf2, 42)
	if _, err := mon2.Tick(policy.New(policy.Bundle{})); err != nil {
		t.Fatal(err)
	}
	if buf2.Len() != 0 {
		t.Fatalf("detektörsüz anomali olayı olmamalıydı, %d olay", buf2.Len())
	}
}

// fakeCtrl, gerçek OS'a dokunmadan controller'ı taklit eder.
type fakeCtrl struct {
	procs   []Process
	killed  []uint32
	failPID uint32
}

func (f *fakeCtrl) List() ([]Process, error) { return f.procs, nil }
func (f *fakeCtrl) Kill(pid uint32) error {
	if pid == f.failPID {
		return errors.New("erişim reddedildi")
	}
	f.killed = append(f.killed, pid)
	return nil
}

func weekdays(ds ...time.Weekday) [7]bool {
	var a [7]bool
	for _, d := range ds {
		a[int(d)] = true
	}
	return a
}

// fixedClock, Now() daima verilen sunucu zamanını döndürecek şekilde senkronize
// bir saat üretir (yerel kaynak sabit).
func fixedClock(server time.Time) *agentclock.Clock {
	c := agentclock.New(func() time.Time { return server })
	c.Sync(server)
	return c
}

func TestEnforceAlwaysBlock(t *testing.T) {
	ctrl := &fakeCtrl{procs: []Process{
		{PID: 100, Name: "torrent.exe", Path: "D:\\x\\torrent.exe"},
		{PID: 200, Name: "notepad.exe"},
		{PID: 42, Name: "agent.exe"}, // self — asla öldürülmemeli
	}}
	buf := collector.NewBuffer(100)
	mon := NewMonitor(ctrl, fixedClock(time.Now()), buf, 42)
	engine := policy.New(policy.Bundle{Rules: []policy.Rule{
		{ID: "b1", Type: policy.RuleAppBlockAlways, Target: "torrent.exe"},
	}})

	n, err := mon.Tick(engine)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 || len(ctrl.killed) != 1 || ctrl.killed[0] != 100 {
		t.Fatalf("yalnız torrent.exe(100) sonlandırılmalıydı, killed=%v n=%d", ctrl.killed, n)
	}
	if buf.Len() != 1 {
		t.Fatalf("1 POLICY_VIOLATION olayı beklenirdi, %d", buf.Len())
	}
}

func TestEnforceTimeBlockWhenSynced(t *testing.T) {
	// Cuma 20:00 — mesai-dışı game.exe yasağı aktif.
	fri2000 := time.Date(2026, 8, 28, 20, 0, 0, 0, time.UTC)
	start, _ := policy.ParseHHMM("18:00")
	end, _ := policy.ParseHHMM("08:00")
	engine := policy.New(policy.Bundle{Rules: []policy.Rule{
		{ID: "t1", Type: policy.RuleAppTimeBlock, Target: "game.exe",
			Start: start, End: end, ActiveDays: weekdays(time.Monday, time.Tuesday, time.Wednesday, time.Thursday, time.Friday)},
	}})
	ctrl := &fakeCtrl{procs: []Process{{PID: 7, Name: "game.exe"}}}
	buf := collector.NewBuffer(100)
	mon := NewMonitor(ctrl, fixedClock(fri2000), buf, 1)

	n, _ := mon.Tick(engine)
	if n != 1 || len(ctrl.killed) != 1 || ctrl.killed[0] != 7 {
		t.Fatalf("mesai-dışı game.exe sonlandırılmalıydı, killed=%v", ctrl.killed)
	}
}

func TestNoTimeEnforceWhenClockUnsynced(t *testing.T) {
	// Senkronize edilmemiş saat: zaman-bloğu uygulanmamalı, ama her-zaman-yasak uygulanmalı.
	start, _ := policy.ParseHHMM("18:00")
	end, _ := policy.ParseHHMM("08:00")
	engine := policy.New(policy.Bundle{Rules: []policy.Rule{
		{ID: "t1", Type: policy.RuleAppTimeBlock, Target: "game.exe",
			Start: start, End: end, ActiveDays: weekdays(time.Friday)},
		{ID: "b1", Type: policy.RuleAppBlockAlways, Target: "malware.exe"},
	}})
	ctrl := &fakeCtrl{procs: []Process{
		{PID: 7, Name: "game.exe"},
		{PID: 9, Name: "malware.exe"},
	}}
	buf := collector.NewBuffer(100)
	unsynced := agentclock.New(time.Now) // Sync çağrılmadı
	mon := NewMonitor(ctrl, unsynced, buf, 1)

	n, _ := mon.Tick(engine)
	// game.exe (zaman-bloğu) DOKUNULMAMALI; malware.exe (her-zaman) sonlandırılmalı.
	if n != 1 || len(ctrl.killed) != 1 || ctrl.killed[0] != 9 {
		t.Fatalf("saat senkronsuzken yalnız her-zaman-yasak uygulanmalıydı, killed=%v", ctrl.killed)
	}
}

func TestKillFailureEmitsCriticalEvent(t *testing.T) {
	ctrl := &fakeCtrl{
		procs:   []Process{{PID: 100, Name: "torrent.exe"}},
		failPID: 100,
	}
	buf := collector.NewBuffer(100)
	mon := NewMonitor(ctrl, fixedClock(time.Now()), buf, 1)
	engine := policy.New(policy.Bundle{Rules: []policy.Rule{
		{ID: "b1", Type: policy.RuleAppBlockAlways, Target: "torrent.exe"},
	}})

	n, _ := mon.Tick(engine)
	if n != 0 {
		t.Fatalf("sonlandırma başarısızsa enforced=0 olmalı, %d", n)
	}
	if buf.Len() != 1 {
		t.Fatalf("başarısızlık için 1 olay üretilmeliydi, %d", buf.Len())
	}
	ev := buf.Pending(1)[0]
	if ev.Severity != "CRITICAL" {
		t.Errorf("başarısız sonlandırma CRITICAL olmalı, %s", ev.Severity)
	}
}
