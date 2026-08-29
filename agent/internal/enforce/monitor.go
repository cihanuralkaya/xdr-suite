// Package enforce, politika uygulamasını (enforcement) yürütür: çalışan
// süreçleri listeler, politika motoruyla değerlendirir, yasaklı olanları
// sonlandırır ve POLICY_VIOLATION olayı üretir.
//
// Süreç listeleme/sonlandırma OS'e özgüdür ve ProcessController arayüzünün
// arkasındadır (Windows implementasyonu controller_windows.go). Buradaki Monitor
// mantığı platformdan bağımsızdır ve sahte controller ile test edilebilir.
package enforce

import (
	"fmt"
	"time"

	"xdr.corp/suite/agent/internal/agentclock"
	"xdr.corp/suite/agent/internal/collector"
	"xdr.corp/suite/agent/internal/policy"
)

// Process, çalışan bir süreçtir.
type Process struct {
	PID  uint32
	Name string
	Path string
}

// ProcessController, OS'e özgü süreç listeleme ve sonlandırma sağlar.
type ProcessController interface {
	List() ([]Process, error)
	Kill(pid uint32) error
}

// Monitor, tek bir değerlendirme turunu yürütür. Motor ajan tarafında sıcak
// değiştirildiğinden, geçerli motor her turda Tick'e verilir.
type Monitor struct {
	ctrl  ProcessController
	clock *agentclock.Clock
	buf   *collector.Buffer
	self  uint32 // ajanın kendi PID'i — asla sonlandırılmaz
}

// NewMonitor oluşturur.
func NewMonitor(ctrl ProcessController, clock *agentclock.Clock, buf *collector.Buffer, selfPID uint32) *Monitor {
	return &Monitor{ctrl: ctrl, clock: clock, buf: buf, self: selfPID}
}

// Tick, bir değerlendirme turu yürütür: süreçleri listeler, verilen motora göre
// yasaklıları tespit edip sonlandırır ve olay üretir. Sonlandırılan süreç
// sayısını döner.
func (m *Monitor) Tick(engine *policy.Engine) (int, error) {
	procs, err := m.ctrl.List()
	if err != nil {
		return 0, err
	}
	now, synced := m.clock.Now()

	enforced := 0
	for _, p := range procs {
		if p.PID == m.self || p.PID == 0 {
			continue // ajanın kendisini ve sistem boşta sürecini atla
		}
		target := p.Path
		if target == "" {
			target = p.Name
		}

		var dec policy.Decision
		if synced {
			dec = engine.EvaluateProcess(target, now)
		} else {
			// Saat çıpası yoksa yalnız her-zaman-yasak kuralları uygulanır.
			dec = engine.EvaluateAlways(target)
		}
		if !dec.Blocked {
			continue
		}

		if err := m.ctrl.Kill(p.PID); err != nil {
			m.emit("CRITICAL", fmt.Sprintf("yasaklı süreç sonlandırılamadı: %s (pid=%d, kural=%s): %v",
				p.Name, p.PID, dec.RuleID, err))
			continue
		}
		m.emit("HIGH", fmt.Sprintf("yasaklı süreç sonlandırıldı: %s (pid=%d, kural=%s, sebep=%s)",
			p.Name, p.PID, dec.RuleID, dec.Reason))
		enforced++
	}
	return enforced, nil
}

func (m *Monitor) emit(severity, message string) {
	m.buf.Add(collector.Event{
		Category:   "POLICY_VIOLATION",
		Severity:   severity,
		Message:    message,
		OccurredAt: time.Now(),
	})
}
