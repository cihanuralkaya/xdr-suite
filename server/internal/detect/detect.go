// Package detect, sunucu-taraflı tespit kural motorudur (Sigma-benzeri, hafif).
// Ajanın ürettiği ham olayları merkezi, ADLANDIRILMIŞ tespit kurallarına eşler:
// her kural bir kategori/mesaj örüntüsüne bakar, normalize edilmiş bir önem düzeyi
// ve MITRE ATT&CK tekniği atar. Böylece tespit içeriği ajan yeniden dağıtılmadan
// merkezden yönetilir ve SOC "hangi tespitlerin devrede olduğunu" görebilir.
//
// Bağımlılıksız (yalnız stdlib + mitre + model).
package detect

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"xdr.corp/suite/server/internal/mitre"
	"xdr.corp/suite/server/internal/model"
)

// Rule, bir tespit kuralıdır. Category boşsa her kategori eşleşir; Contains'taki
// TÜM parçalar (küçük/büyük harf duyarsız) mesajda geçmelidir (AND).
type Rule struct {
	ID        string          `json:"id"`
	Name      string          `json:"name"`
	Category  string          `json:"category,omitempty"`
	Contains  []string        `json:"contains,omitempty"`
	Severity  string          `json:"severity"` // kuralın atadığı normalize önem düzeyi
	Technique mitre.Technique `json:"technique"`
}

// Detection, eşleşen bir kuralın ürettiği tespittir.
type Detection struct {
	RuleID    string          `json:"rule_id"`
	RuleName  string          `json:"rule_name"`
	Severity  string          `json:"severity"`
	Technique mitre.Technique `json:"technique"`
}

// matches, kuralın verilen olaya uyup uymadığını söyler.
func (r Rule) matches(ev model.Event) bool {
	if r.Category != "" && r.Category != ev.Category {
		return false
	}
	msg := strings.ToLower(ev.Message)
	for _, sub := range r.Contains {
		if !strings.Contains(msg, strings.ToLower(sub)) {
			return false
		}
	}
	return true
}

// Engine, sıralı bir kural listesini değerlendirir.
type Engine struct {
	rules []Rule
}

// NewEngine, verilen kurallarla motor kurar. Kural verilmezse yerleşik varsayılan
// kural seti kullanılır.
func NewEngine(rules []Rule) *Engine {
	if len(rules) == 0 {
		rules = DefaultRules()
	}
	cp := make([]Rule, len(rules))
	copy(cp, rules)
	return &Engine{rules: cp}
}

// Evaluate, olaya uyan tüm tespitleri (sıralı) döner. Eşleşme yoksa nil.
func (e *Engine) Evaluate(ev model.Event) []Detection {
	var out []Detection
	for _, r := range e.rules {
		if r.matches(ev) {
			out = append(out, Detection{RuleID: r.ID, RuleName: r.Name, Severity: r.Severity, Technique: r.Technique})
		}
	}
	return out
}

// Rules, motorun kurallarını (katalog/görünürlük için) döner.
func (e *Engine) Rules() []Rule {
	cp := make([]Rule, len(e.rules))
	copy(cp, e.rules)
	return cp
}

// LoadRules, operatör-tanımlı özel tespit kurallarını JSON dizisinden ayrıştırır.
// Her kural en az id/name/severity taşımalıdır (aksi halde hata). Böylece SOC,
// koda dokunmadan kuruma özgü tespit içeriği ekleyebilir.
func LoadRules(r io.Reader) ([]Rule, error) {
	var rules []Rule
	if err := json.NewDecoder(r).Decode(&rules); err != nil {
		return nil, fmt.Errorf("detect: kural JSON ayrıştırılamadı: %w", err)
	}
	for i, rr := range rules {
		if rr.ID == "" || rr.Name == "" || rr.Severity == "" {
			return nil, fmt.Errorf("detect: kural[%d] eksik alan (id/name/severity zorunlu)", i)
		}
	}
	return rules, nil
}

// LoadRulesFile, bir dosyadan özel kural seti yükler.
func LoadRulesFile(path string) ([]Rule, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return LoadRules(f)
}

// WithDefaults, yerleşik kurallara özel kuralları ekler (yerleşikler önce
// değerlendirilir, özel kurallar sonra).
func WithDefaults(extra []Rule) []Rule {
	return append(DefaultRules(), extra...)
}

// MITRE ATT&CK teknikleri (mitre paketiyle tutarlı).
var (
	tImpairDefenses = mitre.Technique{ID: "T1562", Name: "Impair Defenses", Tactic: "Defense Evasion"}
	tScripting      = mitre.Technique{ID: "T1059", Name: "Command and Scripting Interpreter", Tactic: "Execution"}
	tSupplyChain    = mitre.Technique{ID: "T1195", Name: "Supply Chain Compromise", Tactic: "Initial Access"}
	tUserExecution  = mitre.Technique{ID: "T1204", Name: "User Execution", Tactic: "Execution"}
	tProcInjection  = mitre.Technique{ID: "T1055", Name: "Process Injection", Tactic: "Defense Evasion"}
	tNetworkDiscov  = mitre.Technique{ID: "T1046", Name: "Network Service Discovery", Tactic: "Discovery"}
)

// DefaultRules, yerleşik tespit kural setidir. Ajanın gerçekte ürettiği olay
// kategorileri/mesajlarına dayanır.
func DefaultRules() []Rule {
	return []Rule{
		{ID: "XDR-0001", Name: "Ajan kurcalama girişimi", Category: "SECURITY",
			Contains: []string{"kurcalama"}, Severity: "CRITICAL", Technique: tImpairDefenses},
		{ID: "XDR-0002", Name: "İmzasız/sahte script reddedildi", Category: "SECURITY",
			Contains: []string{"script"}, Severity: "HIGH", Technique: tScripting},
		{ID: "XDR-0003", Name: "Sahte/bozuk OTA güncelleme reddedildi", Category: "SECURITY",
			Contains: []string{"güncelleme"}, Severity: "HIGH", Technique: tSupplyChain},
		{ID: "XDR-0004", Name: "Davranışsal anomali", Category: "SECURITY",
			Contains: []string{"anomali"}, Severity: "HIGH", Technique: tProcInjection},
		{ID: "XDR-0005", Name: "Yasaklı süreç yürütmesi", Category: "POLICY_VIOLATION",
			Severity: "HIGH", Technique: tUserExecution},
		{ID: "XDR-0006", Name: "Ağ hizmet keşfi", Category: "NETWORK_DISCOVERY",
			Severity: "LOW", Technique: tNetworkDiscov},
	}
}
