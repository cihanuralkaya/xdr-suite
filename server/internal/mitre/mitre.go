// Package mitre, üretilen güvenlik olaylarını MITRE ATT&CK tekniklerine eşler.
// Bu, olaylara taktik/teknik bağlamı ekler (SOC üçgenlemesi, kapsama raporu) ve
// dış bağımlılık gerektirmez — statik, denetlenebilir bir eşleme tablosudur.
//
// Eşleme, sistemin GERÇEKTE ürettiği olay kategorileri/mesajlarına dayanır
// (agent/internal/enforce, quarantine, cmd/agent, discovery). Bir tespitin
// "hangi düşman tekniğini gözlemlediğini" belirtir — kanonik savunma pratiği.
package mitre

import "strings"

// Technique, bir ATT&CK tekniğidir.
type Technique struct {
	ID     string `json:"id"`     // ör. "T1059"
	Name   string `json:"name"`   // ör. "Command and Scripting Interpreter"
	Tactic string `json:"tactic"` // ör. "Execution"
}

// Teknik sabitleri (kapsanan alt küme).
var (
	tExecutionScript = Technique{ID: "T1059", Name: "Command and Scripting Interpreter", Tactic: "Execution"}
	tUserExecution   = Technique{ID: "T1204", Name: "User Execution", Tactic: "Execution"}
	tImpairDefenses  = Technique{ID: "T1562", Name: "Impair Defenses", Tactic: "Defense Evasion"}
	tSupplyChain     = Technique{ID: "T1195", Name: "Supply Chain Compromise", Tactic: "Initial Access"}
	tNetworkDiscover = Technique{ID: "T1046", Name: "Network Service Discovery", Tactic: "Discovery"}
	tProcInjection   = Technique{ID: "T1055", Name: "Process Injection", Tactic: "Defense Evasion"}
)

// Catalog, sistemin eşleyebildiği tekniklerin tam listesini (kapsama matrisi)
// deterministik sırada döner. ATT&CK kapsama görünümü için kullanılır.
func Catalog() []Technique {
	return []Technique{
		tSupplyChain,     // T1195
		tNetworkDiscover, // T1046
		tProcInjection,   // T1055
		tExecutionScript, // T1059
		tUserExecution,   // T1204
		tImpairDefenses,  // T1562
	}
}

// Classify, bir olay kategorisi ve mesajına göre ATT&CK tekniğini döner. Eşleşme
// yoksa (Technique{}, false) döner (operasyonel/nötr olaylar: SYSTEM, AGENT_UPDATE).
// SECURITY kategorisi birden çok tespiti kapsar; mesaj içeriğiyle inceltilir.
func Classify(category, message string) (Technique, bool) {
	m := strings.ToLower(message)
	switch category {
	case "NETWORK_DISCOVERY":
		return tNetworkDiscover, true
	case "POLICY_VIOLATION":
		// Yasaklı/yetkisiz süreç yürütmesi tespiti.
		return tUserExecution, true
	case "SECURITY":
		switch {
		case strings.Contains(m, "güncelleme"): // sahte/bozuk OTA reddi
			return tSupplyChain, true
		case strings.Contains(m, "script"): // imzasız/sahte script reddi
			return tExecutionScript, true
		case strings.Contains(m, "anomali"): // olağandışı süreç davranışı
			return tProcInjection, true
		case strings.Contains(m, "kurcalama") || strings.Contains(m, "tamper") ||
			strings.Contains(m, "watchdog") || strings.Contains(m, "karantina"):
			return tImpairDefenses, true
		default:
			// Sınıflandırılamayan SECURITY olayı: savunma-etkisizleştirme varsay.
			return tImpairDefenses, true
		}
	default:
		return Technique{}, false
	}
}
