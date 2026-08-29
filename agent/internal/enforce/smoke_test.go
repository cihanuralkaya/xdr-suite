package enforce

import "testing"

// TestRealListSmoke, gerçek OS süreç listeleyicisini çağırır (yalnız LİSTELER;
// hiçbir süreci sonlandırmaz). Desteklenmeyen platformda atlanır.
func TestRealListSmoke(t *testing.T) {
	procs, err := NewProcessController().List()
	if err != nil {
		t.Skipf("bu platformda süreç listeleme yok: %v", err)
	}
	if len(procs) == 0 {
		t.Fatal("hiç çalışan süreç bulunamadı")
	}
	named := 0
	for _, p := range procs {
		if p.Name != "" {
			named++
		}
	}
	if named == 0 {
		t.Fatal("süreç adları boş döndü")
	}
	t.Logf("gerçek süreç listesi OK: %d süreç, %d tanesi adlı", len(procs), named)
}
