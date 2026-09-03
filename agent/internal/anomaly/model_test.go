package anomaly

import (
	"math"
	"path/filepath"
	"testing"
)

// Gönderilen örnek model dosyası (docs/) her zaman yüklenebilir ve mantıklı
// skorlamalı olmalı — şablon bozulursa CI yakalasın.
func TestShippedExampleModelValid(t *testing.T) {
	m, err := LoadModel(filepath.Join("..", "..", "..", "docs", "anomaly-model.example.json"))
	if err != nil {
		t.Fatalf("örnek model yüklenemedi: %v", err)
	}
	anom := m.Score(Features{Values: []float32{1.0, 3, 60, 6}}) // yeni süreç, gece, çok bağlantı
	norm := m.Score(Features{Values: []float32{0.1, 13, 5, 4}}) // normal
	if !(anom > norm) {
		t.Fatalf("örnek model anomaliyi normalden yüksek skorlamalıydı (anom=%.3f norm=%.3f)", anom, norm)
	}
}

// Lojistik model (tek sigmoid katman): yüksek bağlantı sayısı → anomali.
func TestModelScorerLogistic(t *testing.T) {
	js := `{
      "type":"logistic",
      "feature_mean":[0.1,14,5,2],
      "feature_std":[0.1,3,2,1],
      "layers":[
        {"weights":[[0,0,2,0]],"bias":[-3],"activation":"sigmoid"}
      ]
    }`
	m, err := LoadModelJSON([]byte(js))
	if err != nil {
		t.Fatal(err)
	}
	// Normal: bağlantı ortalamada (5) → düşük skor.
	normal := m.Score(Features{Values: []float32{0.1, 14, 5, 2}})
	if normal > 0.2 {
		t.Fatalf("normal gözlem düşük skorlanmalıydı, %.3f", normal)
	}
	// Anomali: çok yüksek bağlantı (50) → yüksek skor.
	anom := m.Score(Features{Values: []float32{0.1, 14, 50, 2}})
	if anom < 0.8 {
		t.Fatalf("yüksek-bağlantı anomalisi yüksek skorlanmalıydı, %.3f", anom)
	}
}

// İki katmanlı MLP (relu gizli + sigmoid çıkış) ileri besleme doğruluğu.
func TestModelScorerMLPForwardPass(t *testing.T) {
	// mean=0,std=1 → standartlaştırma kimlik; giriş = ham değer.
	js := `{
      "type":"mlp",
      "feature_mean":[0,0],
      "feature_std":[1,1],
      "layers":[
        {"weights":[[1,0],[0,-1]],"bias":[0,0],"activation":"relu"},
        {"weights":[[1,1]],"bias":[0],"activation":"linear"}
      ]
    }`
	m, err := LoadModelJSON([]byte(js))
	if err != nil {
		t.Fatal(err)
	}
	// giriş [2,-3]: gizli = relu([2, 3]) = [2,3]; çıkış = 2+3 = 5 → clamp01 → 1.
	if got := m.Score(Features{Values: []float32{2, -3}}); math.Abs(got-1) > 1e-9 {
		t.Fatalf("beklenen 1 (clamp), alınan %.6f", got)
	}
	// giriş [-1,5]: gizli = relu([-1,-5]) = [0,0]; çıkış = 0.
	if got := m.Score(Features{Values: []float32{-1, 5}}); math.Abs(got-0) > 1e-9 {
		t.Fatalf("beklenen 0, alınan %.6f", got)
	}
}

func TestLoadModelValidation(t *testing.T) {
	bad := []string{
		`{"feature_mean":[1],"feature_std":[1,1],"layers":[{"weights":[[1]],"bias":[0]}]}`,                   // mean/std uyumsuz
		`{"feature_mean":[1],"feature_std":[1],"layers":[]}`,                                                 // katman yok
		`{"feature_mean":[1,1],"feature_std":[1,1],"layers":[{"weights":[[1]],"bias":[0]}]}`,                 // giriş boyutu uyumsuz
		`{"feature_mean":[1],"feature_std":[1],"layers":[{"weights":[[1],[1]],"bias":[0,0]}]}`,               // son katman 2 çıkış
		`{"feature_mean":[1],"feature_std":[1],"layers":[{"weights":[[1]],"bias":[0],"activation":"tanh"}]}`, // bilinmeyen aktivasyon
	}
	for i, js := range bad {
		if _, err := LoadModelJSON([]byte(js)); err == nil {
			t.Fatalf("geçersiz model %d hata vermeliydi", i)
		}
	}
}

// ModelScorer, Detector ile drop-in çalışmalı (Scorer arayüzü).
func TestModelScorerPluggableIntoDetector(t *testing.T) {
	js := `{"feature_mean":[0.1,14,5,2],"feature_std":[0.1,3,2,1],
	        "layers":[{"weights":[[0,0,2,0]],"bias":[-3],"activation":"sigmoid"}]}`
	m, err := LoadModelJSON([]byte(js))
	if err != nil {
		t.Fatal(err)
	}
	d := NewDetector(0.8, m) // StatScorer yerine model
	// Featurizer bağlantı sayısını 3. özniteliğe koyar; yüksek bağlantı → anomali.
	r := d.Observe(ProcessObservation{Name: "x.exe", Path: "/x", Connections: 60, Hour: 14})
	if !r.Anomalous {
		t.Fatalf("model-tabanlı detektör yüksek-bağlantıyı anomali işaretlemeliydi, skor=%.3f", r.Score)
	}
}
