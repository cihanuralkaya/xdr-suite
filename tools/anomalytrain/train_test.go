package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestTrainLogisticSeparatesClasses(t *testing.T) {
	var samples []sample
	// Normal: öznitelik0 düşük (1-3); Anomali: öznitelik0 yüksek (10-12).
	// Öznitelik1 sabit (ayırt edici değil) — std=0 → 1'e sabitlenir.
	for i := 0; i < 20; i++ {
		samples = append(samples, sample{features: []float64{float64(1 + i%3), 5}, label: 0})
		samples = append(samples, sample{features: []float64{float64(10 + i%3), 5}, label: 1})
	}
	mean, std, w, b := trainLogistic(samples, 800, 0.5)

	if acc := accuracy(samples, mean, std, w, b); acc < 0.95 {
		t.Fatalf("eğitim doğruluğu yüksek olmalıydı, %.2f", acc)
	}
	// Ayırt edici öznitelik0'ın ağırlığı pozitif (yüksek → anomali) olmalı.
	if w[0] <= 0 {
		t.Fatalf("öznitelik0 ağırlığı pozitif olmalıydı, %.3f", w[0])
	}
	// Model, yeni bir yüksek-öznitelik0 gözlemini anomali (>0.5) skorlamalı.
	z0 := (11 - mean[0]) / std[0]
	z1 := (5 - mean[1]) / std[1]
	p := sigmoid(w[0]*z0 + w[1]*z1 + b)
	if p < 0.5 {
		t.Fatalf("yüksek öznitelik0 anomali skorlanmalıydı, p=%.3f", p)
	}
}

func TestReadCSVSkipsHeaderAndParses(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "s.csv")
	content := "novelty,hour,conn,label\n1.0,3,60,1\n0.1,13,5,0\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	samples, err := readCSV(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(samples) != 2 {
		t.Fatalf("2 örnek beklenirdi (başlık atlanmalı), %d", len(samples))
	}
	if len(samples[0].features) != 3 || samples[0].label != 1 {
		t.Fatalf("ilk örnek yanlış ayrıştırıldı: %+v", samples[0])
	}
}

func TestBuildModelSchema(t *testing.T) {
	m := buildModel([]float64{0, 0}, []float64{1, 1}, []float64{2, -1}, 0.5)
	if m.Type != "logistic" || len(m.Layers) != 1 || m.Layers[0].Activation != "sigmoid" {
		t.Fatalf("model şeması beklenmedik: %+v", m)
	}
	if len(m.Layers[0].Weights) != 1 || len(m.Layers[0].Weights[0]) != 2 || len(m.Layers[0].Bias) != 1 {
		t.Fatalf("katman boyutları beklenmedik: %+v", m.Layers[0])
	}
}
