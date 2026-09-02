package anomaly

import "testing"

func TestStatScorerWarmupThenFlagsOutlier(t *testing.T) {
	s := NewStatScorer(1)

	// Warmup: ilk gözlemler istatistik oturana dek 0 skorlanmalı.
	for i := 0; i < 5; i++ {
		if sc := s.Score(Features{Values: []float32{10}}); sc != 0 {
			t.Fatalf("warmup skoru 0 olmalıydı, %v", sc)
		}
	}
	// Biraz varyanslı normal akış (10,11,12 döngüsü).
	for i := 0; i < 20; i++ {
		s.Score(Features{Values: []float32{float32(10 + i%3)}})
	}
	// Net aykırı değer yüksek skorlanmalı.
	if out := s.Score(Features{Values: []float32{100}}); out < 0.7 {
		t.Fatalf("aykırı değer yüksek skorlanmalıydı, %v", out)
	}
}

func TestStatScorerIgnoresWrongDimension(t *testing.T) {
	s := NewStatScorer(3)
	if sc := s.Score(Features{Values: []float32{1, 2}}); sc != 0 {
		t.Fatalf("yanlış boyutlu vektör 0 dönmeliydi, %v", sc)
	}
}

func TestDetectorFlagsAnomalousProcess(t *testing.T) {
	d := NewDetector(0.7, nil)

	// Normal taban çizgisi: aynı süreç, mesai saati, az bağlantı (hafif varyansla).
	for i := 0; i < 18; i++ {
		r := d.Observe(ProcessObservation{
			Name: "chrome.exe", Path: `C:\Program Files\chrome.exe`,
			Connections: 4 + i%3, Hour: 13 + i%3,
		})
		if r.Anomalous {
			t.Fatalf("normal taban çizgisi anomali işaretlenmemeliydi (i=%d, skor=%.3f)", i, r.Score)
		}
	}

	// Anomali: HİÇ görülmemiş süreç, gece yarısı, çok sayıda ağ bağlantısı.
	out := d.Observe(ProcessObservation{
		Name: "mimikatz.exe", Path: `C:\Temp\mimikatz.exe`,
		Connections: 120, Hour: 3,
	})
	if !out.Anomalous {
		t.Fatalf("aykırı süreç anomali işaretlenmeliydi (skor=%.3f)", out.Score)
	}

	// Anomaliden sonra normal bir gözlem tekrar düşük skorlanmalı (istatistik
	// aykırı değerle şişse de eşik altında kalmalı).
	back := d.Observe(ProcessObservation{
		Name: "chrome.exe", Path: `C:\Program Files\chrome.exe`,
		Connections: 5, Hour: 14,
	})
	if back.Anomalous {
		t.Fatalf("normale dönüş anomali işaretlenmemeliydi (skor=%.3f)", back.Score)
	}
}
