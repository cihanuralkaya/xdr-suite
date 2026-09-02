// Package anomaly, uç noktada hafif davranışsal anomali tespiti sağlar:
// gözlemlerden sayısal öznitelik (feature) çıkarır, bir Scorer ile [0,1]
// anomali skoru üretir ve eşik üstündekileri bildirir.
//
// MİMARİ — ONNX'e hazır sınır: Scorer bir ARAYÜZDÜR. Varsayılan uygulama saf-Go,
// çevrimiçi istatistiksel bir modeldir (StatScorer) — harici bağımlılık yok,
// CGO_ENABLED=0 ile cross-compile edilir ve deterministik test edilir. İleride
// eğitilmiş bir sinir ağı, aynı arayüzü karşılayan bir ONNX-tabanlı Scorer ile
// (ör. onnxruntime CGo, `//go:build onnx` bayrağı arkasında) TAKILIR; çağıran
// kod değişmez. Böylece varsayılan saf-Go derleme bozulmadan ML yolu eklenebilir.
package anomaly

import "math"

// Features, bir gözlemden çıkarılan sayısal öznitelik vektörüdür. Vektör boyutu
// (feature sayısı) Detector ömrü boyunca sabittir.
type Features struct {
	Values []float32
}

// Scorer, bir öznitelik vektörünü [0,1] aralığında bir anomali skoruna eşler
// (0 = normal, 1 = güçlü anomali). Score, gözlemi işleyebilir (çevrimiçi
// öğrenme); aynı vektör iki kez verilirse ikincisi daha normal görünebilir.
type Scorer interface {
	Score(f Features) float64
}

// StatScorer, öznitelik başına çevrimiçi (EWMA) ortalama + varyans tutan saf-Go
// bir anomali scorer'ıdır. Skor, en büyük öznitelik z-skorunu yumuşatarak [0,1]'e
// eşler. İlk 'warmup' gözlem, istatistikleri oturtmak için düşük skorlanır.
type StatScorer struct {
	alpha  float64 // EWMA öğrenme oranı (0<alpha<1); büyük = hızlı uyum
	k      float64 // z→skor yumuşatma ölçeği (skor = 1 - exp(-z/k))
	warmup int     // bu kadar gözlemden önce skor bastırılır
	seen   int
	mean   []float64
	varc   []float64 // varyans (EWMA)
}

// NewStatScorer, verilen öznitelik sayısı için bir StatScorer oluşturur.
// alpha ve k makul varsayılanlara sabitlenir; warmup, ilk gürültüyü bastırır.
func NewStatScorer(numFeatures int) *StatScorer {
	return &StatScorer{
		alpha:  0.15,
		k:      3.0,
		warmup: 5,
		mean:   make([]float64, numFeatures),
		varc:   make([]float64, numFeatures),
	}
}

// Score, öznitelik vektörünü skorlar ve ardından çevrimiçi istatistikleri günceller.
func (s *StatScorer) Score(f Features) float64 {
	n := len(s.mean)
	if len(f.Values) != n || n == 0 {
		return 0
	}
	var maxZ float64
	for i := 0; i < n; i++ {
		x := float64(f.Values[i])
		std := math.Sqrt(s.varc[i])
		if s.seen >= s.warmup && std > 1e-9 {
			z := math.Abs(x-s.mean[i]) / std
			if z > maxZ {
				maxZ = z
			}
		}
	}
	// Çevrimiçi güncelleme (skorladıktan SONRA, böylece gözlem geçmişe karşı ölçülür).
	for i := 0; i < n; i++ {
		x := float64(f.Values[i])
		d := x - s.mean[i]
		s.mean[i] += s.alpha * d
		s.varc[i] = (1-s.alpha)*(s.varc[i] + s.alpha*d*d)
	}
	s.seen++
	if s.seen <= s.warmup {
		return 0
	}
	// z → [0,1]: z=0 →0, büyüdükçe 1'e doyar.
	return 1 - math.Exp(-maxZ/s.k)
}
