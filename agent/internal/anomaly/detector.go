package anomaly

import "strings"

// ProcessObservation, bir süreç örneğinin anomali değerlendirmesi için ham
// girdisidir. Ajan, izlediği süreçlerden bunu üretir.
type ProcessObservation struct {
	Name        string // süreç adı (ör. "chrome.exe")
	Path        string // tam yol (Windows '\' veya Unix '/')
	Connections int    // aktif ağ bağlantısı sayısı
	Hour        int    // gözlem saati (0-23), sunucu-çıpalı saatten
}

// numProcessFeatures, süreç öznitelik vektörünün boyutudur.
const numProcessFeatures = 4

// Detector, gözlemleri öznitelik vektörüne çevirir, bir Scorer ile skorlar ve
// eşiği aşanları anomali olarak işaretler. Süreç-adı novelty'sini (yenilik)
// izlemek için görülen adların sayacını tutar.
type Detector struct {
	scorer     Scorer
	threshold  float64
	nameCounts map[string]int
}

// NewDetector, verilen eşik (0..1) ile bir Detector oluşturur. scorer nil ise
// varsayılan saf-Go StatScorer kullanılır.
func NewDetector(threshold float64, scorer Scorer) *Detector {
	if scorer == nil {
		scorer = NewStatScorer(numProcessFeatures)
	}
	return &Detector{scorer: scorer, threshold: threshold, nameCounts: map[string]int{}}
}

// featurize, bir gözlemi sabit boyutlu öznitelik vektörüne çevirir. Novelty,
// adı SAYMADAN önce hesaplanır (ilk görülen ad = 1.0).
func (d *Detector) featurize(o ProcessObservation) Features {
	name := strings.ToLower(strings.TrimSpace(o.Name))
	novelty := 1.0 / float64(1+d.nameCounts[name]) // yeni ad → 1.0, sık → →0
	d.nameCounts[name]++

	depth := strings.Count(o.Path, "/") + strings.Count(o.Path, `\`)

	return Features{Values: []float32{
		float32(novelty),
		float32(o.Hour),
		float32(o.Connections),
		float32(depth),
	}}
}

// Result, bir gözlemin değerlendirme sonucudur.
type Result struct {
	Score     float64
	Anomalous bool
}

// Observe, bir süreç gözlemini değerlendirir: öznitelik çıkarır, skorlar ve
// eşikle karşılaştırır. Skor çevrimiçi öğrenmeyle geçmişe göre hesaplanır.
func (d *Detector) Observe(o ProcessObservation) Result {
	score := d.scorer.Score(d.featurize(o))
	return Result{Score: score, Anomalous: score >= d.threshold}
}
