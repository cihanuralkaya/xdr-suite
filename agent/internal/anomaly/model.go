package anomaly

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
)

// ModelScorer, ÇEVRİMDIŞI eğitilmiş ve JSON'a dışa aktarılmış küçük bir ileri-
// beslemeli ağı (MLP / lojistik) SAF-GO ile çalıştırır. Bu, "kenar cihazda
// eğitilmiş model çalıştırma" hedefini ONNX Runtime'ın C bağımlılığı OLMADAN
// karşılar (CGO_ENABLED=0 cross-compile korunur). Aynı Scorer arayüzünü
// karşıladığı için StatScorer'ın yerine takılır.
//
// Not: Gerçek `.onnx` ikili formatını yüklemek onnxruntime (CGo) gerektirir ve
// `//go:build onnx` bayrağı arkasına ayrı bir Scorer olarak eklenebilir; bu
// uygulama ise taşınabilir JSON ağırlık formatını kullanır — işlevsel olarak
// eşdeğer (ağırlık × öznitelik → skor), ama saf-Go.
type ModelScorer struct {
	mean   []float64
	std    []float64
	layers []layer
}

type layer struct {
	weights [][]float64 // [çıkış nöronu][giriş] ağırlıkları
	bias    []float64   // [çıkış nöronu]
	act     activation
}

type activation int

const (
	actLinear activation = iota
	actReLU
	actSigmoid
)

// modelJSON, dışa aktarılan model dosyasının şemasıdır.
type modelJSON struct {
	Type        string      `json:"type"` // "mlp" | "logistic"
	FeatureMean []float64   `json:"feature_mean"`
	FeatureStd  []float64   `json:"feature_std"`
	Layers      []layerJSON `json:"layers"`
}

type layerJSON struct {
	Weights    [][]float64 `json:"weights"`
	Bias       []float64   `json:"bias"`
	Activation string      `json:"activation"` // "linear" | "relu" | "sigmoid"
}

// LoadModel, bir JSON model dosyasından ModelScorer yükler.
func LoadModel(path string) (*ModelScorer, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("anomaly: model okunamadı: %w", err)
	}
	return LoadModelJSON(b)
}

// LoadModelJSON, JSON baytlarından ModelScorer kurar ve boyut tutarlılığını
// doğrular.
func LoadModelJSON(data []byte) (*ModelScorer, error) {
	var m modelJSON
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("anomaly: model JSON: %w", err)
	}
	if len(m.FeatureMean) == 0 || len(m.FeatureMean) != len(m.FeatureStd) {
		return nil, fmt.Errorf("anomaly: feature_mean/std boyutları uyumsuz")
	}
	if len(m.Layers) == 0 {
		return nil, fmt.Errorf("anomaly: en az bir katman gerekli")
	}
	s := &ModelScorer{mean: m.FeatureMean, std: m.FeatureStd}
	inDim := len(m.FeatureMean)
	for i, lj := range m.Layers {
		if len(lj.Weights) == 0 || len(lj.Weights) != len(lj.Bias) {
			return nil, fmt.Errorf("anomaly: katman %d ağırlık/bias boyutları uyumsuz", i)
		}
		for j, w := range lj.Weights {
			if len(w) != inDim {
				return nil, fmt.Errorf("anomaly: katman %d nöron %d giriş boyutu %d, beklenen %d", i, j, len(w), inDim)
			}
		}
		act, err := parseActivation(lj.Activation)
		if err != nil {
			return nil, err
		}
		s.layers = append(s.layers, layer{weights: lj.Weights, bias: lj.Bias, act: act})
		inDim = len(lj.Weights) // sonraki katmanın giriş boyutu = bu katmanın çıkış nöron sayısı
	}
	if inDim != 1 {
		return nil, fmt.Errorf("anomaly: son katman tek çıkış (anomali skoru) üretmeli, %d", inDim)
	}
	return s, nil
}

func parseActivation(s string) (activation, error) {
	switch s {
	case "", "linear":
		return actLinear, nil
	case "relu":
		return actReLU, nil
	case "sigmoid":
		return actSigmoid, nil
	default:
		return 0, fmt.Errorf("anomaly: bilinmeyen aktivasyon %q", s)
	}
}

// Score, öznitelik vektörünü standartlaştırır, ağı ileri besler ve [0,1] skoru
// döner. ModelScorer durumsuzdur (çevrimiçi öğrenme yok) — model önceden eğitilmiş.
func (s *ModelScorer) Score(f Features) float64 {
	if len(f.Values) != len(s.mean) {
		return 0
	}
	in := make([]float64, len(f.Values))
	for i, v := range f.Values {
		sd := s.std[i]
		if sd <= 1e-12 {
			sd = 1
		}
		in[i] = (float64(v) - s.mean[i]) / sd
	}
	for _, l := range s.layers {
		out := make([]float64, len(l.weights))
		for j, w := range l.weights {
			sum := l.bias[j]
			for k, wk := range w {
				sum += wk * in[k]
			}
			out[j] = applyActivation(l.act, sum)
		}
		in = out
	}
	return clamp01(in[0])
}

func applyActivation(a activation, x float64) float64 {
	switch a {
	case actReLU:
		if x < 0 {
			return 0
		}
		return x
	case actSigmoid:
		return 1 / (1 + math.Exp(-x))
	default:
		return x
	}
}

func clamp01(x float64) float64 {
	if x < 0 {
		return 0
	}
	if x > 1 {
		return 1
	}
	return x
}
