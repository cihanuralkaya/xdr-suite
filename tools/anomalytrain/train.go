package main

import "math"

// sample, etiketli bir eğitim örneğidir (öznitelikler + 0/1 etiket).
type sample struct {
	features []float64
	label    float64 // 0 = normal, 1 = anomali
}

// modelOut, anomaly.ModelScorer'ın yüklediği JSON şemasıdır (tek sigmoid katman
// = lojistik regresyon). Alan adları anomaly paketiyle birebir uyumludur.
type modelOut struct {
	Type        string     `json:"type"`
	FeatureMean []float64  `json:"feature_mean"`
	FeatureStd  []float64  `json:"feature_std"`
	Layers      []layerOut `json:"layers"`
}

type layerOut struct {
	Weights    [][]float64 `json:"weights"`
	Bias       []float64   `json:"bias"`
	Activation string      `json:"activation"`
}

// standardize, öznitelik başına ortalama ve standart sapmayı hesaplar (std=0 ise
// 1'e sabitlenir). Model bunları saklar; ModelScorer aynı dönüşümü uygular.
func standardize(samples []sample, dim int) (mean, std []float64) {
	mean = make([]float64, dim)
	std = make([]float64, dim)
	n := float64(len(samples))
	for _, s := range samples {
		for j := 0; j < dim; j++ {
			mean[j] += s.features[j]
		}
	}
	for j := range mean {
		mean[j] /= n
	}
	for _, s := range samples {
		for j := 0; j < dim; j++ {
			d := s.features[j] - mean[j]
			std[j] += d * d
		}
	}
	for j := range std {
		std[j] = math.Sqrt(std[j] / n)
		if std[j] < 1e-9 {
			std[j] = 1
		}
	}
	return mean, std
}

func sigmoid(x float64) float64 { return 1 / (1 + math.Exp(-x)) }

// trainLogistic, standartlaştırılmış özniteliklerle lojistik regresyonu toplu
// gradyan inişiyle eğitir ve öğrenilen ağırlık + bias'ı döner.
func trainLogistic(samples []sample, epochs int, lr float64) (mean, std, weights []float64, bias float64) {
	if len(samples) == 0 {
		return nil, nil, nil, 0
	}
	dim := len(samples[0].features)
	mean, std = standardize(samples, dim)

	// Standartlaştırılmış girdiler.
	xs := make([][]float64, len(samples))
	for i, s := range samples {
		z := make([]float64, dim)
		for j := 0; j < dim; j++ {
			z[j] = (s.features[j] - mean[j]) / std[j]
		}
		xs[i] = z
	}

	weights = make([]float64, dim)
	n := float64(len(samples))
	for e := 0; e < epochs; e++ {
		gw := make([]float64, dim)
		var gb float64
		for i, x := range xs {
			p := sigmoid(dot(weights, x) + bias)
			err := p - samples[i].label
			for j := 0; j < dim; j++ {
				gw[j] += err * x[j]
			}
			gb += err
		}
		for j := 0; j < dim; j++ {
			weights[j] -= lr * gw[j] / n
		}
		bias -= lr * gb / n
	}
	return mean, std, weights, bias
}

func dot(a, b []float64) float64 {
	var s float64
	for i := range a {
		s += a[i] * b[i]
	}
	return s
}

// accuracy, 0.5 eşiğiyle eğitim doğruluğunu döner (raporlama için).
func accuracy(samples []sample, mean, std, weights []float64, bias float64) float64 {
	if len(samples) == 0 {
		return 0
	}
	var correct int
	for _, s := range samples {
		z := make([]float64, len(s.features))
		for j := range z {
			z[j] = (s.features[j] - mean[j]) / std[j]
		}
		pred := 0.0
		if sigmoid(dot(weights, z)+bias) >= 0.5 {
			pred = 1
		}
		if pred == s.label {
			correct++
		}
	}
	return float64(correct) / float64(len(samples))
}

// buildModel, öğrenilen parametrelerden JSON çıktı yapısını kurar.
func buildModel(mean, std, weights []float64, bias float64) modelOut {
	return modelOut{
		Type:        "logistic",
		FeatureMean: mean,
		FeatureStd:  std,
		Layers: []layerOut{{
			Weights:    [][]float64{weights},
			Bias:       []float64{bias},
			Activation: "sigmoid",
		}},
	}
}
