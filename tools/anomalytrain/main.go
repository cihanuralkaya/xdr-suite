// Command anomalytrain, etiketli öznitelik verisinden (CSV) ajan için bir
// lojistik anomali modeli eğitir ve anomaly.ModelScorer'ın yüklediği JSON
// formatına yazar. Böylece "eğit → JSON → ajan (XDR_ANOMALY_MODEL)" hattı
// tamamlanır.
//
// CSV: her satır  f1,f2,...,fn,label   (label 0=normal, 1=anomali). İlk satır
// sayısal değilse başlık kabul edilip atlanır.
//
// Örnek:
//
//	anomalytrain -in samples.csv -out model.json -epochs 500 -lr 0.5
package main

import (
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strconv"
)

func main() {
	in := flag.String("in", "", "etiketli CSV girdisi (f1..fn,label) (zorunlu)")
	out := flag.String("out", "model.json", "çıktı model JSON yolu")
	epochs := flag.Int("epochs", 500, "eğitim epoch sayısı")
	lr := flag.Float64("lr", 0.5, "öğrenme oranı")
	flag.Parse()

	if *in == "" {
		fmt.Fprintln(os.Stderr, "anomalytrain: -in zorunlu")
		os.Exit(1)
	}
	samples, err := readCSV(*in)
	if err != nil {
		fmt.Fprintf(os.Stderr, "anomalytrain: %v\n", err)
		os.Exit(1)
	}
	if len(samples) == 0 {
		fmt.Fprintln(os.Stderr, "anomalytrain: örnek yok")
		os.Exit(1)
	}

	mean, std, w, b := trainLogistic(samples, *epochs, *lr)
	acc := accuracy(samples, mean, std, w, b)
	model := buildModel(mean, std, w, b)

	data, _ := json.MarshalIndent(model, "", "  ")
	if err := os.WriteFile(*out, append(data, '\n'), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "anomalytrain: yazma: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("model yazıldı: %s (%d örnek, %d öznitelik, eğitim doğruluğu %.1f%%)\n",
		*out, len(samples), len(samples[0].features), acc*100)
}

// readCSV, CSV'yi örneklere çevirir. Son sütun etikettir. Başlık (ilk satır
// sayısal değilse) atlanır.
func readCSV(path string) ([]sample, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	rows, err := csv.NewReader(f).ReadAll()
	if err != nil {
		return nil, err
	}
	var samples []sample
	for i, row := range rows {
		if len(row) < 2 {
			continue
		}
		if i == 0 {
			if _, err := strconv.ParseFloat(row[0], 64); err != nil {
				continue // başlık satırı
			}
		}
		vals := make([]float64, len(row))
		ok := true
		for j, c := range row {
			v, err := strconv.ParseFloat(c, 64)
			if err != nil {
				ok = false
				break
			}
			vals[j] = v
		}
		if !ok {
			continue
		}
		samples = append(samples, sample{features: vals[:len(vals)-1], label: vals[len(vals)-1]})
	}
	return samples, nil
}
