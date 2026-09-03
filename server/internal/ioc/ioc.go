// Package ioc, tehdit istihbaratı (IoC) eşleştirmesidir: bilinen-kötü
// göstergeleri (IP, MAC, alan adı, hash, süreç adı) bir listeden yükler ve gelen
// olayların yapısal Details alanı + mesajı ile karşılaştırır. Eşleşme, bilinen bir
// tehdidin uç noktada görüldüğünü gösterir (yüksek-güven tespiti).
//
// Liste basit metin biçimindedir (operatör/feed dostu):
//
//	# yorum
//	10.13.37.5        known-c2
//	aa:bb:cc:dd:ee:ff  rogue-device
//	evil.example.com   phishing-altyapı
//	mimikatz.exe       kimlik-hırsızı
//
// İlk boşlukla-ayrılmış belirteç GÖSTERGEDİR; kalanı isteğe bağlı etikettir.
// Bağımlılıksız (yalnız stdlib).
package ioc

import (
	"bufio"
	"io"
	"os"
	"strings"
)

// Set, göstergeleri (küçük harfe normalize edilmiş) etiketleriyle tutar.
type Set struct {
	byValue map[string]string
}

// Size, gösterge sayısını döner.
func (s *Set) Size() int {
	if s == nil {
		return 0
	}
	return len(s.byValue)
}

// Load, verilen okuyucudan gösterge listesini ayrıştırır.
func Load(r io.Reader) (*Set, error) {
	set := &Set{byValue: map[string]string{}}
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		val := strings.ToLower(fields[0])
		label := ""
		if len(fields) > 1 {
			label = strings.Join(fields[1:], " ")
		}
		if label == "" {
			label = "etiketsiz"
		}
		set.byValue[val] = label
	}
	return set, sc.Err()
}

// LoadFile, bir dosyadan gösterge listesi yükler.
func LoadFile(path string) (*Set, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return Load(f)
}

// Match, olayın Details string değerleri ile göstergeleri (tam, küçük/büyük harf
// duyarsız) ve mesajı (alt dize) karşılaştırır. İlk eşleşmenin etiketini döner.
// Set boş/nil ise asla eşleşmez (özellik kapalı).
func (s *Set) Match(details map[string]any, message string) (label, indicator string, ok bool) {
	if s == nil || len(s.byValue) == 0 {
		return "", "", false
	}
	// 1) Details string değerleri — tam eşleşme (ip/mac/process gibi yapısal alanlar).
	for _, v := range details {
		if str, isStr := v.(string); isStr {
			if lbl, hit := s.byValue[strings.ToLower(strings.TrimSpace(str))]; hit {
				return lbl, str, true
			}
		}
	}
	// 2) Mesaj — gösterge alt dize olarak geçiyorsa (mesaja gömülü alan adı/hash).
	msg := strings.ToLower(message)
	for val, lbl := range s.byValue {
		if strings.Contains(msg, val) {
			return lbl, val, true
		}
	}
	return "", "", false
}
