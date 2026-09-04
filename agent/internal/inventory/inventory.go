// Package inventory, uç noktadaki yüklü yazılım envanterini toplar (MDM
// varlık/uyum görünürlüğü). OS-özel sorgular exec ile yapılır; ayrıştırma
// mantığı platform-bağımsız ve test edilebilir tutulur (quarantine/compliance
// ile aynı desen). Gerçek OS sorgusu bu ortamda canlı doğrulanmaz — mantık
// testlidir, OS-derlenir.
package inventory

import (
	"sort"
	"strings"
)

// maxPackages, tek envanter olayında taşınan azami paket sayısıdır. Olay/gövde
// şişmesini önler (yüzlerce paketli hostlarda); toplam sayı ayrıca raporlanır.
const maxPackages = 200

// Collector, OS-özel yazılım envanteri sağlar.
type Collector interface {
	// Software, yüklü yazılım (ham) adlarını döner. Sorgu başarısızsa boş döner
	// (hata değil — envanter best-effort).
	Software() []string
}

// Collect, mevcut platformun yazılım envanterini tekilleştirilmiş+sıralı liste
// (maxPackages'a kırpılmış) ve kırpmadan önceki toplam benzersiz sayı olarak
// döner. Envanter yoksa boş liste + 0.
func Collect() (list []string, total int) {
	return normalize(NewCollector().Software())
}

// normalize, ham ad listesini tekilleştirir, sıralar ve maxPackages'a kırpar.
// Dönen ikinci değer, kırpmadan ÖNCEki toplam benzersiz sayıdır.
func normalize(names []string) (list []string, total int) {
	seen := map[string]bool{}
	var uniq []string
	for _, n := range names {
		// Geçerli UTF-8'e temizle: Windows `reg` çıktısı konsol kod sayfasında
		// olabilir; geçersiz UTF-8, protobuf structpb dönüşümünü bozar (tüm
		// Details düşer). Geçersiz baytları at (ASCII adlar korunur).
		n = strings.ToValidUTF8(strings.TrimSpace(n), "")
		if n == "" || seen[n] {
			continue
		}
		seen[n] = true
		uniq = append(uniq, n)
	}
	sort.Strings(uniq)
	total = len(uniq)
	if len(uniq) > maxPackages {
		uniq = uniq[:maxPackages]
	}
	return uniq, total
}

// parseRegUninstall, Windows `reg query ... /s` çıktısından DisplayName
// değerlerini çıkarır. İlgili satırlar şu biçimdedir:
//
//	DisplayName    REG_SZ    Program Adı
//
// Değer, "REG_SZ" (veya diğer REG_ türleri) belirtecinden sonraki kısımdır.
func parseRegUninstall(out string) []string {
	var names []string
	for _, line := range strings.Split(out, "\n") {
		l := strings.TrimSpace(line)
		if !strings.HasPrefix(l, "DisplayName") {
			continue
		}
		i := strings.Index(l, "REG_")
		if i < 0 {
			continue
		}
		// "REG_SZ" sonrası: tür belirtecini atla, kalan boşlukları kırp.
		rest := l[i:]
		sp := strings.IndexByte(rest, ' ')
		if sp < 0 {
			continue
		}
		val := strings.TrimSpace(rest[sp:])
		if val != "" {
			names = append(names, val)
		}
	}
	return names
}

// parseDpkg, Linux `dpkg-query -W -f=${Package}\t${Version}\n` çıktısından
// paket adlarını çıkarır (sekmeden önceki kısım).
func parseDpkg(out string) []string {
	var names []string
	for _, line := range strings.Split(out, "\n") {
		l := strings.TrimSpace(line)
		if l == "" {
			continue
		}
		if tab := strings.IndexByte(l, '\t'); tab >= 0 {
			l = l[:tab]
		}
		names = append(names, l)
	}
	return names
}

// parseRpm, Linux `rpm -qa` çıktısını (satır başına bir paket) döner.
func parseRpm(out string) []string {
	var names []string
	for _, line := range strings.Split(out, "\n") {
		if l := strings.TrimSpace(line); l != "" {
			names = append(names, l)
		}
	}
	return names
}
