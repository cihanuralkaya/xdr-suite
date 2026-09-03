// Package compliance, uç noktanın güvenlik-duruşu uyum sinyallerini toplar
// (ör. disk şifreleme durumu). OS-özel sorgular exec ile yapılır; ayrıştırma
// mantığı platform-bağımsız ve test edilebilir tutulur. Gerçek OS sorgusu
// (quarantine/discovery gibi) bu ortamda canlı doğrulanmaz — mantık testlidir,
// OS-derlenir.
package compliance

import "strings"

// Disk şifreleme durum değerleri.
const (
	EncOn      = "on"
	EncOff     = "off"
	EncUnknown = "unknown"
)

// Checker, OS-özel uyum sorgularını sağlar.
type Checker interface {
	// DiskEncryption, sistem diskinin şifreleme durumunu döner ("on"/"off"/"unknown").
	DiskEncryption() string
}

// parseBitLockerStatus, Windows `manage-bde -status` çıktısını yorumlar.
func parseBitLockerStatus(out string) string {
	lo := strings.ToLower(out)
	switch {
	case strings.Contains(lo, "protection on") || strings.Contains(lo, "koruma açık"):
		return EncOn
	case strings.Contains(lo, "protection off") || strings.Contains(lo, "koruma kapalı"):
		return EncOff
	default:
		return EncUnknown
	}
}

// parseLsblkCrypt, Linux `lsblk -no TYPE` çıktısını yorumlar: "crypt" türü varsa
// blok cihazlarından biri LUKS/dm-crypt ile şifrelidir. Çıktı boşsa unknown.
func parseLsblkCrypt(out string) string {
	if strings.TrimSpace(out) == "" {
		return EncUnknown
	}
	for _, line := range strings.Split(out, "\n") {
		if strings.TrimSpace(strings.ToLower(line)) == "crypt" {
			return EncOn
		}
	}
	return EncOff
}
