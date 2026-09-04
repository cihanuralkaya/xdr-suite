// Package compliance, uç noktanın güvenlik-duruşu uyum sinyallerini toplar
// (ör. disk şifreleme durumu). OS-özel sorgular exec ile yapılır; ayrıştırma
// mantığı platform-bağımsız ve test edilebilir tutulur. Gerçek OS sorgusu
// (quarantine/discovery gibi) bu ortamda canlı doğrulanmaz — mantık testlidir,
// OS-derlenir.
package compliance

import "strings"

// Uyum durum değerleri (disk şifreleme + güvenlik duvarı ortak "on/off/unknown").
const (
	EncOn      = "on"
	EncOff     = "off"
	EncUnknown = "unknown"

	FwOn      = "on"
	FwOff     = "off"
	FwUnknown = "unknown"
)

// Checker, OS-özel uyum sorgularını sağlar.
type Checker interface {
	// DiskEncryption, sistem diskinin şifreleme durumunu döner ("on"/"off"/"unknown").
	DiskEncryption() string
	// Firewall, OS güvenlik duvarının durumunu döner ("on"/"off"/"unknown").
	// Herhangi bir profil/kural kapalıysa "off" (uyum ihlali) sayılır.
	Firewall() string
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

// parseNetshFirewall, Windows `netsh advfirewall show allprofiles state` çıktısını
// yorumlar. Çıktıda her profil (Domain/Private/Public) için "State ON/OFF" satırı
// bulunur. Herhangi bir profil KAPALIYSA "off" (uyum ihlali); tüm bilinen
// profiller açıksa "on"; hiç durum satırı yoksa "unknown".
func parseNetshFirewall(out string) string {
	lo := strings.ToLower(out)
	sawOn := false
	for _, line := range strings.Split(lo, "\n") {
		l := strings.TrimSpace(line)
		if !strings.HasPrefix(l, "state") && !strings.HasPrefix(l, "durum") {
			continue
		}
		// "kapal"/"aç": Türkçe büyük-ı (İ/I) küçültme belirsizliğinden bağımsız
		// (ToLower "KAPALI"→"kapali", "AÇIK"→"açik") kararlı alt-diziler.
		if strings.Contains(l, "off") || strings.Contains(l, "kapal") {
			return FwOff
		}
		if strings.Contains(l, "on") || strings.Contains(l, "aç") {
			sawOn = true
		}
	}
	if sawOn {
		return FwOn
	}
	return FwUnknown
}

// parseUfwStatus, Linux `ufw status` çıktısını yorumlar: "Status: active" → on,
// "Status: inactive" → off. Tanınmazsa unknown.
func parseUfwStatus(out string) string {
	lo := strings.ToLower(out)
	switch {
	case strings.Contains(lo, "status: active"):
		return FwOn
	case strings.Contains(lo, "status: inactive"):
		return FwOff
	default:
		return FwUnknown
	}
}
