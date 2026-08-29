package discovery

import (
	"strings"
)

// NormalizeMAC, MAC adresini kanonik biçime getirir (küçük harf, iki nokta
// ayraç). 48-bit olmayan girdileri kırpılmış küçük harf olarak döner.
func NormalizeMAC(mac string) string {
	var hex strings.Builder
	for _, r := range mac {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'f':
			hex.WriteRune(r)
		case r >= 'A' && r <= 'F':
			hex.WriteRune(r + ('a' - 'A'))
		}
	}
	h := hex.String()
	if len(h) != 12 {
		return strings.ToLower(strings.TrimSpace(mac))
	}
	var out strings.Builder
	for i := 0; i < len(h); i += 2 {
		if i > 0 {
			out.WriteByte(':')
		}
		out.WriteString(h[i : i+2])
	}
	return out.String()
}

// isBroadcastOrMulticast, yayın/çok-noktalı veya boş MAC'leri filtreler.
func isBroadcastOrMulticast(mac string) bool {
	if mac == "" || mac == "ff:ff:ff:ff:ff:ff" || mac == "00:00:00:00:00:00" {
		return true
	}
	// İlk baytın en düşük biti 1 ise multicast.
	if len(mac) >= 2 {
		if b := fromHex(mac[0])*16 + fromHex(mac[1]); b >= 0 && b&1 == 1 {
			return true
		}
	}
	return false
}

func fromHex(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10
	case c >= 'A' && c <= 'F':
		return int(c-'A') + 10
	}
	return -1
}

// ParseWindowsARP, Windows `arp -a` çıktısını ayrıştırır. Yayın/çok-noktalı
// adresleri atlar.
//
// Örnek satır: "  192.168.1.1           aa-bb-cc-dd-ee-ff     dynamic"
func ParseWindowsARP(text string) []Host {
	var hosts []Host
	for _, line := range strings.Split(text, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		ip := fields[0]
		if !looksLikeIPv4(ip) {
			continue
		}
		mac := NormalizeMAC(fields[1])
		if len(mac) != 17 || isBroadcastOrMulticast(mac) {
			continue
		}
		hosts = append(hosts, Host{MAC: mac, IP: ip})
	}
	return hosts
}

// ParseProcNetARP, Linux /proc/net/arp içeriğini ayrıştırır.
// Sütunlar: IPaddress HWtype Flags HWaddress Mask Device
func ParseProcNetARP(text string) []Host {
	var hosts []Host
	lines := strings.Split(text, "\n")
	for i, line := range lines {
		if i == 0 { // başlık satırı
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		ip := fields[0]
		mac := NormalizeMAC(fields[3])
		if !looksLikeIPv4(ip) || len(mac) != 17 || isBroadcastOrMulticast(mac) {
			continue
		}
		hosts = append(hosts, Host{MAC: mac, IP: ip})
	}
	return hosts
}

func looksLikeIPv4(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		if p == "" || len(p) > 3 {
			return false
		}
		for _, c := range p {
			if c < '0' || c > '9' {
				return false
			}
		}
	}
	return true
}
