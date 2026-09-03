// Package osinfo, uç noktanın okunabilir OS sürümünü tespit eder (filo envanteri).
// OS-özel sorgular (Linux /etc/os-release, Windows `ver`) build-tag'li dosyalarda;
// ayrıştırma mantığı platform-bağımsız ve test edilebilir tutulur. Gerçek OS
// sorgusu (compliance/discovery gibi) bu ortamda canlı doğrulanmaz — mantık testlidir.
package osinfo

import "strings"

// parseOSRelease, Linux /etc/os-release içeriğinden PRETTY_NAME değerini çıkarır.
func parseOSRelease(content string) string {
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "PRETTY_NAME=") {
			return strings.Trim(strings.TrimPrefix(line, "PRETTY_NAME="), "\"")
		}
	}
	return ""
}

// parseWinVer, Windows `cmd /c ver` çıktısından sürümü çıkarır. Örn:
// "Microsoft Windows [Version 10.0.19045.5011]" -> "Windows 10.0.19045.5011".
func parseWinVer(out string) string {
	out = strings.TrimSpace(out)
	if i := strings.Index(out, "[Version "); i >= 0 {
		rest := out[i+len("[Version "):]
		if j := strings.IndexByte(rest, ']'); j >= 0 {
			return "Windows " + strings.TrimSpace(rest[:j])
		}
	}
	return strings.TrimSpace(strings.ReplaceAll(out, "\r\n", " "))
}
