// Package certrenew, ajanın kısa-ömürlü istemci sertifikasını süre dolmadan
// yenilemesi için ne zaman yenileneceğini belirler (saf mantık) ve sertifika
// geçerlilik penceresini çözer.
package certrenew

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"time"
)

// ParseValidity, PEM sertifikanın NotBefore/NotAfter değerlerini döner.
func ParseValidity(certPEM []byte) (notBefore, notAfter time.Time, err error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return time.Time{}, time.Time{}, errors.New("certrenew: sertifika PEM'i çözülemedi")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return time.Time{}, time.Time{}, err
	}
	return cert.NotBefore, cert.NotAfter, nil
}

// ShouldRenew, kalan ömür toplam ömrün `fraction`'ından azsa (veya süre dolmuşsa)
// true döner. Örn. fraction=1/3 → ömrün son üçte birinde yenile.
func ShouldRenew(notBefore, notAfter, now time.Time, fraction float64) bool {
	total := notAfter.Sub(notBefore)
	if total <= 0 {
		return true // geçersiz/tersine pencere: yenile
	}
	remaining := notAfter.Sub(now)
	if remaining <= 0 {
		return true // süresi dolmuş
	}
	return remaining <= time.Duration(float64(total)*fraction)
}
