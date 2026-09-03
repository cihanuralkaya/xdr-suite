package transport

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
)

// Sunucu sertifikası SPKI pinning (HPKP tarzı). CA doğrulamasının ÜSTÜNE, sunucu
// yaprak sertifikasının açık-anahtar (SubjectPublicKeyInfo) SHA-256 özetini
// beklenen pin(ler)e karşı doğrular. Böylece ele geçirilmiş/yanlış-ibraz eden bir
// CA'nın ürettiği geçerli-zincirli sahte sertifika bile REDDEDİLİR (savunma
// derinliği). Pin ayarlı değilse pinning devre dışıdır (geriye dönük uyumlu).
//
// Anahtar rotasyonu için birden çok pin verilebilir (yeni + eski anahtar);
// herhangi biri eşleşirse kabul edilir.

var serverPins atomic.Pointer[[]string]

// SetServerPins, sunucu SPKI pinlerini ayarlar (base64 SHA-256 değerleri). Boş
// liste pinning'i kapatır. Ajan başlangıcında bir kez çağrılır.
func SetServerPins(pins []string) {
	clean := make([]string, 0, len(pins))
	for _, p := range pins {
		if p = strings.TrimSpace(p); p != "" {
			clean = append(clean, p)
		}
	}
	serverPins.Store(&clean)
}

// pinVerifier, ayarlı pin varsa bir tls.VerifyConnection callback'i döner; yoksa
// nil (TLS nil callback'i yok sayar → pinning devre dışı).
func pinVerifier() func(tls.ConnectionState) error {
	p := serverPins.Load()
	if p == nil || len(*p) == 0 {
		return nil
	}
	pins := *p
	return func(cs tls.ConnectionState) error {
		if len(cs.PeerCertificates) == 0 {
			return errors.New("pin: sunucu sertifikası sunulmadı")
		}
		got := spkiPin(cs.PeerCertificates[0])
		for _, want := range pins {
			if want == got {
				return nil
			}
		}
		return fmt.Errorf("pin: sunucu SPKI pini eşleşmedi (got=%s)", got)
	}
}

// spkiPin, bir sertifikanın SubjectPublicKeyInfo SHA-256 özetini base64 döner.
func spkiPin(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return base64.StdEncoding.EncodeToString(sum[:])
}

// ComputeSPKIPin, PEM sertifikadan pin değerini üretir (operasyon: pin'i
// yapılandırmak için sunucu sertifikasından hesaplama). Ops eşdeğeri:
// openssl x509 -in server.crt -pubkey -noout | openssl pkey -pubin -outform der |
// openssl dgst -sha256 -binary | openssl base64
func ComputeSPKIPin(certPEM []byte) (string, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return "", errors.New("pin: geçersiz PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("pin: sertifika ayrıştırılamadı: %w", err)
	}
	return spkiPin(cert), nil
}
