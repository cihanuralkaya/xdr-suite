package security

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"time"
)

// CA, enrollment sırasında ajan CSR'larını imzalayarak kısa ömürlü istemci
// sertifikaları üreten kurum içi sertifika otoritesidir (inceleme #6).
type CA struct {
	cert *x509.Certificate
	key  crypto.Signer
}

// SignedCert, imzalanmış bir istemci sertifikasının sonucudur.
type SignedCert struct {
	CertPEM  []byte
	Serial   *big.Int
	NotAfter time.Time
}

// LoadCA, PEM kodlu CA sertifikası ve özel anahtarından bir CA yükler.
func LoadCA(certPEM, keyPEM []byte) (*CA, error) {
	cert, err := parseCertPEM(certPEM)
	if err != nil {
		return nil, fmt.Errorf("CA sertifikası: %w", err)
	}
	if !cert.IsCA {
		return nil, errors.New("security: verilen sertifika bir CA değil")
	}
	key, err := parsePrivateKeyPEM(keyPEM)
	if err != nil {
		return nil, fmt.Errorf("CA anahtarı: %w", err)
	}
	return &CA{cert: cert, key: key}, nil
}

// SignCSR, ajanın CSR'ını doğrular ve deviceID CN'li, istemci-kimlik-doğrulama
// amaçlı, ttl süreli bir istemci sertifikası imzalar.
func (ca *CA) SignCSR(csrPEM []byte, deviceID string, ttl time.Duration) (*SignedCert, error) {
	block, _ := pem.Decode(csrPEM)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, errors.New("security: geçerli bir CERTIFICATE REQUEST PEM'i değil")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("CSR ayrıştırma: %w", err)
	}
	// CSR'ın kendi imzasını doğrula (istemci özel anahtara sahip mi?).
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("CSR imza doğrulama: %w", err)
	}

	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	notAfter := now.Add(ttl)

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      csr.Subject,
		// Kimliği SUNUCU belirler: CN daima atanan device_id olur; CSR'daki
		// Subject alanlarına güvenilmez.
		NotBefore:   now.Add(-1 * time.Minute), // küçük saat kayması toleransı
		NotAfter:    notAfter,
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	tmpl.Subject.CommonName = deviceID

	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, csr.PublicKey, ca.key)
	if err != nil {
		return nil, fmt.Errorf("sertifika oluşturma: %w", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return &SignedCert{CertPEM: certPEM, Serial: serial, NotAfter: notAfter}, nil
}

func parseCertPEM(p []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(p)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("CERTIFICATE PEM bloğu bulunamadı")
	}
	return x509.ParseCertificate(block.Bytes)
}

func parsePrivateKeyPEM(p []byte) (crypto.Signer, error) {
	block, _ := pem.Decode(p)
	if block == nil {
		return nil, errors.New("PEM bloğu bulunamadı")
	}
	// PKCS#8, EC ve PKCS#1 formatlarını sırayla dene.
	if k, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		if s, ok := k.(crypto.Signer); ok {
			return s, nil
		}
		return nil, errors.New("özel anahtar crypto.Signer değil")
	}
	if k, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return k, nil
	}
	if k, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return k, nil
	}
	return nil, errors.New("desteklenen özel anahtar formatı çözülemedi (PKCS#8/EC/PKCS#1)")
}

func randomSerial() (*big.Int, error) {
	// 128-bit rastgele seri numarası.
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, fmt.Errorf("seri numarası üretimi: %w", err)
	}
	return serial, nil
}
