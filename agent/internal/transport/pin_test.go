package transport

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

// testCert, kendinden imzalı bir sertifika + PEM üretir.
func testCert(t *testing.T) (*x509.Certificate, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestSPKIPinningVerifier(t *testing.T) {
	t.Cleanup(func() { SetServerPins(nil) }) // global durumu geri al

	cert, certPEM := testCert(t)
	otherCert, _ := testCert(t)

	pin, err := ComputeSPKIPin(certPEM)
	if err != nil {
		t.Fatal(err)
	}
	if pin == "" {
		t.Fatal("pin boş")
	}

	// Pin ayarlı değil → pinning devre dışı (verifier nil).
	SetServerPins(nil)
	if pinVerifier() != nil {
		t.Fatal("pin ayarlı değilken verifier nil olmalı")
	}

	// Doğru pin → eşleşen yaprak kabul edilir.
	SetServerPins([]string{pin})
	v := pinVerifier()
	if v == nil {
		t.Fatal("pin ayarlıyken verifier olmalı")
	}
	if err := v(tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}); err != nil {
		t.Fatalf("eşleşen sertifika kabul edilmeliydi: %v", err)
	}
	// Uyuşmayan sertifika → reddedilir.
	if err := v(tls.ConnectionState{PeerCertificates: []*x509.Certificate{otherCert}}); err == nil {
		t.Fatal("uyuşmayan sertifika reddedilmeliydi")
	}
	// Sertifika sunulmadı → reddedilir.
	if err := v(tls.ConnectionState{}); err == nil {
		t.Fatal("boş sertifika zinciri reddedilmeliydi")
	}

	// Rotasyon: birden çok pin, biri eşleşirse kabul.
	SetServerPins([]string{"eskimis-pin-degeri", pin})
	if err := pinVerifier()(tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}); err != nil {
		t.Fatalf("rotasyon pin listesinde eşleşme kabul edilmeliydi: %v", err)
	}
}

func TestComputeSPKIPinRejectsBadPEM(t *testing.T) {
	if _, err := ComputeSPKIPin([]byte("bu PEM değil")); err == nil {
		t.Fatal("geçersiz PEM reddedilmeliydi")
	}
}
