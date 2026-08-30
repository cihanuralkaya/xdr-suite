// Command gencerts, DEMO/geliştirme için CA ve sunucu TLS materyali üretir.
// Üretim ortamında kullanılmaz; kurulum sihirbazı gerçek PKI sağlar.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

func main() {
	out := "."
	if len(os.Args) > 1 {
		out = os.Args[1]
	}
	if err := os.MkdirAll(out, 0o755); err != nil {
		log.Fatal(err)
	}

	// CA
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must(err)
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "XDR Demo CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	must(err)
	caCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	caKeyDER, _ := x509.MarshalPKCS8PrivateKey(caKey)
	caKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: caKeyDER})

	// Sunucu (hem gRPC ServerName "xdr-c2" hem tarayıcı "localhost").
	caCert, err := x509.ParseCertificate(caDER)
	must(err)
	srvKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must(err)
	srvTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "xdr-c2"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"xdr-c2", "localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.IPv6loopback},
	}
	srvDER, err := x509.CreateCertificate(rand.Reader, srvTmpl, caCert, &srvKey.PublicKey, caKey)
	must(err)
	srvCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srvDER})
	srvKeyDER, _ := x509.MarshalPKCS8PrivateKey(srvKey)
	srvKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: srvKeyDER})

	write(filepath.Join(out, "ca.pem"), caCertPEM)
	write(filepath.Join(out, "ca.key"), caKeyPEM)
	write(filepath.Join(out, "server.pem"), srvCertPEM)
	write(filepath.Join(out, "server.key"), srvKeyPEM)
	log.Printf("sertifikalar üretildi: %s (ca.pem, ca.key, server.pem, server.key)", out)
}

func write(path string, b []byte) {
	must(os.WriteFile(path, b, 0o600))
}
func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
