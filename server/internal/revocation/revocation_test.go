package revocation

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

func TestCacheReplaceAndCheck(t *testing.T) {
	c := NewCache()
	fp := []byte("parmak-izi-1")
	if c.IsRevoked(fp) {
		t.Fatal("boş kümede iptal olmamalı")
	}
	c.Replace([][]byte{fp, []byte("baska")})
	if !c.IsRevoked(fp) {
		t.Fatal("eklenen parmak izi iptal olmalı")
	}
	if c.Size() != 2 {
		t.Fatalf("2 giriş beklenirdi, %d", c.Size())
	}
	// Replace atomik değiştirir: eski gider.
	c.Replace(nil)
	if c.IsRevoked(fp) {
		t.Fatal("Replace(nil) kümeyi temizlemeliydi")
	}
}

func makeLeaf(t *testing.T) *x509.Certificate {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(7),
		Subject:      pkix.Name{CommonName: "dev-1"},
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
	return cert
}

func TestVerifyPeerCertificate(t *testing.T) {
	cache := NewCache()
	verify := VerifyPeerCertificate(cache)
	leaf := makeLeaf(t)
	chains := [][]*x509.Certificate{{leaf}}

	// İptal edilmemişken izin verilmeli.
	if err := verify(nil, chains); err != nil {
		t.Fatalf("iptal edilmemiş sertifika reddedildi: %v", err)
	}
	// İptal edilince reddedilmeli.
	sum := sha256.Sum256(leaf.Raw)
	cache.Replace([][]byte{sum[:]})
	if err := verify(nil, chains); err != ErrRevoked {
		t.Fatalf("iptal edilmiş sertifika ErrRevoked dönmeliydi, dönen: %v", err)
	}
	// İstemci sertifikası yoksa (enroll) izin verilmeli.
	if err := verify(nil, nil); err != nil {
		t.Fatalf("sertifikasız bağlantı reddedilmemeli: %v", err)
	}
}

type fakeSource struct{ fps [][]byte }

func (f fakeSource) RevokedFingerprints(context.Context) ([][]byte, error) { return f.fps, nil }

func TestRefresherPopulatesCache(t *testing.T) {
	cache := NewCache()
	r := NewRefresher(fakeSource{fps: [][]byte{[]byte("a"), []byte("b")}}, cache, time.Hour, nil)
	ctx, cancel := context.WithCancel(context.Background())
	// Bir tazeleme turu için: goroutine'de çalıştır, kısa bekle... yerine
	// ilk turu senkron yapmak adına Run'ı goroutine + hemen iptal.
	go r.Run(ctx)
	// İlk tazeleme Run başında senkron yapılır; kısa bir bekleme yeterli.
	deadline := time.Now().Add(time.Second)
	for cache.Size() < 2 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	if cache.Size() != 2 {
		t.Fatalf("refresher kümeyi doldurmalıydı, %d", cache.Size())
	}
}
