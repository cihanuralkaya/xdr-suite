package revocation

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"time"
)

// ErrRevoked, sunulan istemci sertifikası iptal listesindeyse döner.
var ErrRevoked = errors.New("revocation: istemci sertifikası iptal edilmiş")

// VerifyPeerCertificate, tls.Config.VerifyPeerCertificate için bir callback
// üretir. TLS zaten zinciri doğruladıktan SONRA çağrılır; leaf sertifikanın
// SHA-256(DER) parmak izini iptal kümesinde arar. İstemci sertifikası
// sunmadıysa (enroll, VerifyClientCertIfGiven) zincir boştur ve izin verilir.
func VerifyPeerCertificate(cache *Cache) func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	return func(_ [][]byte, verifiedChains [][]*x509.Certificate) error {
		if len(verifiedChains) == 0 || len(verifiedChains[0]) == 0 {
			return nil // istemci sertifikası yok (enroll akışı)
		}
		leaf := verifiedChains[0][0]
		sum := sha256.Sum256(leaf.Raw)
		if cache.IsRevoked(sum[:]) {
			return ErrRevoked
		}
		return nil
	}
}

// Source, iptal edilmiş parmak izlerini üreten kalıcılık kaynağıdır.
type Source interface {
	RevokedFingerprints(ctx context.Context) ([][]byte, error)
}

// Refresher, iptal kümesini periyodik olarak kaynaktan tazeler.
type Refresher struct {
	source   Source
	cache    *Cache
	interval time.Duration
	log      func(string)
}

// NewRefresher oluşturur. interval <= 0 ise 60 sn kullanılır.
func NewRefresher(source Source, cache *Cache, interval time.Duration, log func(string)) *Refresher {
	if interval <= 0 {
		interval = 60 * time.Second
	}
	if log == nil {
		log = func(string) {}
	}
	return &Refresher{source: source, cache: cache, interval: interval, log: log}
}

// Run, başlangıçta bir kez ve sonra periyodik olarak tazeler (ctx bitene dek).
func (r *Refresher) Run(ctx context.Context) {
	t := time.NewTicker(r.interval)
	defer t.Stop()
	for {
		if fps, err := r.source.RevokedFingerprints(ctx); err != nil {
			r.log("iptal listesi tazelenemedi: " + err.Error())
		} else {
			r.cache.Replace(fps)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
