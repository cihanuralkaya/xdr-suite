package anomaly

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
)

const sampleModelJSON = `{"feature_mean":[0.1,14,5,2],"feature_std":[0.1,3,2,1],
  "layers":[{"weights":[[0,0,2,0]],"bias":[-3],"activation":"sigmoid"}]}`

func writeModelAndSig(t *testing.T, dir string, data, sig []byte) string {
	t.Helper()
	mp := filepath.Join(dir, "model.json")
	if err := os.WriteFile(mp, data, 0o644); err != nil {
		t.Fatal(err)
	}
	if sig != nil {
		if err := os.WriteFile(mp+".sig", []byte(base64.StdEncoding.EncodeToString(sig)), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return mp
}

// LoadModelSigned: geçerli imza yüklenir; kurcalanmış model/imza reddedilir;
// imza dosyası yoksa reddedilir (fail-closed).
func TestLoadModelSignedVerifies(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	data := []byte(sampleModelJSON)
	sig := ed25519.Sign(priv, data)
	dir := t.TempDir()

	// Geçerli imza → yüklenir + skorlar.
	mp := writeModelAndSig(t, dir, data, sig)
	m, err := LoadModelSigned(mp, pub)
	if err != nil {
		t.Fatalf("geçerli imzalı model yüklenmeliydi: %v", err)
	}
	if m.Score(Features{Values: []float32{0.1, 14, 50, 2}}) < 0.8 {
		t.Fatal("yüklenen model beklenen gibi skorlamadı")
	}

	// Kurcalanmış model (imza aynı) → reddedilir.
	tampered := append([]byte(nil), data...)
	tampered[len(tampered)-3] ^= 0x20
	mp2 := writeModelAndSig(t, t.TempDir(), tampered, sig)
	if _, err := LoadModelSigned(mp2, pub); err == nil {
		t.Fatal("kurcalanmış model reddedilmeliydi")
	}

	// Yanlış anahtar → reddedilir.
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := LoadModelSigned(mp, otherPub); err == nil {
		t.Fatal("yanlış public key ile reddedilmeliydi")
	}

	// İmza dosyası yok → reddedilir (fail-closed).
	mpNoSig := writeModelAndSig(t, t.TempDir(), data, nil)
	if _, err := LoadModelSigned(mpNoSig, pub); err == nil {
		t.Fatal("imza dosyası yokken reddedilmeliydi")
	}
}
