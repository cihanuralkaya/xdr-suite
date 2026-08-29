package security

import (
	"crypto/sha256"
	"encoding/pem"
)

// CertFingerprint, PEM kodlu bir sertifikanın SHA-256(DER) parmak izini döner.
// PEM çözülemezse ham girdinin hash'ini döner (deterministik davranış).
func CertFingerprint(certPEM []byte) []byte {
	block, _ := pem.Decode(certPEM)
	if block != nil {
		sum := sha256.Sum256(block.Bytes)
		return sum[:]
	}
	sum := sha256.Sum256(certPEM)
	return sum[:]
}
