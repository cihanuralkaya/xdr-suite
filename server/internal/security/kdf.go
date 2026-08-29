package security

import (
	"crypto/hmac"
	"crypto/sha256"
)

// KDF etiketleri — ana anahtardan amaç-ayrımlı alt anahtarlar türetir.
const (
	LabelFieldEncryption = "xdr:field-encryption:v1"
	LabelBlindIndex      = "xdr:blind-index:v1"
)

// DeriveKey, ana anahtardan (master key) belirli bir amaç için 32 baytlık bir
// alt anahtar türetir. Aynı ana anahtarın farklı amaçlar için farklı, birbirine
// bağlanamayan anahtarlar üretmesini sağlar (basit HMAC tabanlı KDF).
//
// Ana anahtar sunucu başlangıcında RAM'e alınır; alt anahtarlar diske yazılmaz.
func DeriveKey(master []byte, label string) []byte {
	m := hmac.New(sha256.New, master)
	m.Write([]byte(label))
	return m.Sum(nil) // 32 bayt
}
