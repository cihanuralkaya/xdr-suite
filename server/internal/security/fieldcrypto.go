package security

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
)

// FieldCipher, hassas serbest-metin alanlarını (hostname, mac, os_info)
// uygulama katmanında AES-256-GCM ile şifreler. DB'de BYTEA olarak saklanır.
//
// Not: pgcrypto yerine uygulama katmanı tercih edildi — anahtar sunucu RAM'inde
// kalır, DB süreci hiçbir zaman düz metni görmez (inceleme notu). Yüksek hacimli
// event_logs bu yolla ŞİFRELENMEZ; onun gizliliği at-rest (disk/TDE) düzeyindedir.
type FieldCipher struct {
	aead cipher.AEAD
}

// NewFieldCipher, 32 baytlık (AES-256) bir anahtarla cipher oluşturur.
func NewFieldCipher(key []byte) (*FieldCipher, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("security: alan şifreleme anahtarı 32 bayt olmalı, %d verildi", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &FieldCipher{aead: aead}, nil
}

// Encrypt, düz metni şifreler. Çıktı biçimi: nonce || ciphertext(+tag).
// Her çağrıda rastgele nonce üretilir.
func (c *FieldCipher) Encrypt(plaintext []byte) ([]byte, error) {
	nonce := make([]byte, c.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	// Seal, ciphertext'i nonce'un ardına ekler (prefix olarak nonce).
	return c.aead.Seal(nonce, nonce, plaintext, nil), nil
}

// EncryptString, string kolaylık sarmalayıcısıdır.
func (c *FieldCipher) EncryptString(s string) ([]byte, error) {
	return c.Encrypt([]byte(s))
}

// Decrypt, Encrypt ile üretilmiş blob'u çözer.
func (c *FieldCipher) Decrypt(blob []byte) ([]byte, error) {
	ns := c.aead.NonceSize()
	if len(blob) < ns {
		return nil, errors.New("security: şifreli veri nonce boyutundan kısa")
	}
	nonce, ciphertext := blob[:ns], blob[ns:]
	return c.aead.Open(nil, nonce, ciphertext, nil)
}

// DecryptString, çözülen veriyi string olarak döner.
func (c *FieldCipher) DecryptString(blob []byte) (string, error) {
	b, err := c.Decrypt(blob)
	if err != nil {
		return "", err
	}
	return string(b), nil
}
