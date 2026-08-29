package security

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"strconv"
	"strings"
	"time"
)

// LabelSessionToken, oturum imzalama alt anahtarı için KDF etiketidir.
const LabelSessionToken = "xdr:admin-session:v1"

// SessionSigner, durumsuz (stateless) admin oturum token'ları üretir/doğrular.
// Token = base64(payload) "." base64(HMAC(payload)); payload = "adminID|expiryUnix".
// Sunucu tarafında oturum saklamaya gerek yoktur; HMAC bütünlüğü yeterlidir.
type SessionSigner struct {
	key []byte
}

// NewSessionSigner, verilen anahtarla imzalayıcı oluşturur (ana anahtardan
// DeriveKey(master, LabelSessionToken) ile türetilmeli).
func NewSessionSigner(key []byte) *SessionSigner {
	k := make([]byte, len(key))
	copy(k, key)
	return &SessionSigner{key: k}
}

// Sign, adminID için exp'e kadar geçerli bir oturum token'ı üretir.
func (s *SessionSigner) Sign(adminID string, exp time.Time) string {
	payload := adminID + "|" + strconv.FormatInt(exp.Unix(), 10)
	mac := s.mac(payload)
	return base64.RawURLEncoding.EncodeToString([]byte(payload)) + "." +
		base64.RawURLEncoding.EncodeToString(mac)
}

// Verify, token'ı doğrular ve adminID'yi döner. İmza geçersiz veya süresi
// geçmişse ok=false döner.
func (s *SessionSigner) Verify(token string, now time.Time) (string, bool) {
	dot := strings.IndexByte(token, '.')
	if dot < 0 {
		return "", false
	}
	payloadB, err := base64.RawURLEncoding.DecodeString(token[:dot])
	if err != nil {
		return "", false
	}
	macB, err := base64.RawURLEncoding.DecodeString(token[dot+1:])
	if err != nil {
		return "", false
	}
	payload := string(payloadB)
	if !hmac.Equal(macB, s.mac(payload)) {
		return "", false
	}
	sep := strings.LastIndexByte(payload, '|')
	if sep < 0 {
		return "", false
	}
	expUnix, err := strconv.ParseInt(payload[sep+1:], 10, 64)
	if err != nil || now.Unix() >= expUnix {
		return "", false
	}
	return payload[:sep], true
}

func (s *SessionSigner) mac(payload string) []byte {
	m := hmac.New(sha256.New, s.key)
	m.Write([]byte(payload))
	return m.Sum(nil)
}
