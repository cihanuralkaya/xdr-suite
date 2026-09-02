package db

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// MFA (2FA) sırlarının kalıcı depolaması. TOTP sırrı, admins.mfa_secret sütununda
// AES-256-GCM (FieldCipher) ile şifreli tutulur; DB'yi ele geçiren biri sırları
// düz göremez. Şifreleyici bağlı değilse yazma reddedilir (fail-closed).

// SetPendingMFASecret, yöneticinin TOTP sırrını şifreleyip saklar (etkin değil).
func (s *Store) SetPendingMFASecret(ctx context.Context, adminID, secret string) error {
	if s.cipher == nil {
		return errors.New("db: MFA için alan şifreleyici bağlı değil")
	}
	enc, err := s.cipher.EncryptString(secret)
	if err != nil {
		return fmt.Errorf("db: MFA sırrı şifreleme: %w", err)
	}
	const q = `UPDATE admins SET mfa_secret = $2, mfa_enrolled = FALSE WHERE id = $1::uuid`
	if _, err := s.pool.Exec(ctx, q, adminID, enc); err != nil {
		return fmt.Errorf("db: MFA sırrı kaydı: %w", err)
	}
	return nil
}

// LookupMFA, yöneticinin TOTP sırrını (çözülmüş) ve etkin durumunu döner. Sır
// yoksa ("", false, nil).
func (s *Store) LookupMFA(ctx context.Context, adminID string) (string, bool, error) {
	const q = `SELECT mfa_secret, mfa_enrolled FROM admins WHERE id = $1::uuid AND is_active`
	var enc []byte
	var enrolled bool
	err := s.pool.QueryRow(ctx, q, adminID).Scan(&enc, &enrolled)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("db: MFA arama: %w", err)
	}
	if len(enc) == 0 {
		return "", false, nil
	}
	if s.cipher == nil {
		return "", false, errors.New("db: MFA için alan şifreleyici bağlı değil")
	}
	secret, err := s.cipher.DecryptString(enc)
	if err != nil {
		return "", false, fmt.Errorf("db: MFA sırrı çözme: %w", err)
	}
	return secret, enrolled, nil
}

// ActivateMFA, bekleyen (sırrı olan) yöneticinin MFA'sını etkinleştirir.
func (s *Store) ActivateMFA(ctx context.Context, adminID string) error {
	const q = `UPDATE admins SET mfa_enrolled = TRUE WHERE id = $1::uuid AND mfa_secret IS NOT NULL`
	if _, err := s.pool.Exec(ctx, q, adminID); err != nil {
		return fmt.Errorf("db: MFA etkinleştirme: %w", err)
	}
	return nil
}

// DisableMFA, TOTP sırrını siler ve MFA'yı kapatır.
func (s *Store) DisableMFA(ctx context.Context, adminID string) error {
	const q = `UPDATE admins SET mfa_secret = NULL, mfa_enrolled = FALSE WHERE id = $1::uuid`
	if _, err := s.pool.Exec(ctx, q, adminID); err != nil {
		return fmt.Errorf("db: MFA kapatma: %w", err)
	}
	return nil
}
