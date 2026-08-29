package db

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"xdr.corp/suite/server/internal/admin"
	"xdr.corp/suite/server/internal/adminapi"
)

// Derleme-zamanı arayüz kontrolleri.
var (
	_ admin.Store        = (*Store)(nil)
	_ adminapi.AuthStore = (*Store)(nil)
)

// LookupAdmin, e-postadan yönetici id'si ve parola hash'ini çözer (adminapi auth).
func (s *Store) LookupAdmin(ctx context.Context, email string) (string, string, error) {
	const q = `SELECT id::text, COALESCE(password_hash, '') FROM admins WHERE email = $1 AND is_active`
	var id, hash string
	err := s.pool.QueryRow(ctx, q, email).Scan(&id, &hash)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", "", nil
	}
	if err != nil {
		return "", "", fmt.Errorf("db: admin arama: %w", err)
	}
	return id, hash, nil
}

// AdminRole, yöneticinin rolünü döner. Bilinmeyen/pasif admin için boş rol
// (yetkisiz) döner.
func (s *Store) AdminRole(ctx context.Context, adminID string) (admin.Role, error) {
	const q = `SELECT role FROM admins WHERE id = $1 AND is_active`
	var r string
	err := s.pool.QueryRow(ctx, q, adminID).Scan(&r)
	if errors.Is(err, pgx.ErrNoRows) {
		return admin.Role(""), nil
	}
	if err != nil {
		return "", fmt.Errorf("db: admin rolü: %w", err)
	}
	return admin.Role(r), nil
}

// SaveEnrollmentToken, admin tarafından üretilen token'ın HMAC indeksini saklar.
func (s *Store) SaveEnrollmentToken(ctx context.Context, tokenIndex []byte, createdBy string, expiresAt time.Time) error {
	const q = `
		INSERT INTO enrollment_tokens (token_hash, created_by, expires_at)
		VALUES ($1, NULLIF($2,'')::uuid, $3)`
	_, err := s.pool.Exec(ctx, q, tokenIndex, createdBy, expiresAt)
	if err != nil {
		return fmt.Errorf("db: enrollment token kaydı: %w", err)
	}
	return nil
}

// WriteAudit, değişmez denetim izine bir satır yazar (#10).
func (s *Store) WriteAudit(ctx context.Context, adminID, action, targetType, targetID string) error {
	const q = `
		INSERT INTO audit_log (admin_id, action, target_type, target_id)
		VALUES (NULLIF($1,'')::uuid, $2, NULLIF($3,''), NULLIF($4,'')::uuid)`
	_, err := s.pool.Exec(ctx, q, adminID, action, targetType, targetID)
	if err != nil {
		return fmt.Errorf("db: denetim izi: %w", err)
	}
	return nil
}

// CreatePolicy, yeni bir politika oluşturur ve id'sini döner.
func (s *Store) CreatePolicy(ctx context.Context, name, version string) (string, error) {
	const q = `INSERT INTO policies (name, version) VALUES ($1, $2) RETURNING id::text`
	var id string
	if err := s.pool.QueryRow(ctx, q, name, version).Scan(&id); err != nil {
		return "", fmt.Errorf("db: politika oluşturma: %w", err)
	}
	return id, nil
}

// AssignPolicy, bir politikayı cihaza atar (idempotent).
func (s *Store) AssignPolicy(ctx context.Context, deviceID, policyID string) error {
	const q = `
		INSERT INTO device_policies (device_id, policy_id)
		VALUES ($1, $2)
		ON CONFLICT (device_id, policy_id) DO NOTHING`
	_, err := s.pool.Exec(ctx, q, deviceID, policyID)
	if err != nil {
		return fmt.Errorf("db: politika atama: %w", err)
	}
	return nil
}
