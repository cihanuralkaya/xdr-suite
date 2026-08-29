package db

import (
	"context"
	"fmt"

	"xdr.corp/suite/server/internal/revocation"
)

// Derleme-zamanı arayüz kontrolü.
var _ revocation.Source = (*Store)(nil)

// RevokedFingerprints, iptal edilmiş (revoked_at dolu) sertifikaların
// SHA-256(DER) parmak izlerini döner.
func (s *Store) RevokedFingerprints(ctx context.Context) ([][]byte, error) {
	const q = `SELECT fingerprint FROM agent_certificates WHERE revoked_at IS NOT NULL`
	rows, err := s.pool.Query(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("db: iptal listesi: %w", err)
	}
	defer rows.Close()

	var out [][]byte
	for rows.Next() {
		var fp []byte
		if err := rows.Scan(&fp); err != nil {
			return nil, err
		}
		out = append(out, fp)
	}
	return out, rows.Err()
}

// RevokeDeviceCerts, bir cihazın geçerli tüm sertifikalarını iptal işaretler
// (admin aksiyonu). İptal, tazeleme turunda mTLS reddine yansır.
func (s *Store) RevokeDeviceCerts(ctx context.Context, deviceID, reason string) error {
	const q = `
		UPDATE agent_certificates
		   SET revoked_at = now(), revoke_reason = NULLIF($2,'')
		 WHERE device_id = $1 AND revoked_at IS NULL`
	if _, err := s.pool.Exec(ctx, q, deviceID, reason); err != nil {
		return fmt.Errorf("db: sertifika iptali: %w", err)
	}
	return nil
}
