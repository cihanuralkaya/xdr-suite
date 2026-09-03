package db

import (
	"context"
	"fmt"
)

// SetDeviceTags, cihazın etiketlerini (filo gruplama) değiştirir. tags nil ise
// boş diziye normalize edilir (sütun NOT NULL). pgx []string'i text[]'e eşler.
func (s *Store) SetDeviceTags(ctx context.Context, deviceID string, tags []string) error {
	if tags == nil {
		tags = []string{}
	}
	const q = `UPDATE devices SET tags = $2 WHERE id = $1::uuid`
	if _, err := s.pool.Exec(ctx, q, deviceID, tags); err != nil {
		return fmt.Errorf("db: cihaz etiketleri: %w", err)
	}
	return nil
}
