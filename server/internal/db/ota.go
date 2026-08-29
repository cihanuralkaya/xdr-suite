package db

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	xdrv1 "xdr.corp/suite/gen/xdr/v1"
)

// LatestUpdate, platform için en güncel yayımlanmış sürümü döner. Ajanın
// mevcut sürümüyle aynıysa "güncelleme yok" döner. Manifesto DB'de saklanan
// İMZAYI taşır (imzalama offline yapılır, bkz. tools/otasign).
func (s *Store) LatestUpdate(ctx context.Context, deviceID, currentVersion, platform string) (*xdrv1.UpdateManifest, error) {
	const q = `
		SELECT version, download_url, sha256_hex, signature, mandatory, rollout_percent
		  FROM ota_releases
		 WHERE os_platform = $1
		 ORDER BY published_at DESC
		 LIMIT 1`
	var (
		version, url, sha string
		signature         []byte
		mandatory         bool
		rollout           int32
	)
	err := s.pool.QueryRow(ctx, q, platform).Scan(&version, &url, &sha, &signature, &mandatory, &rollout)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("db: güncelleme sorgusu: %w", err)
	}
	if version == currentVersion {
		return &xdrv1.UpdateManifest{UpdateAvailable: false}, nil
	}
	return &xdrv1.UpdateManifest{
		UpdateAvailable: true,
		TargetVersion:   version,
		DownloadUrl:     url,
		Sha256Hex:       sha,
		Signature:       signature,
		Mandatory:       mandatory,
		RolloutPercent:  uint32(rollout),
	}, nil
}
