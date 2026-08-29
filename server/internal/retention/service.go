package retention

import (
	"context"
	"time"
)

// Store, partition DDL işlemlerinin kalıcılık kaynağıdır.
type Store interface {
	ListPartitions(ctx context.Context) ([]time.Time, error)
	CreatePartition(ctx context.Context, monthStart time.Time) error
	DropPartition(ctx context.Context, monthStart time.Time) error
}

// Service, saklama planını hesaplayıp uygular.
type Service struct {
	store         Store
	retentionDays int
	aheadMonths   int
	log           func(string)
}

// NewService oluşturur. retentionDays <= 0 ise 90 (varsayılan) kullanılır.
func NewService(store Store, retentionDays, aheadMonths int, log func(string)) *Service {
	if retentionDays <= 0 {
		retentionDays = 90
	}
	if aheadMonths <= 0 {
		aheadMonths = 2
	}
	if log == nil {
		log = func(string) {}
	}
	return &Service{store: store, retentionDays: retentionDays, aheadMonths: aheadMonths, log: log}
}

// Run, mevcut partition'ları listeler, planı hesaplar ve uygular: önce gelecek
// partition'ları OLUŞTURUR (veri kaybı riski olmadan), sonra süresi dolanları DÜŞÜRÜR.
func (s *Service) Run(ctx context.Context, now time.Time) error {
	existing, err := s.store.ListPartitions(ctx)
	if err != nil {
		return err
	}
	create, drop := PlanPartitions(now, s.retentionDays, s.aheadMonths, existing)

	for _, m := range create {
		if err := s.store.CreatePartition(ctx, m); err != nil {
			return err
		}
		s.log("partition oluşturuldu: " + PartitionName(m))
	}
	for _, m := range drop {
		if err := s.store.DropPartition(ctx, m); err != nil {
			return err
		}
		s.log("saklama süresi doldu, partition düşürüldü: " + PartitionName(m))
	}
	return nil
}
