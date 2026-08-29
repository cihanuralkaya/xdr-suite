package db

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/types/known/timestamppb"

	xdrv1 "xdr.corp/suite/gen/xdr/v1"
)

// CurrentPolicy, cihaza atanmış aktif politikayı proto PolicyBundle olarak kurar.
// Atanmış politika yoksa (nil, nil) döner.
func (s *Store) CurrentPolicy(ctx context.Context, deviceID string) (*xdrv1.PolicyBundle, error) {
	const pq = `
		SELECT p.id::text, p.version
		  FROM device_policies dp
		  JOIN policies p ON p.id = dp.policy_id
		 WHERE dp.device_id = $1 AND p.is_active
		 ORDER BY p.updated_at DESC
		 LIMIT 1`
	var policyID, version string
	err := s.pool.QueryRow(ctx, pq, deviceID).Scan(&policyID, &version)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("db: politika sorgusu: %w", err)
	}

	const rq = `
		SELECT id::text, type, target_value,
		       COALESCE(to_char(start_time, 'HH24:MI'), ''),
		       COALESCE(to_char(end_time,   'HH24:MI'), ''),
		       active_days
		  FROM policy_rules
		 WHERE policy_id = $1
		 ORDER BY created_at`
	rows, err := s.pool.Query(ctx, rq, policyID)
	if err != nil {
		return nil, fmt.Errorf("db: kural sorgusu: %w", err)
	}
	defer rows.Close()

	var rules []*xdrv1.PolicyRule
	for rows.Next() {
		var id, typ, target, st, et string
		var days []int32
		if err := rows.Scan(&id, &typ, &target, &st, &et, &days); err != nil {
			return nil, fmt.Errorf("db: kural okuma: %w", err)
		}
		ad := make([]uint32, 0, len(days))
		for _, d := range days {
			if d >= 0 {
				ad = append(ad, uint32(d))
			}
		}
		rules = append(rules, &xdrv1.PolicyRule{
			RuleId:      id,
			Type:        ruleTypeToProto(typ),
			TargetValue: target,
			StartTime:   st,
			EndTime:     et,
			ActiveDays:  ad,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("db: kural iterasyonu: %w", err)
	}

	return &xdrv1.PolicyBundle{
		PolicyVersion: version,
		Rules:         rules,
		IssuedAt:      timestamppb.Now(),
	}, nil
}

func ruleTypeToProto(t string) xdrv1.PolicyRule_RuleType {
	switch t {
	case "APP_TIME_BLOCK":
		return xdrv1.PolicyRule_RULE_TYPE_APP_TIME_BLOCK
	case "APP_BLOCK_ALWAYS":
		return xdrv1.PolicyRule_RULE_TYPE_APP_BLOCK_ALWAYS
	case "NETWORK_RULE":
		return xdrv1.PolicyRule_RULE_TYPE_NETWORK_RULE
	default:
		return xdrv1.PolicyRule_RULE_TYPE_UNSPECIFIED
	}
}
