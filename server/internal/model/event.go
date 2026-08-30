// Package model, transport (grpc) ve depolama (db) katmanlarının paylaştığı
// nötr domain tiplerini barındırır. Böylece db, transport paketine bağımlı
// olmadan aynı tipleri kullanabilir (bağımlılık yönü tek taraflı kalır).
package model

import "time"

// Event, kalıcılaştırılacak bir olayın transport-bağımsız biçimidir.
type Event struct {
	Sequence   uint64
	Category   string
	Severity   string
	Message    string
	OccurredAt time.Time
	// Details, olaya iliştirilen yapılandırılmış ek veridir (serbest biçimli JSON
	// nesnesi). Boş string, ayrıntı olmadığını belirtir (DB'de NULL saklanır).
	Details string
}
