// Package policypush, politika değişikliklerinin açık AgentService.StreamPolicies
// akışlarına ANINDA itilmesi için per-cihaz bir yayın/abone (pub/sub) sağlar.
//
// Admin bir cihaza politika atadığında Publish(deviceID) çağrılır; o cihazın
// açık akışı uyanır ve güncel paketi gönderir (heartbeat'i beklemeden).
package policypush

import "sync"

// Notifier, per-cihaz bildirim aboneliklerini yönetir.
type Notifier struct {
	mu     sync.Mutex
	subs   map[string]map[int]chan struct{}
	nextID int
}

// New oluşturur.
func New() *Notifier {
	return &Notifier{subs: make(map[string]map[int]chan struct{})}
}

// Subscribe, bir cihaz için bildirim kanalı açar. Dönen fonksiyon aboneliği
// kapatır (akış sonlandığında çağrılmalı). Kanal tamponlu (1) ve birleştiricidir:
// bekleyen bir bildirim varken gelen yenileri düşürür (coalesce).
func (n *Notifier) Subscribe(deviceID string) (<-chan struct{}, func()) {
	n.mu.Lock()
	defer n.mu.Unlock()
	ch := make(chan struct{}, 1)
	id := n.nextID
	n.nextID++
	if n.subs[deviceID] == nil {
		n.subs[deviceID] = make(map[int]chan struct{})
	}
	n.subs[deviceID][id] = ch

	cancel := func() {
		n.mu.Lock()
		defer n.mu.Unlock()
		if m := n.subs[deviceID]; m != nil {
			delete(m, id)
			if len(m) == 0 {
				delete(n.subs, deviceID)
			}
		}
	}
	return ch, cancel
}

// Publish, cihazın tüm açık abonelerini uyandırır (bloklamaz).
func (n *Notifier) Publish(deviceID string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	for _, ch := range n.subs[deviceID] {
		select {
		case ch <- struct{}{}:
		default: // zaten bekleyen bildirim var; birleştir
		}
	}
}

// SubscriberCount, bir cihazın açık abone sayısıdır (test/gözlem için).
func (n *Notifier) SubscriberCount(deviceID string) int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return len(n.subs[deviceID])
}
