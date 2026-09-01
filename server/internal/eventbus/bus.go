// Package eventbus, ajan-kaynaklı değişiklikleri (yeni olay, cihaz yaşam sinyali)
// admin konsoluna SSE ile iletmek için hafif bir yayın-abone (pub/sub) sağlar.
// Yavaş bir abone yayıncıyı BLOKLAMAZ: kanal doluysa bildirim atlanır (konsol
// zaten periyodik yenileme ile tutarlılığı yakalar).
package eventbus

import (
	"sync"
	"time"
)

// Notice, konsola iletilen hafif değişiklik bildirimidir.
type Notice struct {
	Type     string    `json:"type"` // "event" | "device"
	DeviceID string    `json:"device_id,omitempty"`
	Severity string    `json:"severity,omitempty"`
	Message  string    `json:"message,omitempty"`
	At       time.Time `json:"at"`
}

// Bus, abonelere bildirim yayınlar.
type Bus struct {
	mu   sync.Mutex
	subs map[int]chan Notice
	next int
}

// New, boş bir bus oluşturur.
func New() *Bus { return &Bus{subs: make(map[int]chan Notice)} }

// Subscribe, tamponlu bir bildirim kanalı ve onu kapatan bir iptal fonksiyonu
// döner. İptal idempotenttir.
func (b *Bus) Subscribe() (<-chan Notice, func()) {
	b.mu.Lock()
	defer b.mu.Unlock()
	ch := make(chan Notice, 32)
	id := b.next
	b.next++
	b.subs[id] = ch
	var once sync.Once
	cancel := func() {
		once.Do(func() {
			b.mu.Lock()
			defer b.mu.Unlock()
			if c, ok := b.subs[id]; ok {
				delete(b.subs, id)
				close(c)
			}
		})
	}
	return ch, cancel
}

// publish, bildirimi tüm abonelere bloklamadan iletir.
func (b *Bus) publish(n Notice) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, ch := range b.subs {
		select {
		case ch <- n:
		default: // dolu/yavaş abone: atla
		}
	}
}

// PublishEvent, yeni bir olay bildirir (grpc.AdminNotifier arayüzü).
func (b *Bus) PublishEvent(deviceID, severity, message string) {
	b.publish(Notice{Type: "event", DeviceID: deviceID, Severity: severity, Message: message, At: time.Now().UTC()})
}

// PublishDevice, bir cihazın yaşam sinyali/durum değişimini bildirir.
func (b *Bus) PublishDevice(deviceID string) {
	b.publish(Notice{Type: "device", DeviceID: deviceID, At: time.Now().UTC()})
}

// SubscriberCount, aktif abone sayısını döner (test/gözlem için).
func (b *Bus) SubscriberCount() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.subs)
}
