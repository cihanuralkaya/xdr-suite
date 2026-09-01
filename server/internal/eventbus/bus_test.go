package eventbus

import (
	"testing"
	"time"
)

func TestBusDeliversToSubscribers(t *testing.T) {
	b := New()
	ch1, cancel1 := b.Subscribe()
	ch2, cancel2 := b.Subscribe()
	defer cancel1()
	defer cancel2()

	if b.SubscriberCount() != 2 {
		t.Fatalf("2 abone beklenirdi, %d", b.SubscriberCount())
	}

	b.PublishEvent("dev-1", "HIGH", "yasaklı süreç")

	for i, ch := range []<-chan Notice{ch1, ch2} {
		select {
		case n := <-ch:
			if n.Type != "event" || n.DeviceID != "dev-1" || n.Severity != "HIGH" {
				t.Fatalf("abone %d yanlış bildirim aldı: %+v", i, n)
			}
		case <-time.After(time.Second):
			t.Fatalf("abone %d bildirim almadı", i)
		}
	}
}

func TestBusDoesNotBlockOnSlowSubscriber(t *testing.T) {
	b := New()
	_, cancel := b.Subscribe() // hiç okunmayan abone (kanalı dolacak)
	defer cancel()

	// Tampondan çok yayın: bloklamamalı (dolu abone atlanır).
	done := make(chan struct{})
	go func() {
		for i := 0; i < 1000; i++ {
			b.PublishDevice("dev-x")
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("yavaş abone yayıncıyı bloklamamalıydı")
	}
}

func TestBusCancelIsIdempotentAndStopsDelivery(t *testing.T) {
	b := New()
	ch, cancel := b.Subscribe()
	cancel()
	cancel() // ikinci çağrı panik/etki üretmemeli

	if b.SubscriberCount() != 0 {
		t.Fatalf("iptal sonrası abone kalmamalı, %d", b.SubscriberCount())
	}
	// Kanal kapalı olmalı.
	if _, open := <-ch; open {
		t.Fatal("iptal edilen abonenin kanalı kapalı olmalıydı")
	}
	b.PublishEvent("dev-1", "LOW", "x") // panik üretmemeli
}
