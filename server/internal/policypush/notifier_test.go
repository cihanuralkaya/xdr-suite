package policypush

import "testing"

func TestPublishWakesSubscriber(t *testing.T) {
	n := New()
	ch, cancel := n.Subscribe("dev-1")
	defer cancel()

	n.Publish("dev-1")
	select {
	case <-ch:
	default:
		t.Fatal("publish aboneyi uyandırmalıydı")
	}
}

func TestPublishCoalesces(t *testing.T) {
	n := New()
	ch, cancel := n.Subscribe("dev-1")
	defer cancel()

	n.Publish("dev-1")
	n.Publish("dev-1") // ikincisi birleşmeli (tampon 1)
	<-ch
	select {
	case <-ch:
		t.Fatal("iki publish tek bekleyen bildirime birleşmeliydi")
	default:
	}
}

func TestPublishOtherDeviceIgnored(t *testing.T) {
	n := New()
	ch, cancel := n.Subscribe("dev-1")
	defer cancel()

	n.Publish("dev-2")
	select {
	case <-ch:
		t.Fatal("başka cihaza publish bu aboneyi uyandırmamalı")
	default:
	}
}

func TestCancelUnsubscribes(t *testing.T) {
	n := New()
	_, cancel := n.Subscribe("dev-1")
	if n.SubscriberCount("dev-1") != 1 {
		t.Fatal("bir abone beklenirdi")
	}
	cancel()
	if n.SubscriberCount("dev-1") != 0 {
		t.Fatal("cancel aboneyi kaldırmalıydı")
	}
}
