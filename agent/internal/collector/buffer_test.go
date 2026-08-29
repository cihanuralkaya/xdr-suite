package collector

import "testing"

func TestSequenceMonotonic(t *testing.T) {
	b := NewBuffer(100)
	s1 := b.Add(Event{Message: "a"})
	s2 := b.Add(Event{Message: "b"})
	if s1 != 1 || s2 != 2 {
		t.Fatalf("sıra numaraları 1,2 olmalı: %d,%d", s1, s2)
	}
}

func TestAckDropsUpToSeq(t *testing.T) {
	b := NewBuffer(100)
	for i := 0; i < 5; i++ {
		b.Add(Event{Message: "e"})
	}
	// İlk 3'ü onayla.
	if removed := b.Ack(3); removed != 3 {
		t.Fatalf("3 silinmeliydi, %d", removed)
	}
	if b.Len() != 2 {
		t.Fatalf("2 kalmalıydı, %d", b.Len())
	}
	// Kalanların ilki seq=4 olmalı.
	if p := b.Pending(0); len(p) != 2 || p[0].Seq != 4 {
		t.Fatalf("kalan ilk olay seq=4 olmalı: %+v", p)
	}
}

func TestAckUnknownSeqNoop(t *testing.T) {
	b := NewBuffer(100)
	b.Add(Event{})
	b.Add(Event{})
	if removed := b.Ack(0); removed != 0 { // hiçbir şey onaylanmadı
		t.Fatalf("0 silinmeliydi, %d", removed)
	}
	if b.Len() != 2 {
		t.Fatal("hiçbir olay silinmemeliydi")
	}
}

func TestCapacityDropsOldest(t *testing.T) {
	b := NewBuffer(3)
	for i := 0; i < 5; i++ {
		b.Add(Event{Message: "x"})
	}
	if b.Len() != 3 {
		t.Fatalf("kapasite 3 olmalı, %d", b.Len())
	}
	if b.Dropped() != 2 {
		t.Fatalf("2 düşmeliydi, %d", b.Dropped())
	}
	// En yeni 3: seq 3,4,5.
	p := b.Pending(0)
	if p[0].Seq != 3 || p[2].Seq != 5 {
		t.Fatalf("en yeni 3 olay tutulmalı, ilk=%d son=%d", p[0].Seq, p[2].Seq)
	}
}

func TestPendingMaxLimit(t *testing.T) {
	b := NewBuffer(100)
	for i := 0; i < 10; i++ {
		b.Add(Event{})
	}
	if got := b.Pending(4); len(got) != 4 {
		t.Fatalf("Pending(4) 4 dönmeli, %d", len(got))
	}
}
