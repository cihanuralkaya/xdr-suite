package liveness

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestBeaconWriteRead(t *testing.T) {
	b := NewBeacon(filepath.Join(t.TempDir(), "x.beacon"))
	if _, ok := b.LastSeen(); ok {
		t.Fatal("yazılmadan LastSeen ok=false olmalı")
	}
	now := time.Unix(1000, 500)
	if err := b.Write(now); err != nil {
		t.Fatal(err)
	}
	got, ok := b.LastSeen()
	if !ok || !got.Equal(now) {
		t.Fatalf("LastSeen yanlış: %v ok=%v", got, ok)
	}
}

type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time          { return c.t }
func (c *fakeClock) advance(d time.Duration) { c.t = c.t.Add(d) }

func TestPeerGuardRestartsOnStale(t *testing.T) {
	dir := t.TempDir()
	self := NewBeacon(filepath.Join(dir, "self.beacon"))
	peer := NewBeacon(filepath.Join(dir, "peer.beacon"))

	clock := &fakeClock{t: time.Unix(0, 0)}
	// Eş, t=0'da canlı bir beacon yazmış; sonra hiç güncellemiyor (bayatlayacak).
	_ = peer.Write(clock.now())

	restarts := 0
	ctx, cancel := context.WithCancel(context.Background())
	iterations := 0

	g := NewPeerGuard(self, peer, Options{
		StaleAfter: 10 * time.Second,
		Interval:   time.Second,
		Cooldown:   1 * time.Hour, // tek restart bekliyoruz
		Restart:    func() { restarts++ },
		Now:        clock.now,
		Sleep: func(time.Duration) {
			clock.advance(time.Second)
			iterations++
			if iterations >= 15 {
				cancel()
			}
		},
	})
	g.Run(ctx)

	if restarts != 1 {
		t.Fatalf("bayatlayan eş için tam 1 yeniden başlatma beklenirdi, %d", restarts)
	}
	// Ajan kendi beacon'unu yazmış olmalı.
	if _, ok := self.LastSeen(); !ok {
		t.Fatal("guard kendi beacon'unu yazmalıydı")
	}
}

func TestPeerGuardNoRestartWhenFresh(t *testing.T) {
	dir := t.TempDir()
	self := NewBeacon(filepath.Join(dir, "self.beacon"))
	peer := NewBeacon(filepath.Join(dir, "peer.beacon"))

	clock := &fakeClock{t: time.Unix(0, 0)}
	restarts := 0
	ctx, cancel := context.WithCancel(context.Background())
	iterations := 0

	g := NewPeerGuard(self, peer, Options{
		StaleAfter: 10 * time.Second,
		Interval:   time.Second,
		Restart:    func() { restarts++ },
		Now:        clock.now,
		Sleep: func(time.Duration) {
			// Her turda eş beacon'u TAZE tut (peer hâlâ canlı).
			_ = peer.Write(clock.now())
			clock.advance(time.Second)
			iterations++
			if iterations >= 15 {
				cancel()
			}
		},
	})
	// İlk kontrolden önce eşi taze yap.
	_ = peer.Write(clock.now())
	g.Run(ctx)

	if restarts != 0 {
		t.Fatalf("taze eş yeniden başlatılmamalı, %d", restarts)
	}
}
