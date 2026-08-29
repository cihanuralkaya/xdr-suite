package liveness

import (
	"context"
	"time"
)

// PeerGuard, kendi beacon'unu periyodik yazar ve eş sürecin (peer) beacon'unu
// izler; eş beacon'u bayatladıysa (var ama güncellenmiyor) restart callback'ini
// çağırır. Cooldown, art arda yeniden başlatmaları engeller.
type PeerGuard struct {
	self       *Beacon
	peer       *Beacon
	staleAfter time.Duration
	interval   time.Duration
	cooldown   time.Duration
	restart    func()

	now   func() time.Time
	sleep func(time.Duration)
	log   func(string)
}

// Options, PeerGuard ayarlarıdır.
type Options struct {
	StaleAfter time.Duration
	Interval   time.Duration
	Cooldown   time.Duration
	Restart    func()
	Now        func() time.Time
	Sleep      func(time.Duration)
	Log        func(string)
}

// NewPeerGuard oluşturur.
func NewPeerGuard(self, peer *Beacon, o Options) *PeerGuard {
	if o.StaleAfter == 0 {
		o.StaleAfter = 15 * time.Second
	}
	if o.Interval == 0 {
		o.Interval = 3 * time.Second
	}
	if o.Cooldown == 0 {
		o.Cooldown = 30 * time.Second
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Sleep == nil {
		o.Sleep = time.Sleep
	}
	if o.Log == nil {
		o.Log = func(string) {}
	}
	if o.Restart == nil {
		o.Restart = func() {}
	}
	return &PeerGuard{
		self: self, peer: peer,
		staleAfter: o.StaleAfter, interval: o.Interval, cooldown: o.Cooldown,
		restart: o.Restart, now: o.Now, sleep: o.Sleep, log: o.Log,
	}
}

// Run, gözetim döngüsünü çalıştırır (ctx bitene dek).
func (g *PeerGuard) Run(ctx context.Context) {
	var lastRestart time.Time
	haveRestarted := false

	for {
		if ctx.Err() != nil {
			return
		}
		now := g.now()
		_ = g.self.Write(now)

		if last, ok := g.peer.LastSeen(); ok {
			age := now.Sub(last)
			coolOK := !haveRestarted || now.Sub(lastRestart) >= g.cooldown
			if age > g.staleAfter && coolOK {
				g.log("eş süreç bayatladı, yeniden başlatılıyor")
				g.restart()
				lastRestart = now
				haveRestarted = true
			}
		}
		g.sleep(g.interval)
	}
}
