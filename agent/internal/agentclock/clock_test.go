package agentclock

import (
	"testing"
	"time"
)

// fakeLocal, kontrollü ilerleyen bir yerel saat kaynağıdır.
type fakeLocal struct{ t time.Time }

func (f *fakeLocal) now() time.Time          { return f.t }
func (f *fakeLocal) advance(d time.Duration) { f.t = f.t.Add(d) }

func TestUnsyncedReturnsFalse(t *testing.T) {
	c := New((&fakeLocal{t: time.Unix(1000, 0)}).now)
	if _, ok := c.Now(); ok {
		t.Fatal("senkronize edilmemiş saat ok=true dönmemeli")
	}
}

func TestAdvancesByMonotonicElapsed(t *testing.T) {
	fl := &fakeLocal{t: time.Unix(1000, 0)}
	c := New(fl.now)

	srv := time.Date(2026, 8, 28, 18, 0, 0, 0, time.UTC)
	c.Sync(srv)

	// Yerel saat 30 dk ilerledi.
	fl.advance(30 * time.Minute)
	got, ok := c.Now()
	if !ok {
		t.Fatal("senkronize saat ok=false döndü")
	}
	want := srv.Add(30 * time.Minute)
	if !got.Equal(want) {
		t.Fatalf("Now = %v, beklenen %v", got, want)
	}
}

func TestWallClockJumpDoesNotAffectElapsed(t *testing.T) {
	// Yerel kaynak monotonik gibi davranır: elapsed yalnız advance ile artar.
	// Duvar saatinin geri/ileri atlaması burada anchorLocal-göreli elapsed'i
	// bozmaz çünkü elapsed = localNow - anchorLocal.
	fl := &fakeLocal{t: time.Unix(5000, 0)}
	c := New(fl.now)
	srv := time.Date(2026, 8, 28, 20, 0, 0, 0, time.UTC)
	c.Sync(srv)

	fl.advance(10 * time.Minute)
	got, _ := c.Now()
	if !got.Equal(srv.Add(10 * time.Minute)) {
		t.Fatalf("beklenen sunucu-göreli ilerleme sağlanmadı: %v", got)
	}
}

func TestSyncedWithin(t *testing.T) {
	fl := &fakeLocal{t: time.Unix(0, 0)}
	c := New(fl.now)
	c.Sync(time.Unix(0, 0))
	fl.advance(2 * time.Minute)
	if !c.SyncedWithin(5 * time.Minute) {
		t.Error("2dk < 5dk taze olmalı")
	}
	if c.SyncedWithin(1 * time.Minute) {
		t.Error("2dk > 1dk bayat olmalı")
	}
}
