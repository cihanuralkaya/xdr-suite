// Command c2, XDR Yönetim Sunucusunu (Command & Control) başlatır.
//
// Bağlanan bileşenler:
//   - EnrollmentService (tek yönlü TLS): token doğrulama + CSR imzalama (PKI)
//   - AgentService (mTLS): heartbeat (sunucu-saati çıpası), olay gönderimi
//   - PostgreSQL (pgx), alan şifreleme + HMAC blind index (ana anahtardan türetilir)
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	xgrpc "xdr.corp/suite/server/internal/grpc"

	"xdr.corp/suite/server/internal/admin"
	"xdr.corp/suite/server/internal/adminapi"
	"xdr.corp/suite/server/internal/adminread"
	"xdr.corp/suite/server/internal/config"
	"xdr.corp/suite/server/internal/db"
	"xdr.corp/suite/server/internal/enroll"
	"xdr.corp/suite/server/internal/eventbus"
	"xdr.corp/suite/server/internal/memstore"
	"xdr.corp/suite/server/internal/policypush"
	"xdr.corp/suite/server/internal/retention"
	"xdr.corp/suite/server/internal/revocation"
	"xdr.corp/suite/server/internal/security"
)

// Backend, C2'nin ihtiyaç duyduğu tüm depolama arayüzlerinin birleşimidir;
// hem *db.Store (PostgreSQL) hem *memstore.Store (bellek-içi demo) karşılar.
type Backend interface {
	enroll.Store
	xgrpc.DeviceRegistry
	xgrpc.EventSink
	xgrpc.PolicyProvider
	xgrpc.UpdateProvider
	admin.Store
	adminread.Store
	revocation.Source
	retention.Store
	adminapi.AuthStore

	// MarkStaleOffline, last_seen'i eşiğin gerisinde kalan ACTIVE cihazları
	// OFFLINE işaretler (bayat-OFFLINE görevi). Hem db hem memstore uygular.
	MarkStaleOffline(ctx context.Context, olderThan time.Time) (int, error)

	// Ping, depo sağlık kontrolü (/readyz). Hem db (pool.Ping) hem memstore (nil).
	Ping(ctx context.Context) error

	// VerifyAuditChain, denetim izi hash-zincirinin bütünlüğünü doğrular (SEC C-1).
	VerifyAuditChain(ctx context.Context) error
}

// openBackend, XDR_DATABASE_URL varsa PostgreSQL, yoksa bellek-içi demo deposu
// açar. Demo modunda bir yönetici ve kurallı bir demo politikası tohumlanır ve
// giriş bilgileri loglanır.
func openBackend(ctx context.Context, cfg *config.Config) (Backend, error) {
	if cfg.DatabaseURL != "" {
		store, err := db.New(ctx, cfg.DatabaseURL)
		if err != nil {
			return nil, err
		}
		log.Println("depo: PostgreSQL")
		return store, nil
	}

	// SEC-006: XDR_DATABASE_URL boşken SESSİZCE demo moduna düşme. Bellek-içi demo
	// (kalıcılık yok + tohumlanmış admin) yalnız AÇIK bir onayla (XDR_DEMO=1)
	// çalışmalı; aksi halde üretimde yanlış-yapılandırma riski (env unutulması)
	// tohumlanmış admin ve loglanmış kimlikle açar. Bayrak yoksa hata ver.
	if os.Getenv("XDR_DEMO") != "1" {
		return nil, fmt.Errorf("config: XDR_DATABASE_URL zorunlu (bellek-içi demo için açıkça XDR_DEMO=1 ayarlayın)")
	}

	ms := memstore.New()
	email := getenv("XDR_DEMO_ADMIN_EMAIL", "admin@local")
	pass := os.Getenv("XDR_DEMO_ADMIN_PASSWORD")
	generated := pass == ""
	if generated {
		b := make([]byte, 6)
		_, _ = rand.Read(b)
		pass = "demo-" + hex.EncodeToString(b)
	}
	hash, err := security.HashPassword(pass)
	if err != nil {
		return nil, err
	}
	ms.SeedAdmin(email, hash, admin.RoleAdmin)
	polID, polVer := ms.SeedDemoPolicy()

	log.Println("=======================================================")
	log.Println(" BELLEK-İÇİ DEMO MODU (XDR_DEMO=1) — kalıcılık yok")
	// Parolayı YALNIZ otomatik üretildiyse logla (operatörün bilmesi için);
	// XDR_DEMO_ADMIN_PASSWORD ile verildiyse loglamaya gerek yok (kimlik sızıntısı).
	if generated {
		log.Printf("  Konsol girişi  e-posta: %s   parola: %s (otomatik üretildi)", email, pass)
	} else {
		log.Printf("  Konsol girişi  e-posta: %s   (parola XDR_DEMO_ADMIN_PASSWORD'den)", email)
	}
	log.Printf("  Demo politika  id: %s  (sürüm %s; 'xdr-demo-blocked.exe' engeller)", polID, polVer)
	log.Println("=======================================================")
	return ms, nil
}

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lmsgprefix)
	log.SetPrefix("[c2] ")

	if err := run(); err != nil {
		log.Fatalf("başlatma hatası: %v", err)
	}
}

func run() error {
	ctx, stop := signal.NotifyContext(context.Background(),
		syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	cfg, err := config.Load()
	if err != nil {
		return err
	}

	// Ana anahtardan amaç-ayrımlı alt anahtarlar türet (diske yazılmaz).
	cipher, err := security.NewFieldCipher(security.DeriveKey(cfg.MasterKey, security.LabelFieldEncryption))
	if err != nil {
		return err
	}
	bidx := security.NewBlindIndexer(security.DeriveKey(cfg.MasterKey, security.LabelBlindIndex))

	// CA (istemci sertifikalarını imzalar) ve sunucu TLS materyali.
	caCertPEM, err := os.ReadFile(cfg.CACertPath)
	if err != nil {
		return err
	}
	caKeyPEM, err := os.ReadFile(cfg.CAKeyPath)
	if err != nil {
		return err
	}
	ca, err := security.LoadCA(caCertPEM, caKeyPEM)
	if err != nil {
		return err
	}
	serverCertPEM, err := os.ReadFile(cfg.ServerCertPath)
	if err != nil {
		return err
	}
	serverKeyPEM, err := os.ReadFile(cfg.ServerKeyPath)
	if err != nil {
		return err
	}

	// Depo seçimi: XDR_DATABASE_URL varsa PostgreSQL, yoksa bellek-içi DEMO deposu.
	backend, err := openBackend(ctx, cfg)
	if err != nil {
		return err
	}
	// MFA (TOTP) sırlarının at-rest şifrelenmesi için DB deposuna alan şifreleyiciyi
	// bağla (memstore bellek-içi tutar, şifreleyiciye ihtiyaç duymaz).
	if store, ok := backend.(*db.Store); ok {
		store.SetFieldCipher(cipher)
	}

	// Servisler + handler'lar.
	enrollSvc := enroll.NewService(backend, ca, bidx, cipher, caCertPEM, cfg.ClientCertTTL)
	enrollHandler := xgrpc.NewEnrollmentHandler(enrollSvc)
	// Anlık politika push: admin atama → notifier → açık akış.
	notifier := policypush.New()
	agentHandler := xgrpc.NewAgentHandler(backend, backend, backend, backend, notifier)
	// Canlı konsol akışı (SSE): ajan olay/heartbeat → bus → admin /api/stream.
	liveBus := eventbus.New()
	agentHandler.SetAdminNotifier(liveBus)

	// Sertifika iptali: bellek-içi küme + depodan periyodik tazeleme.
	revCache := revocation.NewCache()
	go revocation.NewRefresher(backend, revCache, 60*time.Second,
		func(m string) { log.Println("[revocation] " + m) }).Run(ctx)

	tlsMat := xgrpc.TLSMaterial{
		ServerCertPEM: serverCertPEM,
		ServerKeyPEM:  serverKeyPEM,
		ClientCAPEM:   caCertPEM,
		Revocation:    revCache,
	}
	agentSrv, err := xgrpc.NewAgentServer(tlsMat, agentHandler)
	if err != nil {
		return err
	}
	enrollSrv, err := xgrpc.NewEnrollServer(tlsMat, enrollHandler)
	if err != nil {
		return err
	}

	// Admin HTTP API (TLS).
	adminSvc := admin.NewService(backend, bidx, cfg.EnrollTokenTTL)
	adminSvc.SetPublisher(notifier) // politika atamada anlık push
	readSvc := adminread.NewService(backend, cipher)
	sessions := security.NewSessionSigner(security.DeriveKey(cfg.MasterKey, security.LabelSessionToken))
	adminAPI := adminapi.New(adminSvc, readSvc, backend, sessions, cfg.AdminSessionTTL)
	adminAPI.SetStream(liveBus)                                    // canlı SSE akışı
	adminAPI.SetHealthCheck(backend.Ping)                          // /readyz depo sağlık kontrolü
	adminAPI.SetLoginLimit(cfg.LoginMaxAttempts, cfg.LoginLockout) // kaba-kuvvet koruması
	adminAPI.SetPrivacyNotice(os.Getenv("XDR_PRIVACY_NOTICE"))     // KVKK aydınlatma (boşsa varsayılan)
	adminAPI.SetAuditVerifier(backend.VerifyAuditChain)            // denetim izi hash-zincir doğrulama
	httpSrv := &http.Server{Addr: cfg.ListenAdmin, Handler: adminAPI.Handler()}

	// KVKK saklama görevi: dolan event_logs partition'larını düşür, gelecek
	// ayları önceden oluştur (başlangıçta bir kez + günlük).
	retSvc := retention.NewService(backend, cfg.RetentionDays, 2, func(m string) { log.Println("[retention] " + m) })
	go func() {
		t := time.NewTicker(24 * time.Hour)
		defer t.Stop()
		for {
			if err := retSvc.Run(ctx, time.Now()); err != nil {
				log.Printf("saklama görevi hatası: %v", err)
			}
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
		}
	}()

	// Bayat-OFFLINE görevi: belirli süredir heartbeat göndermeyen ACTIVE
	// cihazları OFFLINE işaretle (durum sütunu ve özet sayaçları güvenilir
	// olsun). Eşik (~90 sn) heartbeat aralığının birkaç katıdır; her 1 dk taranır.
	const staleThreshold = 90 * time.Second
	go func() {
		t := time.NewTicker(time.Minute)
		defer t.Stop()
		for {
			if n, err := backend.MarkStaleOffline(ctx, time.Now().Add(-staleThreshold)); err != nil {
				log.Printf("[status] bayat-OFFLINE görevi hatası: %v", err)
			} else if n > 0 {
				log.Printf("[status] %d cihaz OFFLINE işaretlendi", n)
			}
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
		}
	}()

	// Dinleyicileri eşzamanlı başlat.
	errCh := make(chan error, 3)
	go func() {
		log.Printf("AgentService (mTLS) dinliyor: %s", cfg.ListenAgent)
		errCh <- xgrpc.Serve(agentSrv, cfg.ListenAgent)
	}()
	go func() {
		log.Printf("EnrollmentService (TLS) dinliyor: %s", cfg.ListenEnroll)
		errCh <- xgrpc.Serve(enrollSrv, cfg.ListenEnroll)
	}()
	go func() {
		log.Printf("Admin API (TLS) dinliyor: %s", cfg.ListenAdmin)
		if err := httpSrv.ListenAndServeTLS(cfg.ServerCertPath, cfg.ServerKeyPath); err != http.ErrServerClosed {
			errCh <- err
		}
	}()

	select {
	case <-ctx.Done():
		log.Println("kapatma sinyali alındı, nazikçe durduruluyor...")
	case err := <-errCh:
		if err != nil {
			return err
		}
	}

	// Nazik kapanış (en fazla birkaç saniye).
	done := make(chan struct{})
	go func() {
		shutdownCtx, c := context.WithTimeout(context.Background(), 5*time.Second)
		defer c()
		_ = httpSrv.Shutdown(shutdownCtx)
		agentSrv.GracefulStop()
		enrollSrv.GracefulStop()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		agentSrv.Stop()
		enrollSrv.Stop()
	}
	return nil
}
