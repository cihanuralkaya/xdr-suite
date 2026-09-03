// Command agent, uç nokta ajanını başlatır.
//
// Akış: (1) kayıtlı sertifika yoksa tek kullanımlık token + CSR ile enroll et,
// (2) mTLS ile AgentService'e bağlan, (3) heartbeat döngüsü — her turda sunucu
// saatini çıpa al ve tamponlanmış olayları store-and-forward ile gönder.
//
// Not: Süreç izleme ve politika uygulama (mesai-dışı kontrol) OS'e özgüdür ve
// Faz 3'te eklenir; politika motoru (agent/internal/policy) ve saat çıpası
// (agent/internal/agentclock) hazır ve test edilmiştir.
package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"xdr.corp/suite/agent/internal/agentclock"
	"xdr.corp/suite/agent/internal/anomaly"
	"xdr.corp/suite/agent/internal/certrenew"
	"xdr.corp/suite/agent/internal/collector"
	"xdr.corp/suite/agent/internal/compliance"
	"xdr.corp/suite/agent/internal/discovery"
	"xdr.corp/suite/agent/internal/enforce"
	"xdr.corp/suite/agent/internal/liveness"
	"xdr.corp/suite/agent/internal/policy"
	"xdr.corp/suite/agent/internal/quarantine"
	"xdr.corp/suite/agent/internal/script"
	"xdr.corp/suite/agent/internal/transport"
	"xdr.corp/suite/agent/internal/update"
	xdrv1 "xdr.corp/suite/gen/xdr/v1"
	"xdr.corp/suite/logx"
	"xdr.corp/suite/otawire"
	"xdr.corp/suite/scriptwire"
)

type envConfig struct {
	enrollAddr   string
	agentAddr    string
	serverName   string
	caPath       string
	token        string
	dataDir      string
	updatePubKey string   // base64 Ed25519 public key (OTA imza doğrulama)
	scriptPubKey string   // base64 Ed25519 public key (imzalı script doğrulama)
	authMACs     []string // ağ keşfi allowlist'i (yetkili MAC'ler)
	watchdogBin  string   // watchdog ikilisi (verilirse karşılıklı gözetim açık)
	interval     time.Duration
}

func loadEnv() envConfig {
	return envConfig{
		enrollAddr:   getenv("XDR_ENROLL_ADDR", "localhost:8444"),
		agentAddr:    getenv("XDR_AGENT_ADDR", "localhost:8443"),
		serverName:   getenv("XDR_SERVER_NAME", "xdr-c2"),
		caPath:       os.Getenv("XDR_CA_PEM"),
		token:        os.Getenv("XDR_ENROLL_TOKEN"),
		dataDir:      getenv("XDR_AGENT_DATA", "./agent-data"),
		updatePubKey: os.Getenv("XDR_UPDATE_PUBKEY"),
		scriptPubKey: os.Getenv("XDR_SCRIPT_PUBKEY"),
		authMACs:     splitCSV(os.Getenv("XDR_AUTHORIZED_MACS")),
		watchdogBin:  os.Getenv("XDR_WATCHDOG_BIN"),
		interval:     getdur("XDR_HEARTBEAT_INTERVAL", 30*time.Second),
	}
}

func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func main() {
	// XDR_LOG_FORMAT=json → yapısal JSON loglama (SIEM); aksi halde "[agent] " metin.
	logx.Setup(os.Getenv("XDR_LOG_FORMAT"), "[agent] ")
	if err := run(); err != nil {
		log.Fatalf("hata: %v", err)
	}
}

func run() error {
	ctx, stop := signal.NotifyContext(context.Background(),
		syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	cfg := loadEnv()

	// Sunucu SPKI pinning (savunma derinliği): XDR_SERVER_SPKI_PIN ayarlıysa (virgülle
	// ayrılmış base64 SHA-256 pinleri) sunucu sertifikası CA'ya EK OLARAK pin'e karşı
	// doğrulanır. Ayarlı değilse pinning devre dışıdır (yalnız CA doğrulaması).
	if pins := splitCSV(os.Getenv("XDR_SERVER_SPKI_PIN")); len(pins) > 0 {
		transport.SetServerPins(pins)
		log.Printf("mTLS: sunucu SPKI pinning etkin (%d pin)", len(pins))
	}

	ident, err := ensureEnrolled(ctx, cfg)
	if err != nil {
		return err
	}
	log.Printf("kimlik hazır: device_id=%s", ident.deviceID)

	// İstemci sertifikasını dinamik tutucuya al: yenileme sonrası yeni
	// bağlantılar güncel sertifikayı kullanır (yeniden bağlanma zorlamadan).
	certHolder, err := transport.NewCertHolder(ident.certPEM, ident.keyPEM)
	if err != nil {
		return err
	}
	cli, conn, err := transport.DialAgent(cfg.agentAddr, certHolder, ident.caPEM, cfg.serverName)
	if err != nil {
		return err
	}
	defer conn.Close()

	// Proaktif sertifika yenileme: ömrün son üçte birinde süre dolmadan yenile.
	go runCertRenewal(ctx, cfg, certHolder, ident)

	clock := agentclock.New(time.Now)
	buf := collector.NewBuffer(10000)
	// Motor birden çok goroutine'den (heartbeat + politika akışı) erişildiğinden
	// atomik tutulur; politika akışı sıcak değiştirir, enforcement okur.
	var engine atomic.Pointer[policy.Engine]
	engine.Store(policy.New(policy.Bundle{}))
	monitor := enforce.NewMonitor(enforce.NewProcessController(), clock, buf, uint32(os.Getpid()))
	// Davranışsal anomali tespiti (varsayılan AÇIK; XDR_ANOMALY_DISABLE ile kapatılır).
	// XDR_ANOMALY_MODEL verilirse eğitilmiş JSON model (ModelScorer) yüklenir;
	// aksi halde saf-Go çevrimiçi istatistiksel scorer kullanılır. Muhafazakâr
	// eşik (0.85): yalnız güçlü aykırı değerler SECURITY olayı üretir.
	if os.Getenv("XDR_ANOMALY_DISABLE") == "" {
		var scorer anomaly.Scorer
		if mp := os.Getenv("XDR_ANOMALY_MODEL"); mp != "" {
			// SEC C-7: model YALNIZ Ed25519 imzası doğrulanınca yüklenir. İmzasız
			// ya da doğrulanamayan model YÜKLENMEZ (fail-closed) — tespiti sıfırlayan
			// kurcalamayı önler; istatistiksel scorer'a düşülür.
			pubB64 := os.Getenv("XDR_ANOMALY_PUBKEY")
			if pubB64 == "" {
				log.Printf("anomali modeli verildi ama XDR_ANOMALY_PUBKEY yok — imzasız model YÜKLENMEZ; istatistiksel scorer")
			} else if pub, err := base64.StdEncoding.DecodeString(pubB64); err != nil {
				log.Printf("XDR_ANOMALY_PUBKEY geçersiz (%v) — istatistiksel scorer", err)
			} else if m, err := anomaly.LoadModelSigned(mp, ed25519.PublicKey(pub)); err != nil {
				log.Printf("imzalı anomali modeli reddedildi (%v) — istatistiksel scorer", err)
			} else {
				scorer = m
				log.Printf("imzalı anomali modeli doğrulandı + yüklendi: %s", mp)
			}
		}
		monitor.SetAnomalyDetector(anomaly.NewDetector(0.85, scorer))
	}
	neighbors := discovery.NewNeighborSource()
	netTracker := discovery.NewTracker(cfg.authMACs)

	// Karantina yöneticisi: izolasyonda yalnız C2'ye izin verilir.
	// SAFE MODE (XDR_SAFE_MODE): gerçek firewall'a dokunmaz — demo/test için.
	c2Host, _, _ := net.SplitHostPort(cfg.agentAddr)
	var isolator quarantine.Isolator = quarantine.NewIsolator()
	if os.Getenv("XDR_SAFE_MODE") != "" {
		isolator = quarantine.NoopIsolator{}
		log.Println("SAFE MODE açık: karantina gerçek ağ değişikliği yapmayacak")
	}
	quar := quarantine.NewManager(isolator, buf, filterEmpty([]string{c2Host}))

	// OTA doğrulayıcı (opsiyonel): public key verilmişse güncelleme imzaları doğrulanır.
	var updVerifier *update.Verifier
	if cfg.updatePubKey != "" {
		if raw, err := base64.StdEncoding.DecodeString(cfg.updatePubKey); err == nil {
			if v, err := update.NewVerifier(raw); err == nil {
				updVerifier = v
			} else {
				log.Printf("OTA public key geçersiz, güncelleme kontrolü kapalı: %v", err)
			}
		}
	}
	downloader := update.NewHTTPDownloader(0)
	stageDir := filepath.Join(cfg.dataDir, "updates")

	// İmzalı script doğrulayıcı (opsiyonel): yalnız imzalı scriptler çalıştırılır.
	var scriptVerifier *script.Verifier
	if cfg.scriptPubKey != "" {
		if raw, err := base64.StdEncoding.DecodeString(cfg.scriptPubKey); err == nil {
			if v, err := script.NewVerifier(raw); err == nil {
				scriptVerifier = v
			}
		}
	}

	// Başlangıç yaşam-döngüsü olayı (gerçek olay; uydurma telemetri değil). Host
	// bilgisi Details'e iliştirilir (konsol olay-detayında filo görünürlüğü).
	hostname, _ := os.Hostname()
	buf.Add(collector.Event{Category: "SYSTEM", Severity: "INFO", Message: "ajan başladı", OccurredAt: time.Now(),
		Details: map[string]any{"os": runtime.GOOS, "arch": runtime.GOARCH, "agent_version": agentVersion, "hostname": hostname}})

	// Uyum durumu: başlangıçta disk şifreleme kontrol edilir ve raporlanır. Şifreleme
	// KAPALIYSA güvenlik-duruşu ihlali (SECURITY/MEDIUM); açık/bilinmiyor bilgi amaçlı.
	reportCompliance(buf, compliance.NewChecker())

	// Kalıcı politika aboneliği: sunucu politika değiştikçe anında iter.
	go runPolicyStream(ctx, cli, ident, &engine)

	// Çift-süreç karşılıklı gözetim: watchdog verilmişse, onun beacon'unu izle;
	// bayatlarsa yeniden başlat (watchdog da ajanı süreç-çıkışıyla izler).
	if cfg.watchdogBin != "" {
		selfBeacon := liveness.NewBeacon(filepath.Join(cfg.dataDir, "agent.beacon"))
		wdBeacon := liveness.NewBeacon(filepath.Join(cfg.dataDir, "watchdog.beacon"))
		guard := liveness.NewPeerGuard(selfBeacon, wdBeacon, liveness.Options{
			Restart: func() { spawnDetached(cfg.watchdogBin) },
			Log:     func(m string) { log.Println("[liveness] " + m) },
		})
		go guard.Run(ctx)
	}

	ticker := time.NewTicker(cfg.interval)
	defer ticker.Stop()

	beat := func() {
		hbCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()
		resp, err := cli.Heartbeat(hbCtx, &xdrv1.HeartbeatRequest{
			Identity: &xdrv1.AgentIdentity{
				DeviceId:     ident.deviceID,
				AgentVersion: agentVersion,
				OsPlatform:   runtime.GOOS,
			},
			CurrentPolicyVersion: engine.Load().Version(),
		})
		if err != nil {
			log.Printf("heartbeat başarısız: %v", err)
			return
		}
		// Sunucu saatini çıpa al (yerel saate güvenilmez, inceleme #3).
		if resp.GetServerTime() != nil {
			clock.Sync(resp.GetServerTime().AsTime())
		}
		// Sunucudan gelen komutları işle (karantina, imzalı script vb.).
		// ctx (hbCtx değil) geçilir: uzun scriptler heartbeat penceresini bloklamamalı.
		handleCommands(ctx, resp.GetPendingCommands(), quar, scriptVerifier, buf)
		// Politika uygulaması: yasaklı süreçleri sonlandır (Faz 3).
		if n, err := monitor.Tick(engine.Load()); err != nil {
			log.Printf("enforcement hatası: %v", err)
		} else if n > 0 {
			log.Printf("enforcement: %d yasaklı süreç sonlandırıldı", n)
		}
		// OTA: güncelleme var mı, varsa İMZASINI doğrula, indir ve hazırla (#4).
		if updVerifier != nil {
			checkUpdate(hbCtx, cli, ident, updVerifier, downloader, stageDir, buf)
		}
		// Pasif ağ keşfi: yeni cihazları tespit et ve raporla (mimari 4.3).
		scanNetwork(neighbors, netTracker, buf)
		flushEvents(hbCtx, cli, ident, buf)
	}

	beat() // ilk tur hemen
	for {
		select {
		case <-ctx.Done():
			log.Println("kapatılıyor.")
			return nil
		case <-ticker.C:
			beat()
		}
	}
}

// flushEvents, tamponlanmış olayları gönderir ve yalnız sunucunun onayladığı
// sıraya kadar tampondan siler (store-and-forward, inceleme #9).
func flushEvents(ctx context.Context, cli xdrv1.AgentServiceClient, ident *identity, buf *collector.Buffer) {
	pending := buf.Pending(500)
	if len(pending) == 0 {
		return
	}
	stream, err := cli.ReportEvents(ctx)
	if err != nil {
		log.Printf("olay akışı açılamadı: %v", err)
		return
	}
	protoEvents := make([]*xdrv1.Event, 0, len(pending))
	for _, e := range pending {
		pe := &xdrv1.Event{
			Sequence:   e.Seq,
			Category:   protoCategory(e.Category),
			Severity:   protoSeverity(e.Severity),
			Message:    e.Message,
			OccurredAt: timestamppb.New(e.OccurredAt),
		}
		// Yapısal ek veri (varsa) structpb'ye çevrilip iletilir — konsol olay-detay
		// panelinde gösterilir ve sunucu tarafında event_logs.details'e saklanır.
		if len(e.Details) > 0 {
			if ds, err := structpb.NewStruct(e.Details); err == nil {
				pe.Details = ds
			}
		}
		protoEvents = append(protoEvents, pe)
	}
	if err := stream.Send(&xdrv1.EventBatch{
		Identity: &xdrv1.AgentIdentity{DeviceId: ident.deviceID, AgentVersion: agentVersion, OsPlatform: runtime.GOOS},
		Events:   protoEvents,
	}); err != nil {
		log.Printf("olay gönderilemedi: %v", err)
		return
	}
	ack, err := stream.CloseAndRecv()
	if err != nil {
		log.Printf("olay onayı alınamadı: %v", err)
		return
	}
	removed := buf.Ack(ack.GetLastAcceptedSequence())
	log.Printf("olay gönderildi: %d, onaylanan sıra: %d, silinen: %d", len(pending), ack.GetLastAcceptedSequence(), removed)
}

// runPolicyStream, sunucuya KALICI bir politika aboneliği açar ve gelen her
// paketle motoru sıcak değiştirir. Akış koparsa yeniden bağlanır (ctx bitene dek).
func runPolicyStream(ctx context.Context, cli xdrv1.AgentServiceClient, ident *identity, engine *atomic.Pointer[policy.Engine]) {
	for ctx.Err() == nil {
		stream, err := cli.StreamPolicies(ctx, &xdrv1.PolicySubscribeRequest{
			Identity:             &xdrv1.AgentIdentity{DeviceId: ident.deviceID, AgentVersion: agentVersion, OsPlatform: runtime.GOOS},
			CurrentPolicyVersion: engine.Load().Version(),
		})
		if err == nil {
			for {
				b, rerr := stream.Recv()
				if rerr != nil {
					break
				}
				engine.Store(policy.New(policy.FromProto(b)))
				log.Printf("politika güncellendi (push): sürüm=%s, kural=%d", b.GetPolicyVersion(), len(b.GetRules()))
			}
		}
		// Kopma/hata: kısa bekleyip yeniden bağlan.
		select {
		case <-ctx.Done():
			return
		case <-time.After(5 * time.Second):
		}
	}
}

// checkUpdate, sunucudan güncelleme manifestosu ister; imzayı doğrular, paketi
// indirir, SHA-256'yı doğrular ve staging'e yazar (gerçek swap watchdog'un işi).
// İmza/hash geçersizse güncellemeyi REDDEDER ve SECURITY/CRITICAL olayı üretir.
func checkUpdate(ctx context.Context, cli xdrv1.AgentServiceClient, ident *identity, v *update.Verifier, dl update.Downloader, stageDir string, buf *collector.Buffer) {
	resp, err := cli.CheckUpdate(ctx, &xdrv1.UpdateCheckRequest{
		Identity: &xdrv1.AgentIdentity{DeviceId: ident.deviceID, AgentVersion: agentVersion, OsPlatform: runtime.GOOS},
	})
	if err != nil || !resp.GetUpdateAvailable() {
		return
	}
	// Bu sürüm zaten staging'de bekliyorsa tekrar indirme (watchdog swap'ini bekle);
	// aksi halde her heartbeat'te aynı paket boşuna yeniden indirilir.
	if data, rerr := os.ReadFile(filepath.Join(stageDir, "agent-staged.version")); rerr == nil &&
		strings.TrimSpace(string(data)) == resp.GetTargetVersion() {
		return
	}
	m := otawire.Manifest{
		TargetVersion: resp.GetTargetVersion(),
		SHA256Hex:     resp.GetSha256Hex(),
		DownloadURL:   resp.GetDownloadUrl(),
		Mandatory:     resp.GetMandatory(),
	}
	staged, err := update.Prepare(ctx, m, resp.GetSignature(), v, dl, stageDir)
	if err != nil {
		if err == update.ErrBadSignature || err == update.ErrHashMismatch {
			log.Printf("GÜNCELLEME REDDEDİLDİ (%v): sürüm=%s", err, resp.GetTargetVersion())
			buf.Add(collector.Event{
				Category: "SECURITY", Severity: "CRITICAL",
				Message:    "sahte/bozuk güncelleme reddedildi: " + resp.GetTargetVersion(),
				OccurredAt: time.Now(),
			})
			return
		}
		log.Printf("güncelleme hazırlanamadı: %v", err)
		return
	}
	log.Printf("güncelleme hazırlandı: sürüm=%s (staging: %s; swap watchdog tarafından)", staged.Version, staged.Path)
	buf.Add(collector.Event{
		Category: "AGENT_UPDATE", Severity: "INFO",
		Message:    "imzalı güncelleme doğrulandı ve staging'e alındı: " + staged.Version,
		OccurredAt: time.Now(),
	})
}

// handleCommands, sunucudan gelen anlık komutları uygular (karantina, imzalı script).
func handleCommands(ctx context.Context, cmds []*xdrv1.Command, quar *quarantine.Manager, sv *script.Verifier, buf *collector.Buffer) {
	for _, c := range cmds {
		switch c.GetType() {
		case xdrv1.Command_COMMAND_TYPE_QUARANTINE:
			if err := quar.Apply(); err != nil {
				log.Printf("karantina uygulanamadı: %v", err)
			} else {
				log.Println("karantina uygulandı")
			}
		case xdrv1.Command_COMMAND_TYPE_UNQUARANTINE:
			if err := quar.Release(); err != nil {
				log.Printf("karantina kaldırılamadı: %v", err)
			} else {
				log.Println("karantina kaldırıldı")
			}
		case xdrv1.Command_COMMAND_TYPE_RUN_SIGNED_SCRIPT:
			// Uzun sürebilir; heartbeat döngüsünü bloklamamak için arka planda.
			go runSignedScript(ctx, c, sv, buf)
		default:
			// Diğer komut tipleri (uninstall, teşhis) ileride.
		}
	}
}

// runSignedScript, komut parametrelerinden scripti çıkarır, İMZASINI gömülü
// public key ile doğrular ve YALNIZ geçerliyse sınırlı biçimde çalıştırır.
// İmza geçersizse SECURITY/CRITICAL olayı üretir ve çalıştırmaz.
func runSignedScript(ctx context.Context, c *xdrv1.Command, sv *script.Verifier, buf *collector.Buffer) {
	if sv == nil {
		log.Println("imzalı script alındı ama script public key ayarlı değil; atlanıyor")
		return
	}
	f := c.GetParams().GetFields()
	s := scriptwire.Script{
		Interpreter: f["interpreter"].GetStringValue(),
		Body:        f["body"].GetStringValue(),
	}
	for _, v := range f["args"].GetListValue().GetValues() {
		s.Args = append(s.Args, v.GetStringValue())
	}
	sig, err := base64.StdEncoding.DecodeString(f["signature"].GetStringValue())
	if err != nil || sv.Verify(s, sig) != nil {
		log.Printf("SCRIPT REDDEDİLDİ (imza doğrulanamadı): komut=%s", c.GetCommandId())
		buf.Add(collector.Event{Category: "SECURITY", Severity: "CRITICAL",
			Message: "imzasız/sahte script reddedildi: " + c.GetCommandId(), OccurredAt: time.Now()})
		return
	}
	res, err := script.Run(ctx, s, 60*time.Second, 256*1024)
	if err != nil {
		log.Printf("script çalıştırılamadı: %v", err)
		return
	}
	log.Printf("imzalı script çalıştı: komut=%s çıkış=%d timeout=%v", c.GetCommandId(), res.ExitCode, res.TimedOut)
	buf.Add(collector.Event{Category: "SYSTEM", Severity: "INFO",
		Message:    fmt.Sprintf("imzalı script çalıştı (komut=%s, çıkış=%d)", c.GetCommandId(), res.ExitCode),
		OccurredAt: time.Now()})
}

// spawnDetached, verilen ikiliyi bağımsız bir süreç olarak başlatır (beklemez).
func spawnDetached(bin string) {
	cmd := exec.Command(bin)
	if err := cmd.Start(); err != nil {
		log.Printf("watchdog yeniden başlatılamadı: %v", err)
		return
	}
	log.Printf("watchdog yeniden başlatıldı (pid=%d)", cmd.Process.Pid)
	// Zombie bırakmamak için arka planda bekle.
	go func() { _ = cmd.Wait() }()
}

func filterEmpty(ss []string) []string {
	var out []string
	for _, s := range ss {
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

// runCertRenewal, ajanın istemci sertifikasını süre dolmadan yeniler. Ömrün
// son üçte birine girildiğinde enroll endpoint'ine mTLS ile bağlanıp yeniler,
// yeni cert+key'i diske yazar ve holder'ı günceller (canlı bağlantı eski cert
// hâlâ geçerli olduğu için etkilenmez; sonraki bağlantılar yeniyi kullanır).
func runCertRenewal(ctx context.Context, cfg envConfig, holder *transport.CertHolder, ident *identity) {
	nb, na, err := certrenew.ParseValidity(ident.certPEM)
	if err != nil {
		log.Printf("sertifika süresi çözülemedi, yenileme kapalı: %v", err)
		return
	}
	check := time.NewTicker(6 * time.Hour)
	defer check.Stop()
	for {
		if certrenew.ShouldRenew(nb, na, time.Now(), 1.0/3.0) {
			rctx, cancel := context.WithTimeout(ctx, 30*time.Second)
			certPEM, keyPEM, newNA, rerr := transport.Renew(rctx, cfg.enrollAddr, holder, ident.caPEM, cfg.serverName)
			cancel()
			if rerr != nil {
				log.Printf("sertifika yenileme başarısız (yeniden denenecek): %v", rerr)
			} else {
				_ = os.WriteFile(filepath.Join(cfg.dataDir, "agent.crt"), certPEM, 0o644)
				_ = os.WriteFile(filepath.Join(cfg.dataDir, "agent.key"), keyPEM, 0o600)
				nb, na = time.Now(), newNA
				log.Printf("sertifika yenilendi, yeni bitiş: %s", na.Format(time.RFC3339))
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-check.C:
		}
	}
}

// scanNetwork, komşu tablosunu tarar ve yeni tespit edilen cihazları
// NETWORK_DISCOVERY olayı olarak tamponlar. Yetkisiz cihazlar MEDIUM olarak
// işaretlenir.
// reportCompliance, disk şifreleme uyum durumunu bir olay olarak yayınlar. Şifreleme
// kapalıysa SECURITY/MEDIUM (uyum ihlali), aksi halde SYSTEM/INFO. Details, konsol
// detay panelinde ve sunucu event_logs'ta durumu taşır.
func reportCompliance(buf *collector.Buffer, chk compliance.Checker) {
	status := chk.DiskEncryption()
	cat, sev, msg := "SYSTEM", "INFO", "disk şifreleme: "+status
	if status == compliance.EncOff {
		cat, sev, msg = "SECURITY", "MEDIUM", "uyum ihlali: disk şifreleme KAPALI"
	}
	buf.Add(collector.Event{
		Category:   cat,
		Severity:   sev,
		Message:    msg,
		OccurredAt: time.Now(),
		Details:    map[string]any{"disk_encryption": status},
	})
}

func scanNetwork(src discovery.NeighborSource, tr *discovery.Tracker, buf *collector.Buffer) {
	hosts, err := src.Neighbors()
	if err != nil {
		return // keşif bu platformda yoksa sessizce geç
	}
	for _, d := range tr.Observe(hosts, time.Now()) {
		severity, label := "INFO", "yetkili"
		if !d.Authorized {
			severity, label = "MEDIUM", "YETKİSİZ"
		}
		buf.Add(collector.Event{
			Category:   "NETWORK_DISCOVERY",
			Severity:   severity,
			Message:    fmt.Sprintf("yeni cihaz (%s): %s / %s", label, d.Host.IP, d.Host.MAC),
			OccurredAt: time.Now(),
			Details:    map[string]any{"ip": d.Host.IP, "mac": d.Host.MAC, "authorized": d.Authorized},
		})
	}
}

// agentVersion, sürüm etiketidir. Release derlemesinde ldflags ile damgalanır:
//
//	-ldflags "-X main.agentVersion=1.0.0"
var agentVersion = "0.1.0-dev"

func protoCategory(s string) xdrv1.EventCategory {
	if v, ok := xdrv1.EventCategory_value["EVENT_CATEGORY_"+s]; ok {
		return xdrv1.EventCategory(v)
	}
	return xdrv1.EventCategory_EVENT_CATEGORY_SYSTEM
}

func protoSeverity(s string) xdrv1.Severity {
	if v, ok := xdrv1.Severity_value["SEVERITY_"+s]; ok {
		return xdrv1.Severity(v)
	}
	return xdrv1.Severity_SEVERITY_INFO
}

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func getdur(k string, def time.Duration) time.Duration {
	if v := os.Getenv(k); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return def
}

// primaryMAC, ilk loopback olmayan arayüzün MAC adresini döner.
//
//nolint:unused // enroll.go tarafından kullanılır
func primaryMAC() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, i := range ifaces {
		if i.Flags&net.FlagLoopback != 0 || len(i.HardwareAddr) == 0 {
			continue
		}
		return i.HardwareAddr.String()
	}
	return ""
}
