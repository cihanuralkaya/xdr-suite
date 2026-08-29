# Mimari

## Genel akış

```
                 mTLS + gRPC
  ┌──────────┐  ◄──────────────►  ┌────────────────────┐
  │  Ajan    │                    │   C2 Sunucusu      │
  │ (agent)  │   enrollment       │  - AgentService    │
  │          │  ─────(1-way TLS)─►│  - EnrollmentSvc   │
  │ Watchdog │                    │  - OTA / Politika  │
  └──────────┘                    └─────────┬──────────┘
                                            │
                                   ┌────────▼─────────┐
                                   │   PostgreSQL     │
                                   │ (at-rest şifreli)│
                                   └──────────────────┘
```

## Teknoloji kararları

- **Tek dil: Go** — C2 ve ajan ortak protobuf tiplerini paylaşır, bakım tek
  ekosistemde. Kernel sürücüsü (ileride) zorunlu olarak C/C++.
- **gRPC + mTLS** — çift yönlü sertifika doğrulaması; ajan gövdesindeki
  `device_id`'ye güvenilmez, kimlik istemci sertifikasından alınır.
- **PostgreSQL** — hassas serbest-metin alanları `pgcrypto` ile şifreli; yüksek
  hacimli `event_logs` sorgulanabilir kalır ve gizliliği at-rest (disk/tablespace)
  şifreleme ile korunur.

## Kurulum ve paketleme

### Sunucu (C2)
Tek dosya installer (Windows MSI / Linux deb-rpm) C2 servisini ve PostgreSQL
bağlantı yapılandırmasını kurar. Ana şifreleme anahtarı (master key) kurulumda
belirlenir ve serviste RAM'e alınır; diske düz saklanmaz.

### İstemci (agent) — benzersiz kurulum
Kurulum bir **enrollment token** ile bootstrap edilir:

1. IT, yönetim panelinden bir cihaz için tek kullanımlık, süreli token üretir
   (DB: `enrollment_tokens`, ham token saklanmaz — HMAC'i tutulur).
2. Token ajana iki moddan biriyle ulaşır (**karar: her ikisi de desteklenir**):
   - **Gömülü mod:** cihaz başına benzersiz installer, token damgalı → kullanıcı
     çift-tıkla kurar, sıfır yapılandırma. Dağıtım başına paket üretilir.
   - **Kod-giriş modu:** tek ortak installer; kurulumda IT'nin verdiği tek
     kullanımlık kod girilir. Dağıtımı basit.
   Çekirdek ajan her iki modda aynıdır; farklılık yalnızca paketleme katındadır.
3. Ajan ilk açılışta lokal anahtar çifti üretir, CSR oluşturur ve
   `EnrollmentService.Enroll(token, csr)` çağırır.
4. Sunucu token'ı doğrular, CSR'ı imzalar, kısa ömürlü istemci sertifikası döner.
5. Sonraki tüm iletişim mTLS iledir. Token tek kullanımlıktır ve tüketilir.

### Hedef platformlar
**Karar: hem sunucu hem istemci Linux + Windows.** Go cross-compile ile tek
kaynaktan üretilir; installer hedefleri: Windows **MSI**, Linux **deb/rpm**.
OS'e özgü parçalar (servis kaydı, süreç sonlandırma, firewall/iptables,
ileride sürücü) platform-spesifik dosyalarda soyutlanır.

## Fazlar (yol haritası)

- **Faz 1 — İskelet (tamam):** yapı, proto sözleşmeleri, düzeltilmiş DB şeması.
- **Faz 2a — Enrollment/PKI çekirdeği (tamam):** security ilkelleri (HMAC blind
  index, AES-256-GCM alan şifreleme, CA/CSR imzalama, KDF), config, transport'tan
  bağımsız enrollment domain servisi + birim testleri; pgx `Store` ve gRPC
  handler adaptörleri (proto/DB üretimi sonrası derlenir).
- **Politika anlık push (tamam):** `server/internal/policypush` per-cihaz pub/sub;
  `StreamPolicies` artık uzun-ömürlü — ilk paketi gönderir, sonra admin atama
  (`AssignPolicy`→`Publish`) ile yeni paketleri ANINDA iter. Ajan kalıcı abonelik
  tutar ve motoru `atomic.Pointer` ile sıcak değiştirir. e2e ile push doğrulandı.
- **Faz 2b — Rutin akış (tamam, derleniyor):** ajan-domain (politika motoru,
  sunucu-saati çıpası, olay tamponu) + sunucu `AgentService` (Heartbeat +
  ReportEvents, kimlik mTLS peer sertifikasından) + iki gRPC sunucu mTLS/TLS ile
  ayağa kalkıyor + ajan ana döngüsü (enroll → heartbeat → olay flush).
- **Faz 2c — Politika dağıtımı + canlı kanıt (tamam):** `StreamPolicies` uçtan
  uca bağlı (sunucu geçerli paketi sunar, ajan proto→domain çevirip motora
  yükler); dev sertifika aracı (`tools/gencerts`); `server/internal/e2e` gerçek
  mTLS gRPC ile enroll→heartbeat→olay→**politika**→token akışını doğruluyor.
  `RenewCertificate` bağlandı: kayıtlı ajan mTLS ile (token'sız) sertifikasını
  yeniler; enroll sunucusu "sertifika varsa doğrula" modunda, kimlik peer
  sertifikasından alınır. e2e ile doğrulandı. Ajan artık PROAKTİF yeniler:
  `agent/internal/certrenew` ömrün son 1/3'ünde, `transport.CertHolder` ile canlı
  bağlantıyı yeniden kurmadan (GetClientCertificate ile dinamik cert) yeniler.
- **Sertifika iptali (tamam):** `server/internal/revocation` — bellek-içi iptal
  kümesi (SHA-256 parmak izi), DB'den periyodik tazeleme, mTLS `VerifyPeerCertificate`
  kapısı; admin `RevokeDevice` (OPERATOR+, audit) + `/api/devices/revoke` + konsol
  düğmesi. e2e: iptal edilen sertifikayla yeni bağlantı reddedilir.
- **Faz 3 — Politika uygulama (kısmen tamam):** süreç izleme + sonlandırma
  (`agent/internal/enforce`), sunucu-saatine çıpalı değerlendirme, saat
  senkronsuzken fail-safe (yalnız her-zaman-yasak), `POLICY_VIOLATION` olayı.
  Windows kontrolcüsü (Toolhelp/TerminateProcess) gerçek süreçlerle doğrulandı;
  Linux kontrolcüsü (`/proc` tarama + SIGKILL) cross-compile ile derlendi, macOS
  için desteklenmiyor stub'ı. **Kalan:** enforcement kadansı ayarı.
- **Faz 4 — OTA imza doğrulama (kısmen tamam):** Ed25519 imzalı manifesto
  (`otawire` kanonik kodlama, `server/internal/ota` imzalayıcı, `agent/internal/update`
  doğrulayıcı), `CheckUpdate` uçtan uca bağlı ve e2e ile doğrulandı (geçerli
  kabul, değiştirilmiş red), `tools/otasign` (anahtar üretimi + sürüm imzalama +
  SQL).
- **Faz 4b — OTA indirme + staging (kısmen tamam):** `agent/internal/update` —
  boyut-sınırlı indirici, `Prepare` boru hattı (imza → indir → SHA-256 → atomik
  staging + sürüm işaretçisi); imza/hash başarısızsa uygulanmaz. `httptest` ile
  doğrulandı.
- **Kademeli dağıtım / canary (tamam):** `server/internal/rollout` — cihaz+sürüm
  hash'ine göre deterministik kohort; `CheckUpdate`, cihaz `rollout_percent`
  kohortunda değilse güncelleme sunmaz. Monoton (yüzde artınca kohort büyür),
  dağılım/sınır testli; e2e ile %0 kapısı doğrulandı.
- **İmzalı script yürütme (tamam, sınırlı):** `scriptwire` + `agent/internal/script`
  — Ed25519 imza doğrulama (tek bayt değişse ret) + sınırlı yürütme (timeout,
  çıktı sınırı, minimal env); `RUN_SIGNED_SCRIPT` komutu ajanda bağlı, `tools/scriptsign`
  imzalar. **Sınır (#7):** gerçek izolasyon sınırı DEĞİL; süreç-ağacı sonlandırma
  ve sandbox (Job Object / AppContainer / container) ileri faz.
- **Watchdog (tamam):** `agent/internal/watchdog` — süreç gözetimi + backoff'lu
  yeniden başlatma (Supervisor, sahte runner ile test), staged swap + yedek +
  **deneme penceresinde çöküşte rollback** (FileSwapper, geçici dizinle test),
  gerçek `os/exec` runner. OTA döngüsünü kapatır (Prepare→swap→rollback).
- **Çift-süreç karşılıklı gözetim (tamam):** `agent/internal/liveness` — dosya
  beacon'ları; watchdog ajanı süreç-çıkışıyla, ajan watchdog'u beacon
  bayatlamasıyla (`PeerGuard`) yeniden başlatır. Beacon + guard mantığı sahte
  saatle test edildi. **Kalan:** kademeli dağıtım (rollout), hung (asılı) ajan
  tespiti (beacon ile).
- **Faz 5a — Ağ keşfi (tamam):** `agent/internal/discovery` — komşu/ARP tablosu
  (read-only) tarama, ARP ayrıştırıcı (Windows `arp -a`, Linux `/proc/net/arp`),
  yeni-cihaz takibi + yetkili/yetkisiz allowlist, `NETWORK_DISCOVERY` olayları.
  Windows'ta gerçek ağda doğrulandı (7 cihaz bulundu).
- **Faz 5b — Karantina (kısmen tamam):** `agent/internal/quarantine` — idempotent
  durum yöneticisi (Apply/Release, geçişlerde SECURITY olayı) sahte izolatörle
  test edildi; Windows (`netsh`, varsayılan politika blok + C2 allow) ve Linux
  (`iptables` özel zincir) izolatörleri derlendi/cross-compile edildi. Ajan,
  heartbeat `pending_commands`'taki QUARANTINE/UNQUARANTINE'i uygular. **Kalan:**
  komutu üreten sunucu tarafı (komut kuyruğu + admin), canlı firewall testi.
- **Faz 6 — Lokal ML:** ONNX Isolation Forest, baseline, human-in-the-loop.
- **Faz 7 — Tamper (yüksek maliyet):** MiniFilter sürücüsü, PPL/ELAM, kod imzalama.
- **Faz 8 — Paketleme:** sunucu + benzersiz istemci installer'ları.
- **Admin çekirdeği (tamam):** `server/internal/admin` — RBAC'li
  (VIEWER/OPERATOR/ADMIN) işlemler: enrollment token üretimi (HMAC indeksli),
  karantina/serbest komutu verme, politika oluşturma/atama; her hassas işlem
  `audit_log`'a yazılır. Komut kuyruğu (`device_commands`) + heartbeat teslimi
  (en-fazla-bir-kez) e2e ile doğrulandı.
- **Admin HTTP API (tamam):** `server/internal/adminapi` — Argon2id parola
  doğrulama, HMAC-imzalı durumsuz oturum token'ı, Bearer korumalı REST uçları
  (login, enrollment-token, karantina/serbest, politika CRUD/atama);
  `httptest` ile uçtan uca doğrulandı (login→komut, RBAC 403, hatalı parola 401).
  `tools/adminseed` yönetici parolası hash'ler.
- **Web yönetim konsolu (tamam):** `server/internal/adminapi/console.html` — C2
  admin sunucusundan **aynı köken** gömülü (Go embed) tek-sayfa konsol: login,
  enrollment token üretimi, karantina/serbest, politika oluştur/ata. İkiliye
  gömülü, `GET /` ile sunulur; `httptest` ile doğrulandı.
- **Okuma API'si + görünürlük (tamam):** `server/internal/adminread` — cihaz
  listesi (şifreli hostname/mac sunucuda deşifre) ve olay logları; `GET /api/devices`,
  `GET /api/events`. Konsolda canlı **Cihazlar** ve **Olaylar** tabloları. Deşifre
  ve uç noktalar test edildi.
- **KVKK saklama otomasyonu (tamam):** `server/internal/retention` — saf plan
  (düşürülecek/oluşturulacak aylık partition'lar) + DB yürütücü; C2'de günlük
  çalışır (`XDR_RETENTION_DAYS`, varsayılan 90). Plan mantığı sahte store ile test edildi.
