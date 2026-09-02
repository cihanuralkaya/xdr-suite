# Durum Raporu — XDR/MDM

Bu belge, kod tabanının mevcut durumunu, neyin nasıl doğrulandığını ve bilinçli
olarak kapsam dışı bırakılanları özetler. Devir/gözden geçirme için referanstır.

## Özet

Mimari dökümdeki **yazılım-tarafı yeteneklerin tamamına yakını** kodlandı ve test
edildi. Güvenlik-kritik akışlar gerçek mTLS gRPC ve gerçek kripto ile **uçtan uca
kanıtlandı** (`server/internal/e2e`). Kernel-seviye tamper koruması bilinçli
olarak kapsam dışıdır (bkz. aşağıda).

- Dil: **Go** (tek dil), iletişim **gRPC + mTLS**, TLS 1.3.
- ~8 100 satır üretim Go + kapsamlı test.
- **132 test fonksiyonu / 26 test paketi**, tümü geçiyor (`go test ./...`).
- Cross-compile doğrulandı: Windows (native), Linux, macOS.
- **Bellek-içi demo modu** canlı çalıştırıldı (`XDR_DATABASE_URL` boş): gerçek
  enrollment, gerçek ağ keşfi, tüm admin/konsol akışları uçtan uca denendi.

## Uçtan uca kanıtlanan zincir (e2e)

`enroll (PKI) → mTLS → heartbeat (sunucu-saati) → politika dağıtımı (push) →
OTA imza + rollout kapısı → komut teslimi (karantina) → tek-kullanımlık token`
— hepsi tek entegrasyon testinde, gerçek TCP + mTLS gRPC + gerçek imza/hash ile.

**Smoke/kabul testi** (`scripts/smoke-test.sh`, `make smoke`): gerçek c2 + gerçek
agent süreçlerini izole portlarda ayağa kaldırır ve kayıt → CSR imza → heartbeat →
olay → admin eylem (tanılama) → denetim izi → özet/politika okuma → **SSE canlı
akış** zincirini 11 iddiayla doğrular. **CI** (`.github/workflows/ci.yml`):
proto üret + `go vet` + `go test ./...` + smoke test + çapraz derleme (artifact).

## Yetenek matrisi

| Yetenek | Durum | Paket | Doğrulama |
|---|---|---|---|
| Enrollment / PKI bootstrap | ✅ | `server/internal/enroll` | e2e + birim |
| Kriptografi (HMAC blind index, AES-GCM, CA/CSR) | ✅ | `server/internal/security` | birim |
| mTLS gRPC (2 sunucu) | ✅ | `server/internal/grpc` | e2e |
| Heartbeat + sunucu-saati çıpası | ✅ | `grpc` + `agent/internal/agentclock` | e2e + birim |
| Politika motoru (mesai-dışı, gece-aşırı) | ✅ | `agent/internal/policy` | birim |
| Politika dağıtımı — anlık push | ✅ | `server/internal/policypush` | e2e + birim |
| Süreç enforcement (izle + sonlandır) | ✅ Win gerçek / Linux derlendi | `agent/internal/enforce` | birim + gerçek liste (Win) |
| Store-and-forward olay tamponu | ✅ | `agent/internal/collector` | birim |
| OTA imza doğrulama (Ed25519) | ✅ | `server/internal/ota`, `agent/internal/update`, `otawire` | e2e + birim |
| OTA indirme + staging | ✅ | `agent/internal/update` | birim (httptest) |
| Kademeli dağıtım (canary) | ✅ | `server/internal/rollout` | e2e + birim |
| Watchdog (gözetim + swap + rollback) | ✅ | `agent/internal/watchdog` | birim |
| Çift-süreç karşılıklı gözetim | ✅ | `agent/internal/liveness` | birim |
| Ağ keşfi (ARP/komşu) | ✅ Win gerçek / Linux derlendi | `agent/internal/discovery` | birim + gerçek tarama (Win) |
| Karantina (ağ izolasyonu) | ✅ mantık / OS derlendi | `agent/internal/quarantine` | birim (sahte izolatör) |
| Komut kuyruğu (karantina teslimi) | ✅ | `server/internal/db` + `grpc` | e2e |
| Admin servisi (RBAC + denetim izi) | ✅ | `server/internal/admin` | birim |
| Admin HTTP API + Argon2 + oturum | ✅ | `server/internal/adminapi` | birim (httptest) |
| Yönetici yönetimi (oluştur/rol/pasifleştir) | ✅ | `admin/adminusers.go`, `db/admins.go` | birim + canlı demo |
| Enrollment token yönetimi (listele/iptal) | ✅ | `db/tokens.go`, `adminread` | birim + canlı demo |
| Politika listeleme (kural + cihaz sayımı) | ✅ | `adminread.ListPolicies`, `db/policy.go` | birim + canlı demo |
| Konsol: önem grafiği, cihaz arama, CSV dışa aktarma | ✅ | `adminapi/console.html` | canlı demo |
| Cihaz-detay olay akışı (device-scoped) | ✅ | `adminapi/console.html` + `adminread` | canlı demo |
| Tanılama topla komutu (COLLECT_DIAGNOSTICS) | ✅ | `admin.CollectDiagnostics` | birim + canlı demo |
| Canlı SSE push (olay/heartbeat → konsol) | ✅ | `eventbus`, `grpc.AdminNotifier`, `/api/stream` | birim + entegrasyon + canlı demo |
| KVKK veri sahibi hakları (erişim/dışa aktarma + silme) | ✅ | `admin.EraseDevice/AuthorizeExport`, `adminread.ExportDevice` | birim + canlı demo |
| Sağlık/hazırlık uçları (`/healthz`, `/readyz`) | ✅ | `adminapi` + `Store.Ping` | birim + smoke |
| Olay ayrıntısı (yapısal JSON) + sunucu-taraflı süzme | ✅ | `adminread`, `grpc` | birim + canlı demo |
| Cihaz OFFLINE otomasyonu (bayat heartbeat) | ✅ | `db/status.go`, `memstore` | birim |
| Web yönetim konsolu (SOC paneli, canlı yenileme) | ✅ | `adminapi/console.html` (embed) | httptest + canlı demo |
| Okuma API'si + görünürlük | ✅ | `server/internal/adminread` | birim |
| KVKK saklama otomasyonu | ✅ mantık / DB derlendi | `server/internal/retention` | birim |
| Şifreli PostgreSQL şeması | ✅ | `db/schema.sql` | — |

## İlk inceleme bulguları — karşılıklar

Bkz. `docs/threat-model.md`. Özet: kırık şema düzeltildi, şifreli-log yerine
at-rest + partitioning; düz-hash yerine **HMAC blind index**; yerel-saat yerine
**sunucu-saati çıpası**; hash-yerine **imza** OTA'da; enrollment/PKI eklendi;
RBAC + değişmez denetim izi.

**Canlı demo sırasında yakalanan bulgu (düzeltildi):** bellek-içi
`LookupAdmin` `is_active` süzmüyordu → pasifleştirilen yönetici hâlâ giriş
yapabiliyordu. PostgreSQL yolu (`WHERE ... AND is_active`) zaten doğruydu;
memstore ona eşitlendi + regresyon testi (`TestLookupAdminExcludesDeactivated`).

## Bilinçli olarak kapsam dışı / canlı doğrulanmayan

- **Kernel-seviye tamper koruması** (MiniFilter sürücüsü + PPL/ELAM): C/C++, EV
  sertifikası, WHQL/attestation imzalama, BSOD riski — Go kod tabanının dışında,
  çok yüksek maliyetli **ayrı proje**. Watchdog + liveness yalnız **ilk savunma**.
- **Canlı çalıştırılmayanlar** (mantık test edildi, ama bu ortamda çalıştırılmadı):
  - PostgreSQL'e karşı gerçek sorgular: bu makinede Postgres/Docker YOK, bu yüzden
    **yerelde** çalıştırılmadı. Ancak **CI'da** `postgres:16` servisine karşı DB
    uçtan uca smoke testi kurgulandı (`.github/workflows/ci.yml` → `db-test`):
    şema yüklenir, admin tohumlanır, pgx yolu tüm zincirle çalıştırılır.
  - Gerçek firewall izolasyonu (`netsh`/`iptables`) — ağı keser, riskli.
  - Gerçek süreç **sonlandırma** — testte sahte controller (gerçek süreç öldürülmedi).
  - Linux `/proc`+SIGKILL ve OS izolatörleri — yalnız cross-compile.
  - `go test -race` — C derleyicisi (gcc) yok; eşzamanlılık mutex/atomic ile doğru-inşa.
- **Operasyonel uçlar:** veri sahibi başvuru akışı (KVKK erişim/silme) **YAPILDI**
  (aşağı bkz.). Kalan: çalışan aydınlatma metni; lokal ONNX ML anomali hattı.
  İmzalı script yürütme YAPILDI (imza + sınırlı yürütme) ama gerçek sandbox/
  süreç-ağacı sonlandırma yok — ileri faz.

## Çalıştırma

```bash
make proto && go mod tidy && go test ./...   # üret + test
make dev-certs                                # geliştirme sertifikaları + env önerisi
go run ./tools/otasign -genkey -out ./ota-keys
go run ./tools/adminseed -email a@x -password '...' -role ADMIN
# db/schema.sql yükle, XDR_* env ayarla, bin/c2 ve bin/agent çalıştır
# yönetim konsolu: https://localhost:8445/
```

## Araçlar

- `tools/gencerts` — dev/prod CA + sunucu sertifikası.
- `tools/otasign` — OTA imza anahtarı üretimi + sürüm imzalama (+ SQL).
- `tools/adminseed` — yönetici parolası (Argon2id) + INSERT SQL.
- `tools/mkclient` — TEK DOSYA istemci kurulum betiği üreteci (benzersiz/token
  gömülü veya paylaşımlı/kod girişli; ajan ikilisi base64 gömülü; Win/Linux).

## Dağıtım / paketleme (nihai teslimat) — ✅

- `scripts/build-release.sh` — c2/agent/watchdog/gencerts çapraz derleme
  (Windows+Linux amd64 → `dist/`), sürüm ldflags ile damgalı.
- **Sunucu kurulumu:** `deploy/server/install-linux.sh` (systemd),
  `install-windows.ps1` (zamanlanmış görev) — PKI + ana anahtar + config +
  servis otomasyonu. `c2.env.example` şablonu.
- **İstemci kurulumu:** `mkclient` ile üretilen tek-dosya installer; token gömülü
  (benzersiz) veya kod girişli (paylaşımlı); ajan+CA gömülü; servis kurar.
- Ayrıntı: `deploy/README.md`. **Canlı doğrulandı:** üretilen benzersiz Windows
  installer'ın gömülü yükü çalıştırıldığında cihaz başarıyla kaydoldu.
