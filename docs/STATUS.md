# Durum Raporu — XDR/MDM

Bu belge, kod tabanının mevcut durumunu, neyin nasıl doğrulandığını ve bilinçli
olarak kapsam dışı bırakılanları özetler. Devir/gözden geçirme için referanstır.

## Özet

Mimari dökümdeki **yazılım-tarafı yeteneklerin tamamına yakını** kodlandı ve test
edildi. Güvenlik-kritik akışlar gerçek mTLS gRPC ve gerçek kripto ile **uçtan uca
kanıtlandı** (`server/internal/e2e`). Kernel-seviye tamper koruması bilinçli
olarak kapsam dışıdır (bkz. aşağıda).

- Dil: **Go** (tek dil), iletişim **gRPC + mTLS**, TLS 1.3.
- ~5 400 satır üretim Go + ~2 900 satır test.
- **86 test fonksiyonu / 21 test paketi**, tümü geçiyor (`go test ./...`).
- Cross-compile doğrulandı: Windows (native), Linux, macOS.

## Uçtan uca kanıtlanan zincir (e2e)

`enroll (PKI) → mTLS → heartbeat (sunucu-saati) → politika dağıtımı (push) →
OTA imza + rollout kapısı → komut teslimi (karantina) → tek-kullanımlık token`
— hepsi tek entegrasyon testinde, gerçek TCP + mTLS gRPC + gerçek imza/hash ile.

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
| Web yönetim konsolu | ✅ | `adminapi/console.html` (embed) | httptest |
| Okuma API'si + görünürlük | ✅ | `server/internal/adminread` | birim |
| KVKK saklama otomasyonu | ✅ mantık / DB derlendi | `server/internal/retention` | birim |
| Şifreli PostgreSQL şeması | ✅ | `db/schema.sql` | — |

## İlk inceleme bulguları — karşılıklar

Bkz. `docs/threat-model.md`. Özet: kırık şema düzeltildi, şifreli-log yerine
at-rest + partitioning; düz-hash yerine **HMAC blind index**; yerel-saat yerine
**sunucu-saati çıpası**; hash-yerine **imza** OTA'da; enrollment/PKI eklendi;
RBAC + değişmez denetim izi.

## Bilinçli olarak kapsam dışı / canlı doğrulanmayan

- **Kernel-seviye tamper koruması** (MiniFilter sürücüsü + PPL/ELAM): C/C++, EV
  sertifikası, WHQL/attestation imzalama, BSOD riski — Go kod tabanının dışında,
  çok yüksek maliyetli **ayrı proje**. Watchdog + liveness yalnız **ilk savunma**.
- **Canlı çalıştırılmayanlar** (mantık test edildi, ama bu ortamda çalıştırılmadı):
  - PostgreSQL'e karşı gerçek sorgular (Postgres kurulu değil) — pgx katmanı derlendi.
  - Gerçek firewall izolasyonu (`netsh`/`iptables`) — ağı keser, riskli.
  - Gerçek süreç **sonlandırma** — testte sahte controller (gerçek süreç öldürülmedi).
  - Linux `/proc`+SIGKILL ve OS izolatörleri — yalnız cross-compile.
  - `go test -race` — C derleyicisi (gcc) yok; eşzamanlılık mutex/atomic ile doğru-inşa.
- **Operasyonel uçlar (yapılmadı):** veri sahibi başvuru akışı (KVKK erişim/silme),
  çalışan aydınlatma metni;
  lokal ONNX ML anomali hattı. İmzalı script yürütme YAPILDI (imza + sınırlı
  yürütme) ama gerçek sandbox/süreç-ağacı sonlandırma yok — ileri faz.

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

- `tools/gencerts` — dev CA + sunucu sertifikası.
- `tools/otasign` — OTA imza anahtarı üretimi + sürüm imzalama (+ SQL).
- `tools/adminseed` — yönetici parolası (Argon2id) + INSERT SQL.
