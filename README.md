# XDR / MDM — Kurumsal Uç Nokta Güvenliği ve Ajan Yönetim Sistemi

Yetkili kurumsal ortam için (şirkete ait cihazlar, bildirilmiş kullanım
politikası, IT yönetimi) tasarlanmış uç nokta güvenlik ve yönetim platformu.
Tek dil: **Go**. Ajan ↔ C2 iletişimi **gRPC + mTLS**, şema-öncesi kaynak
sürüm bu iskelettir.

> **Durum:** Faz 2 tamam ve **uçtan uca derleniyor**. C2 (iki gRPC sunucu:
> mTLS'li AgentService + TLS'li EnrollmentService) ve ajan (enroll → mTLS
> heartbeat → store-and-forward olay gönderimi) bağlandı. Üretilen proto,
> pgx DB katmanı, kriptografik ilkeller ve ajan-domain motoru yerinde;
> 17 birim testi geçiyor.
>
> **Derleme + test:**
> ```bash
> make proto        # gen/ üretir (buf)
> go mod tidy
> go test ./...     # 5 paket, 17 test
> make build        # bin/c2, bin/agent, bin/watchdog
> ```
>
> **Runtime kanıtlandı:** `server/internal/e2e` gerçek mTLS gRPC üzerinden
> uçtan-uca akışı doğrular — enroll → mTLS heartbeat (sunucu saati) → olay
> gönderimi (ack) → tek-kullanımlık token reddi (bellek-içi store, Postgres'siz):
> ```bash
> make e2e
> ```
> **Politika uygulama (Faz 3):** ajan süreçleri izler, yasaklıları sonlandırır
> (`agent/internal/enforce`) ve `POLICY_VIOLATION` üretir; Windows kontrolcüsü
> gerçek süreçlerle doğrulandı.
>
> **OTA imza doğrulama (Faz 4):** güncelleme manifestoları Ed25519 ile imzalanır
> (`tools/otasign`), ajan indirmeden önce imzayı gömülü public key ile doğrular —
> yalnız SHA-256 yetmez (#4). Ajan paketi indirir, SHA-256 doğrular ve atomik
> olarak staging'e yazar (`update.Prepare`); **watchdog** çalıştırmalar arasında
> swap eder, yeni sürüm çabuk çökerse **rollback** yapar (`agent/internal/watchdog`).
>
> **Ağ keşfi (Faz 5a):** ajan komşu/ARP tablosunu tarar (`agent/internal/discovery`),
> yeni cihazları tespit edip yetkili/yetkisiz sınıflar ve `NETWORK_DISCOVERY`
> üretir; Windows'ta gerçek ağda doğrulandı.
>
> **Karantina (Faz 5b):** idempotent karantina yöneticisi (`agent/internal/quarantine`)
> sahte izolatörle test edildi; Windows (`netsh`) ve Linux (`iptables`) izolatörleri
> derlendi (canlı çalıştırılmadı — ağı keser). Ajan sunucudan gelen QUARANTINE
> komutlarını uygular.
>
> **Admin API (RBAC):** `server/internal/adminapi` — Argon2id parola + HMAC oturum
> token'ı + Bearer korumalı REST uçları (login, enrollment-token, karantina,
> politika CRUD); komut kuyruğu heartbeat ile ajana teslim edilir (`device_commands`).
> `tools/adminseed` ile yönetici tohumlanır.
>
> **Web konsolu (tamam):** C2 admin sunucusundan aynı köken gömülü tek-sayfa konsol
> (`GET /`) — login, token üretimi, karantina, politika, **canlı Cihazlar/Olaylar
> tabloları** (`GET /api/devices`, `/api/events`; şifreli alanlar sunucuda deşifre).
> Linux enforcement ve StreamPolicies push henüz eksik.
>
> **Canlı ikililer için (Postgres ile):** `make dev-certs` ile geliştirme
> sertifikaları üret (komut çıktısı `XDR_*` env değişkenlerini önerir),
> `db/schema.sql`'i yükle, sonra `bin/c2` ve `bin/agent` çalıştır.

## Bileşenler

| Bileşen | Dizin | Rol |
|---|---|---|
| C2 sunucusu | `server/` | Log toplama, politika dağıtımı, OTA, enrollment/PKI |
| Uç nokta ajanı | `agent/` | Politika uygulama, olay toplama, ağ keşfi |
| Watchdog | `agent/cmd/watchdog` + `internal/watchdog` | Ajanı canlı tutar + OTA swap/rollback (ilk savunma) |
| Proto sözleşmeleri | `proto/xdr/v1` | gRPC servis + mesaj tanımları |
| Veritabanı | `db/` | Düzeltilmiş PostgreSQL şeması + migration'lar |
| Dokümantasyon | `docs/` | Mimari, tehdit modeli, KVKK notları |

## Gereksinimler (geliştirme)

- Go 1.23+
- [buf](https://buf.build) (proto üretimi) veya protoc + eklentiler
- PostgreSQL 14+ (`uuid-ossp`, `pgcrypto` eklentileri)

## Hızlı başlangıç

```bash
# 1) Proto kodunu üret
make proto

# 2) Bağımlılıkları düzenle
make tidy

# 3) İkilileri derle
make build        # bin/c2, bin/agent, bin/watchdog

# 4) Veritabanı şemasını kur
psql -U postgres -d xdr -f db/schema.sql
```

## Kurulum ve dağıtım (planlanan — faz sonu)

- **Sunucu (C2) installer:** Tek dosya kurulum (Windows: MSI, Linux: deb/rpm)
  ile C2 + PostgreSQL yapılandırması.
- **İstemci (agent) installer:** Her cihaz için **benzersiz** kurulum paketi.
  Paket, tek kullanımlık bir **enrollment token** ile damgalanır; ajan ilk
  çalıştığında bu token ile kendini kaydeder (PKI bootstrap) ve mTLS sertifikası
  alır. Ayrıntı ve tasarım kararı için [docs/architecture.md](docs/architecture.md#kurulum-ve-paketleme).

## Yol haritası

Bkz. [docs/architecture.md](docs/architecture.md) — fazlara bölünmüş plan.
İnceleme bulguları ve karşılığında alınan kararlar [docs/threat-model.md](docs/threat-model.md)
içinde.
