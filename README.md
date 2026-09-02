# XDR / MDM — Kurumsal Uç Nokta Güvenliği ve Ajan Yönetim Sistemi

[![CI](https://github.com/cihanuralkaya/xdr-suite/actions/workflows/ci.yml/badge.svg)](https://github.com/cihanuralkaya/xdr-suite/actions/workflows/ci.yml)

Yetkili kurumsal ortam için (şirkete ait cihazlar, bildirilmiş kullanım
politikası, IT yönetimi) tasarlanmış uç nokta güvenlik ve yönetim platformu.
Tek dil: **Go**. Ajan ↔ C2 iletişimi **gRPC + mTLS** (TLS 1.3).

> **Durum: özellik-tam, CI yeşil, dağıtıma hazır.** Ayrıntılı yetenek matrisi ve
> ne-nasıl-doğrulandı için **[docs/STATUS.md](docs/STATUS.md)**.
>
> - **134 test / 26 paket** geçiyor; **CI** (`.github/workflows/ci.yml`) her push'ta
>   `go vet` + test + **uçtan uca smoke** + **gerçek PostgreSQL'e karşı DB testi** +
>   çapraz derleme çalıştırır — hepsi yeşil.
> - Uçtan uca kanıtlı zincir: enroll (PKI) → mTLS heartbeat (sunucu-saati) → olay →
>   politika push → OTA imza + rollout → komut teslimi → tek-kullanımlık token
>   (`server/internal/e2e`, `make e2e`).
> - **Güvenlik:** HMAC blind index, AES-256-GCM alan şifreleme, Argon2id parola,
>   Ed25519 OTA/script imzası, RBAC + değişmez denetim izi, giriş kaba-kuvvet
>   koruması, sıkılaştırılmış güvenlik başlıkları (HSTS/CSP).
> - **KVKK:** at-rest şifreleme + partition-bazlı saklama; **veri sahibi hakları**
>   (erişim/dışa aktarma + silme, denetim korunur).
> - **Konsol:** gömülü tek-sayfa SOC paneli — cihazlar/olaylar/politikalar/yöneticiler,
>   **canlı SSE push**, önem grafiği, arama, CSV dışa aktarma, sağlık uçları
>   (`/healthz`, `/readyz`).
> - **Dağıtım:** çapraz derleme + tek-dosya istemci installer üreteci (token gömülü
>   veya kod girişli, Win/Linux) + sunucu kurulum betikleri — bkz.
>   **[deploy/README.md](deploy/README.md)**.
> - Üçüncü taraf lisanslar (telif uyumu): **[docs/THIRD_PARTY_LICENSES.md](docs/THIRD_PARTY_LICENSES.md)**
>   (hepsi izin verici; copyleft yok).

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

## Kurulum ve dağıtım ✅

Tam akış: **[deploy/README.md](deploy/README.md)**.

- **Release:** `scripts/build-release.sh 1.0.0` — c2/agent/watchdog/gencerts
  Windows+Linux için çapraz derlenir (`dist/`).
- **Sunucu (C2):** `deploy/server/install-linux.sh` (systemd) /
  `install-windows.ps1` (zamanlanmış görev) — PKI + ana anahtar + config + servis
  otomatik.
- **İstemci (agent):** `tools/mkclient` her cihaz için **tek-dosya** kurulum betiği
  üretir — **benzersiz** (enrollment token gömülü, otomatik kaydolur) veya
  **paylaşımlı** (kod girişli); ajan ikilisi base64 gömülü, servisi kurar.
  Windows (`.ps1`) + Linux (`.sh`).

## Yol haritası

Bkz. [docs/architecture.md](docs/architecture.md) — fazlara bölünmüş plan.
İnceleme bulguları ve karşılığında alınan kararlar [docs/threat-model.md](docs/threat-model.md)
içinde.
