# Üçüncü Taraf Lisansları — XDR/MDM

Bu belge, dağıtılan ikililere (**c2**, **agent**, **watchdog**) derlenen üçüncü
taraf Go modüllerini ve lisanslarını listeler. Lisans türleri, Go modül
önbelleğindeki **gerçek `LICENSE` dosyalarından** doğrulanmıştır (ezber değil).

## Özet — telif/uyum durumu

- Dağıtılan tüm bağımlılıklar **izin verici (permissive)** lisanslıdır:
  **MIT**, **BSD-3-Clause**, **Apache-2.0**.
- **Tüm bağımlılık grafiğinde** (test + derleme araçları dahil) **copyleft
  YOK** — GPL / LGPL / AGPL / MPL / CDDL / EPL bulunmadı (otomatik tarandı).
- Sonuç: **kapalı kaynak / ticari dağıtımda kaynak-açıklama yükümlülüğü yoktur.**
  Tek yükümlülük **atıf**: bu lisans metinlerinin (telif bildirimleri) dağıtımla
  birlikte korunması. Apache-2.0 için varsa `NOTICE` dosyası da eklenmelidir.

## İkililere derlenen bağımlılıklar (dağıtılan)

`go version -m <ikili>` çıktısından türetilmiştir (ikiliye gömülü kesin liste).

| Modül | Sürüm | Lisans |
|---|---|---|
| github.com/jackc/pgx/v5 | v5.6.0 | MIT |
| github.com/jackc/pgpassfile | v1.0.0 | MIT |
| github.com/jackc/pgservicefile | v0.0.0-20221227161230-091c0ba34f0a | MIT |
| github.com/jackc/puddle/v2 | v2.2.1 | MIT |
| golang.org/x/crypto | v0.36.0 | BSD-3-Clause |
| golang.org/x/net | v0.38.0 | BSD-3-Clause |
| golang.org/x/sync | v0.12.0 | BSD-3-Clause |
| golang.org/x/sys | v0.31.0 | BSD-3-Clause |
| golang.org/x/text | v0.23.0 | BSD-3-Clause |
| google.golang.org/grpc | v1.66.0 | Apache-2.0 |
| google.golang.org/protobuf | v1.34.2 | BSD-3-Clause |
| google.golang.org/genproto/googleapis/rpc | v0.0.0-20240604185151-ef581f913117 | Apache-2.0 |

Lisans dağılımı: **MIT ×4**, **BSD-3-Clause ×6**, **Apache-2.0 ×2**.

> Not: Go **standart kütüphanesi** (kripto, TLS, net/http, x509…) BSD-3-Clause'dur
> ve projenin çekirdek güvenlik paketleri yalnız stdlib kullanır.

## Yalnızca derleme/test araçları (İKİLİYE GİRMEZ, dağıtılmaz)

Bunlar CI/geliştirmede kullanılır; son ürüne dahil edilmez, dolayısıyla dağıtım
yükümlülüğü doğurmaz. Yine de hepsi izin vericidir:

- `buf` (proto lint/generate) — Apache-2.0
- `protoc-gen-go`, `protoc-gen-go-grpc` — BSD-3-Clause / Apache-2.0
- `github.com/stretchr/testify` (MIT), `github.com/google/go-cmp` (BSD-3-Clause),
  `github.com/davecgh/go-spew` (ISC), `github.com/pmezard/go-difflib` (BSD-3),
  `gopkg.in/yaml.v3` (MIT+Apache-2.0), `gopkg.in/check.v1` (BSD-2-Clause),
  grpc'nin geçişli test/tooling bağımlılıkları (envoyproxy/*, cncf/xds,
  planetscale/vtprotobuf, glog…) — Apache-2.0 / BSD.

## Yükümlülüklerin yerine getirilmesi

1. **Atıf (zorunlu):** Bu tablodaki modüllerin `LICENSE` metinlerini dağıtımla
   birlikte bulundurun (ör. bu belge + ilgili lisans kopyaları). Bu dosya
   atıf kaydı olarak yeterlidir; istenirse tam lisans metinleri eklenebilir.
2. **Apache-2.0 (grpc, genproto):** Varsa `NOTICE` içeriğini koruyun; kaynakta
   değişiklik yaptıysanız belirtin (bu projede bu modüller değiştirilmemiştir).
3. **Copyleft:** Yok — ek yükümlülük yoktur.

## Yeniden üretme

```bash
# İkiliye gömülü kesin modül listesi:
go build -o /tmp/c2 ./server/cmd/c2 && go version -m /tmp/c2 | awk '$1=="dep"'
# Lisans türü, her modülün $(go env GOMODCACHE)/<modül>@<sürüm>/LICENSE dosyasından.
```
