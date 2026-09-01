# XDR/MDM — Dağıtım ve Kurulum

Bu dizin, sunucu (C2) ve uç istemci (agent) kurulum akışını içerir. Tüm ikililer
tek dilde (Go) çapraz derlenir; kurulum betikleri **tek dosya, kendi kendine
yeten** olacak şekilde üretilir.

## 1. Release ikililerini derle

```bash
scripts/build-release.sh 1.0.0
```

Çıktı: `dist/<os>-<arch>/` altında `c2`, `agent`, `watchdog`, `gencerts`
(Windows ve Linux, amd64). `VERSION` ajan sürümüne damgalanır.

## 2. Sunucuyu (C2) kur

Sunucu ikililerini (`c2`, `gencerts`) hedef makineye kopyala; kurulum betiğini
yanına koy ve çalıştır. Betik: PKI üretir, 32 baytlık ana anahtar + rastgele
yönetici parolası üretir, yapılandırmayı yazar, servisi kurar ve başlatır.

**Linux (systemd):**
```bash
sudo deploy/server/install-linux.sh xdr-c2      # arg: sertifika SAN adı
```

**Windows (zamanlanmış görev, SYSTEM):**
```powershell
.\deploy\server\install-windows.ps1 -ServerName xdr-c2
```

Kurulum sonunda konsol girişi (admin@local / üretilen parola) ekrana yazılır.
Yönetim konsolu: `https://<sunucu>:8445/`

> Üretim: `XDR_DATABASE_URL` ayarlayıp PostgreSQL'e geçin ve yöneticiyi
> `tools/adminseed` ile ekleyin (bkz. `db/schema.sql`). Boş bırakılırsa
> **bellek-içi demo modu** (kalıcılık yok) çalışır.

## 3. İstemci (agent) setup'ı üret

Konsoldan bir **enrollment token** üretin, sonra `mkclient` ile hedef cihaz için
kurulum dosyası oluşturun. İki mod:

- **Benzersiz setup** (`-token <TOKEN>`): token betiğe gömülür; kullanıcı yalnız
  çalıştırır, otomatik kaydolur. Her cihaz için ayrı üretilir.
- **Paylaşımlı setup** (`-token` verilmez): tek betik birçok cihaza dağıtılır;
  çalışırken kullanıcıdan kayıt kodu istenir.

Ajan ikilisi `-agent` ile verilirse base64 **gömülür** (gerçek tek dosya).

**Windows (benzersiz, ajan gömülü):**
```bash
mkclient -os windows -server c2.sirket.local \
  -ca /etc/xdr/pki/ca.crt -agent dist/windows-amd64/agent.exe \
  -token ABC123... -out xdr-agent-setup.ps1
```
Hedefte (Yönetici): `.\xdr-agent-setup.ps1`

**Linux (paylaşımlı, kod girişli):**
```bash
mkclient -os linux -server c2.sirket.local \
  -ca /etc/xdr/pki/ca.crt -agent dist/linux-amd64/agent \
  -out xdr-agent-setup.sh
```
Hedefte (root): `sudo ./xdr-agent-setup.sh` → kayıt kodunu girin.

`-safe-mode` bayrağı: karantina gerçek ağ değişikliği yapmaz (test/dağıtım
başlangıcı için güvenli).

## Kurulan konumlar

| | Sunucu | Ajan |
|---|---|---|
| Linux ikili | `/opt/xdr/c2` | `/opt/xdr-agent/agent` |
| Linux yapılandırma | `/etc/xdr/` | `/etc/xdr-agent/` |
| Linux servis | `xdr-c2.service` | `xdr-agent.service` |
| Windows ikili | `%ProgramFiles%\XDR Server\` | `%ProgramFiles%\XDR Agent\` |
| Windows servis | Görev: `XDR C2 Server` | Görev: `XDR Agent` |

## Güvenlik notları

- Ana anahtar (`XDR_MASTER_KEY`) ve CA özel anahtarı yalnız sunucuda kalır;
  yapılandırma dosyaları `600` izinlidir.
- Ajan setup'ı CA sertifikasını (genel) ve tek-kullanımlık enrollment token'ı
  taşır — özel anahtar taşımaz. Token kaydolunca tüketilir.
- mTLS TLS 1.3; ajan kimliği enrollment'ta CSR ile üretilir, özel anahtar
  cihazdan çıkmaz.
