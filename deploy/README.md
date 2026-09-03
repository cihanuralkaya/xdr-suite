# XDR/MDM — Dağıtım ve Kurulum
# XDR/MDM — Deployment & Installation

**Türkçe** · [English](#english)

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

---

# English

This directory contains the installation flow for the server (C2) and the endpoint
client (agent). All binaries are cross-compiled in a single language (Go); the
install scripts are generated to be **single-file, self-contained**.

## 1. Build the release binaries

```bash
scripts/build-release.sh 1.0.0
```

Output: `c2`, `agent`, `watchdog`, `gencerts` under `dist/<os>-<arch>/` (Windows and
Linux, amd64). `VERSION` is stamped into the agent version.

## 2. Install the server (C2)

Copy the server binaries (`c2`, `gencerts`) to the target machine; place the install
script alongside and run it. The script generates PKI, a 32-byte master key + a random
admin password, writes the configuration, and installs and starts the service.

**Linux (systemd):**
```bash
sudo deploy/server/install-linux.sh xdr-c2      # arg: certificate SAN name
```

**Windows (scheduled task, SYSTEM):**
```powershell
.\deploy\server\install-windows.ps1 -ServerName xdr-c2
```

At the end of installation the console login (admin@local / generated password) is
printed to the screen. Admin console: `https://<server>:8445/`

> Production: set `XDR_DATABASE_URL` to switch to PostgreSQL and add the admin with
> `tools/adminseed` (see `db/schema.sql`). If left empty, an **in-memory demo mode**
> (no persistence) runs.

## 3. Generate the client (agent) setup

Generate an **enrollment token** from the console, then build an installer for the
target device with `mkclient`. Two modes:

- **Unique setup** (`-token <TOKEN>`): the token is embedded in the script; the user
  just runs it and it auto-enrolls. Generated separately per device.
- **Shared setup** (no `-token`): a single script is distributed to many devices; it
  prompts the user for an enrollment code at runtime.

If the agent binary is provided with `-agent`, it is base64-**embedded** (a true
single file).

**Windows (unique, agent embedded):**
```bash
mkclient -os windows -server c2.company.local \
  -ca /etc/xdr/pki/ca.crt -agent dist/windows-amd64/agent.exe \
  -token ABC123... -out xdr-agent-setup.ps1
```
On the target (Administrator): `.\xdr-agent-setup.ps1`

**Linux (shared, code-entry):**
```bash
mkclient -os linux -server c2.company.local \
  -ca /etc/xdr/pki/ca.crt -agent dist/linux-amd64/agent \
  -out xdr-agent-setup.sh
```
On the target (root): `sudo ./xdr-agent-setup.sh` -> enter the enrollment code.

The `-safe-mode` flag: quarantine makes no real network changes (safe for
testing / the start of a rollout).

## Installed locations

| | Server | Agent |
|---|---|---|
| Linux binary | `/opt/xdr/c2` | `/opt/xdr-agent/agent` |
| Linux config | `/etc/xdr/` | `/etc/xdr-agent/` |
| Linux service | `xdr-c2.service` | `xdr-agent.service` |
| Windows binary | `%ProgramFiles%\XDR Server\` | `%ProgramFiles%\XDR Agent\` |
| Windows service | Task: `XDR C2 Server` | Task: `XDR Agent` |

## Security notes

- The master key (`XDR_MASTER_KEY`) and the CA private key stay on the server only;
  configuration files have `600` permissions.
- The agent setup carries the CA certificate (public) and a single-use enrollment
  token - it carries no private key. The token is consumed once enrollment succeeds.
- mTLS TLS 1.3; the agent identity is produced via a CSR at enrollment, and the
  private key never leaves the device.
