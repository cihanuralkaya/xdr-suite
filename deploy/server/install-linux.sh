#!/usr/bin/env bash
# XDR C2 sunucu kurulumu (Linux, systemd).
# Yanında bulunması gerekenler: c2, gencerts (dist/linux-amd64/'den).
#
# Kullanım (root):
#   sudo ./install-linux.sh [SUNUCU_ADI]
# SUNUCU_ADI: sertifika SAN'ı (ajanların bağlanacağı ad; vars. xdr-c2).
set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "root olarak çalıştırın (sudo)." >&2; exit 1; }

SERVER_NAME="${1:-xdr-c2}"
HERE="$(cd "$(dirname "$0")" && pwd)"
INSTALL_DIR="/opt/xdr"
CONF_DIR="/etc/xdr"
PKI_DIR="$CONF_DIR/pki"

command -v openssl >/dev/null 2>&1 || { echo "openssl gerekli." >&2; exit 1; }
[ -x "$HERE/c2" ] || { echo "c2 ikilisi bulunamadı ($HERE/c2)." >&2; exit 1; }
[ -x "$HERE/gencerts" ] || { echo "gencerts bulunamadı ($HERE/gencerts)." >&2; exit 1; }

mkdir -p "$INSTALL_DIR" "$PKI_DIR"
install -m 0755 "$HERE/c2" "$INSTALL_DIR/c2"

# Sertifikalar (yoksa üret; varsa dokunma).
if [ ! -f "$PKI_DIR/ca.crt" ]; then
  "$HERE/gencerts" -out "$PKI_DIR" -name "$SERVER_NAME"
  chmod 600 "$PKI_DIR"/*.key
  echo "PKI üretildi: $PKI_DIR"
else
  echo "Mevcut PKI korunuyor: $PKI_DIR"
fi

# Ana anahtar (yoksa üret).
ENV_FILE="$CONF_DIR/c2.env"
if [ ! -f "$ENV_FILE" ]; then
  MASTER_KEY="$(openssl rand -base64 32)"
  ADMIN_PASS="$(openssl rand -base64 12)"
  cat > "$ENV_FILE" <<EOF
XDR_DATABASE_URL=
XDR_MASTER_KEY=$MASTER_KEY
XDR_CA_CERT=$PKI_DIR/ca.crt
XDR_CA_KEY=$PKI_DIR/ca.key
XDR_SERVER_CERT=$PKI_DIR/server.crt
XDR_SERVER_KEY=$PKI_DIR/server.key
XDR_LISTEN_AGENT=:8443
XDR_LISTEN_ENROLL=:8444
XDR_LISTEN_ADMIN=:8445
XDR_DEMO_ADMIN_EMAIL=admin@local
XDR_DEMO_ADMIN_PASSWORD=$ADMIN_PASS
XDR_RETENTION_DAYS=90
EOF
  chmod 600 "$ENV_FILE"
  echo "Yapılandırma üretildi: $ENV_FILE"
  echo ">>> Konsol girişi: admin@local / $ADMIN_PASS  (DEMO/bellek-içi mod)"
  echo ">>> Üretim için: XDR_DATABASE_URL ayarlayın ve tools/adminseed ile yönetici ekleyin."
else
  echo "Mevcut yapılandırma korunuyor: $ENV_FILE"
fi

cat > /etc/systemd/system/xdr-c2.service <<UNITEOF
[Unit]
Description=XDR C2 (Command & Control)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=$ENV_FILE
ExecStart=$INSTALL_DIR/c2
Restart=always
RestartSec=5
# Sertleştirme
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=$CONF_DIR
ProtectHome=true

[Install]
WantedBy=multi-user.target
UNITEOF

systemctl daemon-reload
systemctl enable --now xdr-c2.service
echo "XDR C2 kuruldu ve başlatıldı (systemctl status xdr-c2)."
echo "Ajan istemci setup'ı üretmek için (aynı makinede):"
echo "  mkclient -os windows -server $SERVER_NAME -ca $PKI_DIR/ca.crt -agent agent.exe -token <TOKEN> -out setup.ps1"
