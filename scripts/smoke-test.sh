#!/usr/bin/env bash
# smoke-test.sh — uçtan uca kabul testi: gerçek c2 + gerçek agent'ı ayağa
# kaldırır, kayıt → heartbeat → olay → admin eylem → SSE zincirini iddialarla
# doğrular. Bellek-içi demo modu (harici bağımlılık yok). CI'da da çalışır.
#
# Çıkış kodu 0 = tüm iddialar geçti.
set -uo pipefail
cd "$(dirname "$0")/.."

EXT=""; [ "${OS:-}" = "Windows_NT" ] && EXT=".exe"
WORK="$(mktemp -d 2>/dev/null || echo "./_smoke")"; mkdir -p "$WORK"
AGENT_PORT=18443; ENROLL_PORT=18444; ADMIN_PORT=18445
B="https://127.0.0.1:${ADMIN_PORT}"
PIDS=()
FAILED=0

log(){ printf '  %s\n' "$*"; }
pass(){ printf '  \033[32m✓\033[0m %s\n' "$*"; }
fail(){ printf '  \033[31m✗ %s\033[0m\n' "$*"; FAILED=1; }
cleanup(){
  for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null; done
  rm -rf "$WORK" 2>/dev/null
}
trap cleanup EXIT

echo "[1/6] İkilileri derle"
go build -o "$WORK/c2$EXT" ./server/cmd/c2 || { echo "c2 derlenemedi"; exit 1; }
go build -o "$WORK/agent$EXT" ./agent/cmd/agent || { echo "agent derlenemedi"; exit 1; }
go build -o "$WORK/gencerts$EXT" ./tools/gencerts || { echo "gencerts derlenemedi"; exit 1; }
pass "c2, agent, gencerts derlendi"

echo "[2/6] PKI + sunucuyu başlat"
"$WORK/gencerts$EXT" -out "$WORK/pki" -name xdr-c2 >/dev/null
MASTER_KEY="$(openssl rand -base64 32 2>/dev/null || head -c32 /dev/urandom | base64)"
XDR_MASTER_KEY="$MASTER_KEY" \
XDR_DEMO_ADMIN_PASSWORD="smoke1234" \
XDR_CA_CERT="$WORK/pki/ca.crt" XDR_CA_KEY="$WORK/pki/ca.key" \
XDR_SERVER_CERT="$WORK/pki/server.crt" XDR_SERVER_KEY="$WORK/pki/server.key" \
XDR_LISTEN_AGENT=":$AGENT_PORT" XDR_LISTEN_ENROLL=":$ENROLL_PORT" XDR_LISTEN_ADMIN=":$ADMIN_PORT" \
  "$WORK/c2$EXT" > "$WORK/c2.log" 2>&1 &
PIDS+=($!)

# Admin API hazır olana dek bekle (maks ~10 sn)
ready=0
for _ in $(seq 1 50); do
  if curl -sk "$B/" -o /dev/null 2>/dev/null; then ready=1; break; fi
  sleep 0.2
done
[ "$ready" = 1 ] && pass "C2 dinliyor (:$ADMIN_PORT)" || { fail "C2 başlamadı"; cat "$WORK/c2.log"; exit 1; }

echo "[3/6] Giriş + enrollment token"
TOK="$(curl -sk "$B/api/login" -X POST -H 'Content-Type: application/json' \
  -d '{"email":"admin@local","password":"smoke1234"}' | sed -E 's/.*"token":"([^"]+)".*/\1/')"
[ -n "$TOK" ] && [ "$TOK" != "$(printf '{')" ] && pass "yönetici girişi başarılı" || fail "giriş başarısız"
ETOK="$(curl -sk "$B/api/enrollment-tokens" -X POST -H "Authorization: Bearer $TOK" -d '{}' \
  | sed -E 's/.*"enrollment_token":"([^"]+)".*/\1/')"
[ ${#ETOK} -ge 16 ] && pass "enrollment token üretildi" || fail "token üretilemedi"

echo "[4/6] Ajanı kaydet + olay akışını doğrula"
XDR_ENROLL_ADDR="127.0.0.1:$ENROLL_PORT" XDR_AGENT_ADDR="127.0.0.1:$AGENT_PORT" \
XDR_SERVER_NAME="xdr-c2" XDR_CA_PEM="$WORK/pki/ca.crt" XDR_ENROLL_TOKEN="$ETOK" \
XDR_AGENT_DATA="$WORK/agent-data" XDR_HEARTBEAT_INTERVAL="2s" XDR_SAFE_MODE="1" \
  "$WORK/agent$EXT" > "$WORK/agent.log" 2>&1 &
PIDS+=($!)

# Cihaz görünene dek bekle
dev=0
for _ in $(seq 1 40); do
  n="$(curl -sk "$B/api/devices" -H "Authorization: Bearer $TOK" | grep -o '"id"' | wc -l)"
  if [ "$n" -ge 1 ]; then dev=1; break; fi
  sleep 0.25
done
[ "$dev" = 1 ] && pass "ajan kaydoldu (cihaz listede)" || fail "cihaz kaydı görünmedi"
grep -q "kimlik hazır" "$WORK/agent.log" && pass "ajan kimliği üretildi (CSR imzalandı)" || fail "ajan kimliği yok"

evc="$(curl -sk "$B/api/events?limit=50" -H "Authorization: Bearer $TOK" | grep -o '"id"' | wc -l)"
[ "$evc" -ge 1 ] && pass "olaylar alındı ($evc olay)" || fail "olay yok"

echo "[5/6] Admin eylemleri + okuma uçları"
DID="$(curl -sk "$B/api/devices" -H "Authorization: Bearer $TOK" | sed -E 's/.*"id":"([^"]+)".*/\1/')"
curl -sk "$B/api/devices/collect-diagnostics" -X POST -H "Authorization: Bearer $TOK" \
  -d "{\"device_id\":\"$DID\"}" -o /dev/null
sleep 0.3
curl -sk "$B/api/audit?limit=20" -H "Authorization: Bearer $TOK" | grep -q "COLLECT_DIAGNOSTICS" \
  && pass "tanılama komutu kuyruğa alındı + denetlendi" || fail "tanılama denetim izinde yok"
curl -sk "$B/api/summary" -H "Authorization: Bearer $TOK" | grep -q "devices_total" \
  && pass "özet uç yanıt verdi" || fail "özet uç başarısız"
curl -sk "$B/api/policies" -H "Authorization: Bearer $TOK" | grep -q "policies" \
  && pass "politika listeleme uç yanıt verdi" || fail "politika uç başarısız"

echo "[6/6] SSE canlı akış"
SSE="$(curl -sk -N --max-time 5 "$B/api/stream" -H "Authorization: Bearer $TOK" 2>/dev/null)"
echo "$SSE" | grep -q '"type":"' && pass "SSE bildirim iletti" || fail "SSE bildirim gelmedi"

echo
if [ "$FAILED" = 0 ]; then
  echo -e "\033[32mSMOKE TEST GEÇTİ — uçtan uca zincir sağlıklı.\033[0m"; exit 0
else
  echo -e "\033[31mSMOKE TEST BAŞARISIZ.\033[0m"; echo "--- c2.log ---"; tail -20 "$WORK/c2.log"; exit 1
fi
