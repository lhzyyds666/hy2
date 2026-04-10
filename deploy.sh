#!/usr/bin/env bash
# One-shot installer for hy2 — Hysteria2 + Xray + subscription panel.
# Run as root on a fresh Debian/Ubuntu VPS.
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HY_DIR=/root/hysteria
XRAY_ETC=/usr/local/etc/xray
SYSTEMD_DIR=/etc/systemd/system
TEMPLATE_DIR=/root  # subscription_service.py scans /root/*.yaml for clash templates

log()  { printf '\033[1;32m[+]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[!]\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m[x]\033[0m %s\n' "$*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "Must run as root."

# ---------- 1. Load .env ----------
ENV_FILE="$REPO_DIR/.env"
[[ -f "$ENV_FILE" ]] || die "$ENV_FILE not found. Copy .env.example → .env and fill it in."
# shellcheck disable=SC1090
set -a; . "$ENV_FILE"; set +a

REQUIRED=(
  HY_SERVER_HOST HY_API_SECRET HY_OBFS_PASSWORD
  XRAY_REALITY_PRIVATE_KEY XRAY_REALITY_PUBLIC_KEY
  XRAY_REALITY_SHORT_ID XRAY_CLIENT_UUID
)
for v in "${REQUIRED[@]}"; do
  val="${!v:-}"
  [[ -n "$val" && "$val" != replace_me* && "$val" != your.server* ]] || die "$v is not set in .env"
done

# ---------- 2. OS packages ----------
log "Installing OS packages..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -y >/dev/null
apt-get install -y curl openssl iptables ca-certificates python3 >/dev/null

# ---------- 3. Install hysteria binary ----------
if ! command -v hysteria >/dev/null 2>&1; then
  log "Installing hysteria..."
  bash <(curl -fsSL https://get.hy2.sh/)
else
  log "hysteria already installed: $(hysteria version 2>/dev/null | head -1 || true)"
fi

# Disable the stock hysteria-server@ instance — we use our own unit.
systemctl disable --now hysteria-server.service 2>/dev/null || true

# ---------- 4. Install xray binary ----------
if ! command -v xray >/dev/null 2>&1; then
  log "Installing xray..."
  bash -c "$(curl -fsSL https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install
else
  log "xray already installed: $(xray version 2>/dev/null | head -1 || true)"
fi

# ---------- 5. Render templates ----------
render() {
  # render <src_template> <dest>
  local src="$1" dst="$2"
  sed \
    -e "s|__HY_API_SECRET__|${HY_API_SECRET}|g" \
    -e "s|__HY_OBFS_PASSWORD__|${HY_OBFS_PASSWORD}|g" \
    -e "s|__HY_SERVER_HOST__|${HY_SERVER_HOST}|g" \
    -e "s|__XRAY_REALITY_PRIVATE_KEY__|${XRAY_REALITY_PRIVATE_KEY}|g" \
    -e "s|__XRAY_REALITY_PUBLIC_KEY__|${XRAY_REALITY_PUBLIC_KEY}|g" \
    -e "s|__XRAY_REALITY_SHORT_ID__|${XRAY_REALITY_SHORT_ID}|g" \
    -e "s|__XRAY_CLIENT_UUID__|${XRAY_CLIENT_UUID}|g" \
    "$src" > "$dst"
}

install -d -m 755 "$HY_DIR" "$HY_DIR/state" "$XRAY_ETC" "$TEMPLATE_DIR"

log "Rendering hysteria config and sources..."
render "$REPO_DIR/hysteria/config.yaml.tpl"          "$HY_DIR/config.yaml"
render "$REPO_DIR/hysteria/auth_backend.py"          "$HY_DIR/auth_backend.py"
render "$REPO_DIR/hysteria/subscription_service.py"  "$HY_DIR/subscription_service.py"
render "$REPO_DIR/hysteria/traffic_limiter.py"       "$HY_DIR/traffic_limiter.py"
chmod 700 "$HY_DIR"/*.py
chmod 600 "$HY_DIR/config.yaml"

log "Rendering clash subscription template → $TEMPLATE_DIR/default.yaml"
render "$REPO_DIR/hysteria/clash-default.yaml.tpl" "$TEMPLATE_DIR/default.yaml"

log "Rendering xray config.json..."
render "$REPO_DIR/xray/config.json.tpl" "$XRAY_ETC/config.json"
chmod 600 "$XRAY_ETC/config.json"

# ---------- 6. Initial users.json ----------
if [[ ! -f "$HY_DIR/users.json" ]]; then
  log "Creating empty users.json"
  echo '{}' > "$HY_DIR/users.json"
  chmod 600 "$HY_DIR/users.json"
fi

# ---------- 7. Self-signed TLS cert ----------
if [[ ! -f "$HY_DIR/server.crt" || ! -f "$HY_DIR/server.key" ]]; then
  log "Generating self-signed TLS certificate..."
  openssl req -x509 -nodes -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -keyout "$HY_DIR/server.key" -out "$HY_DIR/server.crt" \
    -subj "/CN=hysteria2" -days 3650 >/dev/null 2>&1
  chmod 600 "$HY_DIR/server.key"
fi

# ---------- 8. Port hopping script ----------
install -m 755 "$REPO_DIR/scripts/hysteria-porthop.sh" /usr/local/sbin/hysteria-porthop.sh

# ---------- 9. Systemd units ----------
log "Installing systemd units..."
install -m 644 "$REPO_DIR/systemd/hysteria-server.service"           "$SYSTEMD_DIR/"
install -m 644 "$REPO_DIR/systemd/hysteria-subscription.service"     "$SYSTEMD_DIR/"
install -m 644 "$REPO_DIR/systemd/hysteria-traffic-limiter.service"  "$SYSTEMD_DIR/"
install -m 644 "$REPO_DIR/systemd/hysteria-traffic-limiter.timer"    "$SYSTEMD_DIR/"
install -m 644 "$REPO_DIR/systemd/hysteria-porthop.service"          "$SYSTEMD_DIR/"

systemctl daemon-reload

# ---------- 10. Enable + start ----------
log "Enabling and starting services..."
systemctl enable --now hysteria-porthop.service
systemctl enable --now hysteria-server.service
systemctl enable --now hysteria-subscription.service
systemctl enable --now hysteria-traffic-limiter.timer
systemctl enable --now xray.service

sleep 1
log "Status:"
for u in hysteria-server hysteria-subscription hysteria-traffic-limiter.timer xray; do
  printf '  %-40s %s\n' "$u" "$(systemctl is-active "$u" || true)"
done

cat <<EOF

Done. Open the admin panel at:
  http://${HY_SERVER_HOST}:8080/admin

First-time setup:
  1. Log in (default admin credentials are generated into $HY_DIR/subscription_meta.json
     on first service start — cat that file to see the initial admin token).
  2. Create users. Each user gets a /sub/<name>?token=... URL to import into Clash.
  3. Hysteria auth flows through $HY_DIR/auth_backend.py which reads users.json.

Keep $HY_DIR/{users.json,subscription_meta.json,server.key} safe — they are NOT in git.
EOF
