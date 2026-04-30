<h1 align="center">hy2</h1>

<p align="center">
  <b>One-shot Hysteria2 + Xray (VLESS&nbsp;Reality) deploy with a built-in subscription &amp; admin panel.</b>
</p>

<p align="center">
  <a href="#features"><img alt="status" src="https://img.shields.io/badge/status-ready-4ade80?style=flat-square"></a>
  <a href="#one-shot-deploy"><img alt="platform" src="https://img.shields.io/badge/platform-Debian%20%7C%20Ubuntu-60a5fa?style=flat-square"></a>
  <img alt="license" src="https://img.shields.io/badge/license-MIT-d1d5db?style=flat-square">
  <a href="README.zh-CN.md"><img alt="lang" src="https://img.shields.io/badge/lang-中文-f87171?style=flat-square"></a>
</p>

<p align="center">
  <a href="#features">Features</a> ·
  <a href="#architecture">Architecture</a> ·
  <a href="#one-shot-deploy">Deploy</a> ·
  <a href="#admin-panel">Panel</a> ·
  <a href="#configuration">Config</a> ·
  <a href="#security-notes">Security</a>
</p>

---

## Features

- ⚡  **Hysteria2** on `:443/udp` with Salamander obfs + UDP port-hopping over `20000-40000/udp`.
- 🛡️ **Xray VLESS&nbsp;+&nbsp;Reality** on `:443/tcp` (primary) and `:8443/tcp` (backup), masquerading as `www.bing.com`.
- 🎛️ **Built-in admin panel** — create users, see live traffic, manage subscription template & route rules from a browser. Sidebar layout, dark theme, fully responsive.
- 📊 **Per-user quota & device limit** — enforced by a 1-minute job that pulls hysteria + xray stats, kicks over-quota users, resets on the 21st of each month.
- 🔗 **Per-user subscription URL** that emits Clash YAML on the fly with the right password & UUID injected.
- 🚀 **One-shot deploy** — fill in `.env`, run `./deploy.sh`, get a working stack in under a minute.

## Architecture

```
        ┌──────────────────────────────────────────────┐
        │  Client (Clash / sing-box / mihomo)          │
        └───────────────────┬──────────────────────────┘
                            │ subscribe → http://host/sub/<user>?token=…
                            ▼
        ┌──────────────────────────────────────────────┐
        │  nginx :80   →   subscription_service.py     │
        │                  127.0.0.1:8081              │
        └───────┬────────────────┬─────────────────────┘
                │ /admin         │ /sub/<user>
                ▼                ▼ (renders template.yaml)
        ┌──────────────┐    ┌──────────────────────────┐
        │   panel UI   │    │  users.json + usage.json │
        └──────────────┘    └──────────────────────────┘

                  data plane
        ┌──────────────────────────────────────────────┐
        │  hysteria2 :443/udp  +  port-hop 20000-40000 │
        │  xray vless+reality  :443/tcp & :8443/tcp    │
        └──────────────────────────────────────────────┘
```

## One-shot deploy

```bash
git clone https://github.com/lhzyyds666/hy2.git
cd hy2
cp .env.example .env
$EDITOR .env             # fill in every value (each line tells you how)
sudo ./deploy.sh
```

`deploy.sh` will:

1. Install the official `hysteria` and `xray` binaries.
2. Render every config template with your `.env` values.
3. Drop files into `/root/hysteria/`, `/usr/local/etc/xray/`, `/etc/systemd/system/`.
4. Generate a self-signed TLS cert for Hysteria if missing.
5. `systemctl daemon-reload`, enable & start every unit, and install the nginx reverse proxy.

### Required `.env` keys

| Key | How to generate |
|---|---|
| `HY_SERVER_HOST` | your VPS public IP or domain |
| `HY_API_SECRET` | `openssl rand -hex 24` |
| `HY_OBFS_PASSWORD` | `openssl rand -base64 24 \| tr -d '/+='` |
| `XRAY_REALITY_PRIVATE_KEY` / `_PUBLIC_KEY` | `xray x25519` |
| `XRAY_REALITY_SHORT_ID` | `openssl rand -hex 8` |
| `XRAY_CLIENT_UUID` | `xray uuid` (or `uuidgen`) |

## Admin panel

After deploy:

- **Admin** — `http://<server>/admin` — set the admin password on first visit (stored hashed in `subscription_meta.json`).
- **Add a user** from the panel → instant subscription URL `http://<host>/sub/<name>?token=<token>`.
- **User panel** — `http://<server>/panel/<user>?token=<token>` — usage + device stats per user.
- **Template config** — edit the shared Clash YAML template inline (JSON view, validation, format/collapse).
- **Route rules** — add / remove / re-order proxy/direct/reject rules; live diff against the template.
- **Reset log** — full audit trail of every traffic-reset action.

The panel polls `/admin/usage.json` every 5s, automatically pauses when the tab is hidden, and uses an in-memory row index so it doesn't re-query the DOM on each tick.

## Configuration

### Port layout on the server

| Port | Service |
|---|---|
| `80/tcp` | nginx → reverse-proxies `127.0.0.1:8081` (panel & subscriptions) |
| `443/tcp` | Xray — VLESS + Reality |
| `443/udp` | Hysteria2 |
| `8443/tcp` | Xray — VLESS + Reality (backup) |
| `20000-40000/udp` | iptables REDIRECT → `443/udp` (port-hopping) |

### Files NOT in git (by design)

These are per-server secrets or runtime state — never commit them. They are already in `.gitignore`:

- `.env` — real secret values
- `server.crt`, `server.key` — TLS cert (auto-generated by `deploy.sh`)
- `users.json` — user roster with password hashes & `sub_token`s
- `subscription_meta.json` — admin password hash
- `state/` — usage counters, online snapshot, reset log

## Security notes

- The subscription service binds **only** to `127.0.0.1:8081`. The public surface is nginx on `:80`.
- All template files use `__PLACEHOLDER__` markers; the **real secrets only ever live in `.env` and the rendered files under `/root/hysteria/`**, both of which are gitignored.
- Hysteria management API is localhost-only and gated by `HY_API_SECRET`. Treat that secret like an SSH key.
- Admin auth uses PBKDF2-SHA256 with 200k rounds + per-secret salt; sessions use HTTP-only `SameSite=Lax` cookies.
- Per-user `sub_token` is a 24-byte URL-safe random; rotating it instantly invalidates a leaked subscription URL without affecting the user record.
- Set up a real TLS cert (e.g. `certbot --nginx`) before exposing this on the public internet — the bundled cert is self-signed for the Hysteria endpoint only.

> **Rotation log** — an early commit (pre-`e7d9d3a`) accidentally embedded a real `HY_API_SECRET` in source. It was rotated and verified invalid on 2026-04-30; the value present in pre-`e7d9d3a` git history no longer authenticates against any live endpoint.

## Project layout

```
.
├── deploy.sh                       # one-shot installer
├── .env.example                    # secrets template (copy → .env)
├── hysteria/
│   ├── config.yaml.tpl             # hysteria2 server config
│   ├── auth_backend.py             # auth-by-command bridge
│   ├── subscription_service.py     # admin panel + /sub renderer
│   ├── traffic_limiter.py          # 1-min job: stats + auto-kick
│   └── clash-default.yaml.tpl      # subscription template
├── xray/config.json.tpl            # vless+reality config
├── nginx/hysteria-panel.conf       # :80 reverse proxy
├── scripts/hysteria-porthop.sh     # iptables port-hop script
└── systemd/                        # unit files for every service
```

## License

MIT — see `LICENSE` if present, otherwise treat as MIT.

---

<p align="center"><sub>中文文档 → <a href="README.zh-CN.md">README.zh-CN.md</a></sub></p>
