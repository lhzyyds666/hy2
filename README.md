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
- ⏱️ **Codex quota dashboard** — reuses the server's existing Codex login, samples 5-hour/weekly limits every three minutes, and provides reset countdowns plus day/week/month/year hoverable trends without storing credentials or raw responses.
- 📊 **Per-user quota & device limit** — enforced by a 90-second job that pulls Hysteria + Xray stats, kicks over-quota users, and resets on a configurable billing cycle (default: day-12 anchor, 30-day cycle).
- 🔐 **Persistent HTTP auth** — Hysteria authenticates through a loopback-only, fixed-capacity service instead of starting Python for every connection; the emergency command CLI remains token-only compatible and never performs process-local PBKDF2 work.
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
                 │ auth POST (loopback only)
                 ▼
        ┌──────────────────────────────────────────────┐
        │ auth_service.py 127.0.0.1:8082 → users/state │
        └──────────────────────────────────────────────┘
```

## One-shot deploy

```bash
git clone https://github.com/lhzyyds666/hy2.git
cd hy2
cp .env.example .env
$EDITOR .env             # fill in every value (each line tells you how)
chmod 600 .env           # deploy rejects group/world-readable secrets
sudo ./deploy.sh
```

`deploy.sh` will:

1. Install checksum-pinned, architecture-matched Hysteria, Xray, and TUIC binaries.
2. Render every config template atomically with literal `.env` values (no shell/sed replacement semantics).
3. Drop files into `/root/hysteria/`, `/usr/local/etc/xray/`, `/etc/systemd/system/`.
4. Generate a self-signed TLS cert for Hysteria if missing.
5. `systemctl daemon-reload`, pass the auth service's shallow liveness check, then start Hysteria and the remaining units.
6. Install the nginx reverse proxy and require three consecutive deep full-stack readiness observations before committing the deployment transaction. Backup age is an operational health signal checked by the post-deploy timer, not a fresh-host deployment gate.
7. Keep a root-only write-ahead recovery journal for the complete static artifact set. Critical readers and writers must be authoritatively quiescent before the snapshot is frozen; a boot gate and same-boot watchdog recover an interrupted or `SIGKILL`ed deployment before consumers may start.

### Required `.env` keys

| Key | How to generate |
|---|---|
| `HY_SERVER_HOST` | your VPS public IP or domain |
| `HY_API_SECRET` | `openssl rand -hex 24` |
| `HY_OBFS_PASSWORD` | `openssl rand -base64 24 \| tr -d '/+='` |
| `XRAY_REALITY_PRIVATE_KEY` / `_PUBLIC_KEY` | `xray x25519` |
| `XRAY_REALITY_SHORT_ID` | `openssl rand -hex 8` |

The initial Xray configuration intentionally has no client UUID. Create every
client in the admin panel so Xray/TUIC authorization, quota enforcement, and
revocation all use the same canonical user record.

### Optional `.env` keys

| Key | Default | Notes |
|---|---:|---|
| `HY_DISPLAY_MULTIPLIER` | `2.28` | Display/billing multiplier applied to raw Hysteria/Xray/TUIC traffic counters. Keep it aligned with your provider accounting. `/admin/health` shows a calibration suggestion after enough traffic samples. Valid range: `0.1`-`20.0`. |
| `HY_HYSTERIA_VERSION` | `v2.9.3` | Exact checksum-verified Hysteria release installed by `deploy.sh`. |
| `HY_XRAY_VERSION` | `v26.6.27` | Exact Xray release installed from the repository-pinned archive. |
| `HY_ENABLE_HTTPS` | `1` | Set to `0` only for an intentionally HTTP-only private deployment. |
| `HY_CERTBOT_EMAIL` | empty | Optional Let's Encrypt account email. |
| `HY_HTTPS_PORT` | `9444` | nginx TLS port; must not conflict with Xray/TUIC. |

## Admin panel

After deploy:

- **Admin** — `https://<server>:9444/admin` — log in at `/login`. The admin password is **not** set via a first-visit form. On first deploy, write `admin_pass` (plaintext) into `subscription_meta.json`; on the next start it is migrated to a salted PBKDF2 `admin_pass_hash` and the plaintext is removed. If no password is configured, a random one is generated and written to a root-only file `admin_initial_password.txt` (next to `subscription_meta.json`, mode 0600) so you can read it, log in, and rotate it — then delete the file. Rotate the password any time from `/admin/settings` — that also signs out all other sessions while keeping you logged in on the current device.
- **User login** — `https://<server>:9444/user/login` — admins can set a separate temporary user-panel password when adding or editing a user. First login is forced through `/user/change-password`; users can change it again from the panel at any time, which signs out their other panel sessions. The credential is independent from both the direct proxy password and subscription token; existing users without one can keep opening token-authenticated panel links, which are immediately exchanged for a revocable cookie session at the clean `/user/panel` URL.
- **Add a user** from the panel → instant subscription URL `https://<host>:9444/sub/<name>?token=<token>`. A device limit of `0` means unlimited. The add flow rejects an existing username instead of overwriting it; use that user's **rotate subscription** action after a leak so revocation and audit guarantees remain intact.
- **Per-user actions** — each row can edit the plan, set an expiry date, add extra quota, keep an operator note, reset/refresh usage, **rotate the subscription token** (instantly invalidate a leaked link), **suspend/resume** (disable without deleting: reject new connections, pull the xray inbound, and drop live sessions), and delete. Every mutation carries the user revision seen when the page was opened: if another operator wins the race, the stale page receives HTTP 409 rather than overwriting newer state. Edit-conflict pages preserve non-sensitive draft fields but never echo passwords. Expired users are rejected by auth and removed from static Xray/TUIC plans until renewed. If token rotation commits but Xray/TUIC reconciliation fails, those static-auth services stop fail-closed and the admin receives a recovery warning instead of a misleading generic failure.
- **User panel** — `https://<server>:9444/panel/<user>?token=<token>` — validates the token once, redirects to a clean token-free session URL, and shows per-user usage + device stats, a quota-reset countdown, a 30-day usage trend, one-click copy, guided multi-profile import, on-demand QR codes, and 30-second usage refresh (paused while hidden). Signed-in users can automatically follow the common Clash template or pin its current revision, apply personal rule packs, and add or delete validated domain, IP/CIDR, and process-name rules with direct/proxy/reject actions. Personal mutations are session-scoped and use account revisions to avoid overwriting concurrent admin changes. A pinned user sees later common-template updates as opt-in merges; merging replaces only the common base and preserves the personal overlay. Self-service rotation requires that clean panel's valid `usid` plus a hidden idempotency key. Before changing `users.json`, it writes a mode-0600, session-bound five-minute recovery receipt, so a crash or lost response can replay the same request and recover the same new token without putting it in a URL, log, or exception. Receipts are capped at 256 entries, actively erased by the background worker after expiry, and excluded from backups. Revocation side effects use a separate durable queue capped at 512 unfinished tasks: committed rotations and account deletions are never silently discarded by age, while an expired pre-commit rotation intent is retired only when the old generation is still canonical. Hysteria receives an immediate kick and a delayed second kick over a direct loopback HTTP connection that ignores proxy environment variables; failed static stops/reload scheduling remain durable, and the UI distinguishes confirmed pause from unconfirmed retry. If a new session cannot be persisted, the final no-store recovery page returns HTTP 200 and exposes the current new links only to that recovery flow.
- **Subscription profiles** — `profile=game|work|lowdata|safe` can be appended to `/sub/<user>?token=...`. `game` favors UDP/low latency, `work` favors TCP fallback stability, `lowdata` routes unknown traffic direct, and `safe` proxies everything except LAN/private traffic. Omitting `profile` keeps the shared template unchanged.
- **Template config** — edit the common Clash YAML template inline (JSON view, structural and syntax validation, format/collapse). Saves use file revisions; a stale draft receives HTTP 409 and retains its input. Existing users default to automatic following. Pinned revisions are content-addressed and deduplicated in `state/template_versions.json`, which is covered by the normal runtime-state backup.
- **Route rules** — add / remove / re-order proxy/direct/reject rules; live diff against the template. Adds, deletes, and raw saves use the same revision check, so a stale row index cannot delete a rule that moved.
- **Reset log** — full audit trail of every traffic-reset action.
- **Settings** — `https://<server>:9444/admin/settings` — change the admin password in-browser (verifies the current password, then stores a fresh PBKDF2 hash). Changing it signs out every existing session and re-issues a session cookie for the current device.
- **Health** — alongside the 6 status cards, a "send test alert" button verifies the Telegram / webhook channels in `alerts.json`. The page also includes a line radar that compares recent Hysteria/Xray/TUIC protocol traffic and recommends a subscription profile, plus a cost calibrator that compares public NIC counters with app-level raw traffic and suggests a `HY_DISPLAY_MULTIPLIER`. TUIC traffic is port-level aggregate metering, not per-user quota metering. Alert tests are dispatched on a background thread (non-blocking); the webhook URL is operator-supplied (admin-equivalent trust) with no URL allowlisting, so confirm delivery at the receiver.
- **Codex quota** — `https://<server>:9444/admin/codex` — reads account limits through the local Codex app-server and shows remaining capacity, reset countdowns, and day/week/month/year trends. The collector is a three-minute one-shot process and compacts history at 3-minute, 15-minute, and 2-hour tiers. Missing upstream windows are shown as unavailable rather than inferred from stale values.

The admin overview and analytics summaries refresh every 30s; chart series refresh every 90s to match the source collector cadence and only rebuild when changed. Polling pauses while the tab is hidden.

## Configuration

### Port layout on the server

| Port | Service |
|---|---|
| `80/tcp` | nginx → reverse-proxies `127.0.0.1:8081` (panel & subscriptions) |
| `127.0.0.1:8082/tcp` | Persistent Hysteria HTTP authentication (never exposed publicly) |
| `443/tcp` | Xray — VLESS + Reality |
| `443/udp` | Hysteria2 |
| `8443/tcp` | Xray — VLESS + Reality (backup) |
| `9443/udp` | TUIC v5 |
| `9444/tcp` | nginx — HTTPS admin/subscription panel |
| `20000-40000/udp` | iptables REDIRECT → `443/udp` (port-hopping) |

### Backup

After deploy, run:

```bash
sudo /usr/local/sbin/hy2-backup.sh
```

Backups are written to `/root/hysteria/backups/` by default, mode 0600, with a `.sha256` checksum file. The archive includes users, admin metadata, subscription template, alert config, runtime state (excluding live admin and user-panel sessions), TLS/API secrets, TUIC config, and Xray config.

Optional encryption:

```bash
sudo install -m 600 /dev/null /root/hysteria/backup.pass
sudo sh -c 'openssl rand -base64 32 > /root/hysteria/backup.pass'
sudo HY2_BACKUP_PASSPHRASE_FILE=/root/hysteria/backup.pass /usr/local/sbin/hy2-backup.sh
```

Optional off-host upload uses an rclone destination and refuses plaintext
archives. Put `HY2_BACKUP_PASSPHRASE_FILE` and `HY2_BACKUP_REMOTE` in the
root-only `/root/hysteria/backup.env`; configure rclone separately. Without a
remote, daily local backups continue normally.

A dedicated private Git repository is also supported. The uploader verifies
every checksum, includes only `*.tar.gz.enc` plus portable checksum files, keeps
the latest 14 archives, and force-pushes a single rolling snapshot so encrypted
binary history cannot grow indefinitely:

```bash
HY2_BACKUP_PASSPHRASE_FILE=/root/hysteria/backup.pass
HY2_BACKUP_GIT_REPO=https://github.com/OWNER/hy2-encrypted-backups.git
HY2_BACKUP_GIT_KEEP=14
```

Keep the passphrase outside GitHub. The Git credential used by the timer should
have access only to the private backup repository.

Before restoring anything, dry-run the archive:

```bash
sudo /usr/local/sbin/hy2-restore-check.sh /root/hysteria/backups/hy2-backup-YYYYMMDDTHHMMSSZ.tar.gz
sudo HY2_RESTORE_PASSPHRASE_FILE=/root/hysteria/backup.pass /usr/local/sbin/hy2-restore-check.sh /root/hysteria/backups/hy2-backup-YYYYMMDDTHHMMSSZ.tar.gz.enc
```

The dry-run decrypts if needed, validates archive paths, checks JSON/YAML parseability, and reports how many live runtime files would be overwritten. It never writes back into `/root/hysteria`.

### HTTPS for the admin panel

The helper accepts either a DNS name or the server's public IPv4 address. DNS
names receive a normal Let's Encrypt certificate. IP addresses receive a
publicly trusted six-day certificate, so automated renewal must stay healthy.
TCP/9444 is used because Xray owns TCP/443 and TCP/8443.

```bash
sudo /usr/local/sbin/hy2-enable-https.sh panel.example.com you@example.com
sudo /usr/local/sbin/hy2-enable-https.sh 203.0.113.10 '' 9444
```

Or set `HY_ENABLE_HTTPS=1` in `.env` before running `deploy.sh`. The helper
installs a current Certbot, preserves the HTTP ACME challenge path, redirects
other HTTP traffic to HTTPS, installs the renewal reload hook, and enables the
snap renewal timer. `HY_CERTBOT_EMAIL` is recommended but optional.

### Files NOT in git (by design)

These are per-server secrets or runtime state — never commit them. They are already in `.gitignore`:

- `.env` — real secret values
- `server.crt`, `server.key` — TLS cert (auto-generated by `deploy.sh`)
- `users.json` — user roster with password hashes & `sub_token`s
- `subscription_meta.json` — admin password hash
- `state/codex_quota.json` — credential-free Codex quota history (tiered retention up to 400 days)
- `state/` — usage counters, online snapshot, reset log

## Security notes

- The subscription service binds **only** to `127.0.0.1:8081`. nginx exposes the ACME/redirect listener on `:80` and the encrypted panel on `:9444`.
- `hysteria-auth.service` binds **only** to `127.0.0.1:8082`, validates and canonicalizes the exact Hysteria HTTP-auth schema, and uses fixed worker/pending limits plus a dedicated bounded overload responder. One absolute connection deadline covers slow headers, bodies, policy work, and every loopback online-API I/O. Token authentication stays on a constant-time fast path; PBKDF2 fallback work exists only in this persistent service and has bounded per-source/global rates plus a separate non-queuing CPU slot limit. An accepted request re-reads the user's authorization generation before returning, so a concurrent token/password rotation, suspension, expiry, or policy edit fails closed. `/livez` is process-only startup liveness, while `/readyz` requires the live online API and the admission ledger without consuming a device slot; cached online snapshots may help an individual capped-user login for at most 20 seconds but can never make readiness green. Hysteria remains lifecycle-bound to auth: a root-only runtime intent marker is written only after deep startup succeeds, preserved across an auth-caused stop, and cleared by a deliberate server stop while auth is healthy. Auth recovery therefore queues one non-blocking start only for an enabled server that was actually running, without undoing an operator stop. Invalid credentials and throttled password attempts both receive the protocol-required generic HTTP 200 denial; secrets and request bodies are never journaled. `auth_backend.py` retains an emergency command CLI for `sub_token` credentials only; legacy PBKDF2 passwords are intentionally rejected there.
- All template files use `__PLACEHOLDER__` markers; the **real secrets only ever live in `.env` and the rendered files under `/root/hysteria/`**, both of which are gitignored. The renderer reads values from the environment rather than argv, preserves literal `|`, `&`, and backslashes, rejects NUL/multiline values plus unknown or residual placeholders, fsyncs, and atomically replaces the destination.
- Hysteria 2.9.3, Xray 26.6.27, and TUIC 1.0.0 use explicit `amd64`/`arm64` mappings and repository-pinned SHA-256 values. Deployment verifies owner, mode, link count, and digest before trusting an installed binary, and never executes an unverified old binary as root.
- Hysteria management API is localhost-only and gated by `HY_API_SECRET`. Treat that secret like an SSH key.
- Admin auth uses PBKDF2-SHA256 with 200k rounds + per-secret salt; sessions use HTTP-only `SameSite=Lax` cookies.
- Per-user `sub_token` is a 24-byte URL-safe random; rotating it instantly invalidates a leaked subscription URL without affecting the user record.
- Set up a trusted TLS cert for the admin/subscription panel before exposing it on the public internet. Use `/usr/local/sbin/hy2-enable-https.sh <domain-or-ip> [email] [port]`; the bundled self-signed cert remains limited to the Hysteria/TUIC endpoints.

> **Rotation log** — an early commit (pre-`e7d9d3a`) accidentally embedded a real `HY_API_SECRET` in source. It was rotated and verified invalid on 2026-04-30; the value present in pre-`e7d9d3a` git history no longer authenticates against any live endpoint.

## Project layout

```
.
├── deploy.sh                       # one-shot installer
├── .env.example                    # secrets template (copy → .env)
├── hysteria/
│   ├── config.yaml.tpl             # hysteria2 server config
│   ├── auth_service.py             # bounded loopback HTTP auth service
│   ├── auth_backend.py             # shared policy + token-only command CLI
│   ├── subscription_service.py     # admin panel + /sub renderer
│   ├── traffic_limiter.py          # 5-sec job: stats + auto-kick
│   └── clash-default.yaml.tpl      # subscription template
├── xray/config.json.tpl            # vless+reality config
├── nginx/hysteria-panel.conf       # :80 reverse proxy
├── scripts/hysteria-porthop.sh     # iptables port-hop script
└── systemd/                        # unit files for every service
```

## Alerts (optional)

Drop a `/root/hysteria/alerts.json` (chmod 600) to enable Telegram / webhook alerts:

```json
{
  "telegram": {"bot_token": "...", "chat_id": "..."},
  "webhook":  {"url": "https://example.com/hook", "secret": "optional-hmac-key"},
  "anomaly_z_threshold": 3.0,
  "anomaly_min_bytes": 1073741824
}
```

- 80% / 100% quota crossings → one push per user per billing month
- Daily total exceeding `z_threshold` σ above the trailing 7-day mean → one push per user per day
- Expiry reminders → one push when a user is within `expiry_warn_days` (default 3) of `expires_at`, plus one push after expiry
- Webhook payloads are HMAC-SHA256 signed via `X-Hy2-Signature: sha256=<hex>` when `secret` is set
- Dedup state uses a cross-process claim → unlocked delivery → compare-and-swap completion flow. Concurrent ticks send an event once; every configured transport must succeed before the dedup key commits; failures release immediately for retry, and abandoned claims expire after 60 seconds. Credential-bearing destination URLs are never written to failure logs.

If the file is absent, the dispatcher is a no-op. Live infra heartbeat at `/admin/health` (6 cards: cron pulse / hysteria / xray / disk / TLS cert / online users, auto-refreshes every 30s).

## Development

For local test runs:

```bash
python3 -m pip install -r requirements-dev.txt
python3 -m pytest -q
```

## License

MIT — see `LICENSE` if present, otherwise treat as MIT.

---

<p align="center"><sub>中文文档 → <a href="README.zh-CN.md">README.zh-CN.md</a></sub></p>
