# Observability & Alerting — Design Spec

**Date:** 2026-05-05
**Bundle:** A (Observability + Alerting)
**Status:** Approved by operator, ready for implementation plan

## 1. Motivation

The recently shipped daily-traffic collection (`usage_daily.json`, 30-day rolling) wires up a data source nobody is reading yet. Today the only way to know "did anything weird happen" is to open `/admin/daily` and eyeball a 14×N table. The single-server self-hosted operator wants:

- **At-a-glance trend** on the main dashboard, not in a separate page
- **Push-style notification** when a user crosses quota or spikes anomalously
- **Infra heartbeat** without SSH-ing the box
- **Statistical** anomaly detection so alerts mean something

This bundle closes those four loops and turns the existing daily series into actual signal.

## 2. Scope

### In scope (4 features, all interlocked)

1. **Sparkline column** in `/admin` dashboard (per-user 30-day mini bar chart)
2. **Alert dispatcher** with Telegram + generic webhook channels
3. **Health page** at `/admin/health` (6 read-only status cards)
4. **Anomaly detection** running inside `traffic_limiter.main()` (z-score against trailing 7 days)

### Explicitly out of scope

- Email alerting (deferred — needs SMTP config burden)
- Multi-server / federation (single-server design holds)
- Time-series databases (the JSON file is fine for 30 days × ~50 users)
- User-facing alerting on `/panel/<user>` (admin-only this round)
- Replacing JSON storage with sqlite/redis
- Writes from the health page (read-only by design)
- Alert delivery retries / dead-letter queues (best-effort, log on fail)

## 3. Components

### 3.1 Sparkline (`subscription_service.py`)

**Where:** new column in the table inside `render_admin()`, between "用户" and "本月用量".

**Render:** server-side SVG, 30 bars at 3px width × 24px height max, 1px gap, total ~120px wide. Each bar height = `int(24 * day_total / window_max)`, `min(1)` if non-zero. Today's bar uses `--accent`, others `--text-muted`. Empty days render no bar (gap stays).

**Hover:** native `<title>` element per bar showing `YYYY-MM-DD: 1.23 GB`. No JS.

**Data source:** load `USAGE_DAILY_FILE` once per page render, scale by `DISPLAY_MULTIPLIER`. Add helper `daily_window_for_user(uid, daily, days=30) -> list[(date_str, total_bytes)]` so logic is shared with anomaly detection.

**Performance:** O(users × days), pure Python loop, file is small (a few KB). Fine for the 5s refresh polling — the JSON endpoint `/admin/usage.json` ALSO returns the sparkline values so the column updates without page reload.

### 3.2 Alert dispatcher (`hysteria/alerts.py`, new module)

**Config file:** `/root/hysteria/alerts.json` (chmod 600). Schema:
```json
{
  "telegram": {"bot_token": "...", "chat_id": "..."},
  "webhook":  {"url": "https://...", "secret": "optional-hmac-key"},
  "anomaly_z_threshold": 3.0,
  "anomaly_min_bytes": 1073741824
}
```
- Both channel keys (`telegram`, `webhook`) optional; if both absent, dispatcher logs once and treats every event as a no-op.
- `anomaly_z_threshold` defaults to **3.0** if missing; `anomaly_min_bytes` defaults to **1073741824** (1 GiB).
- Missing/unreadable file = dispatcher silently disabled (logged once at module load).

**State file:** `/root/hysteria/state/alert_state.json`. Schema:
```json
{
  "quota_80":   {"alice": "2026-05",  ...},
  "quota_100":  {"alice": "2026-05",  ...},
  "anomaly":    {"alice": "2026-05-05", ...}
}
```
- `quota_80` / `quota_100` keyed on billing-month-key — one alert per user per month per threshold
- `anomaly` keyed on date — one alert per user per day max

**API:**
```python
def dispatch(event: dict) -> None: ...
```
where `event` is `{"kind": "quota_80"|"quota_100"|"anomaly", "user": str, "details": dict}`.
Internally: format human-readable message → POST to telegram + webhook (in parallel, but sequential is fine — they're rare). Each transport wrapped in try/except, logs to stderr, never raises.

**Webhook payload:** the `event` dict as JSON. If `secret` set, add `X-Hy2-Signature: sha256=<hmac>` header.

**Telegram message format:**
```
🟡 alice 已用 80% (12.3 / 15.0 GB) · 周期 2026-05
```

### 3.3 Health page (`subscription_service.py`)

**Route:** `GET /admin/health`. Auth: `is_logged_in`. Sidebar: new entry `('health', '/admin/health', '健康状态', 'pulse')`.

**Cards (6, in a `grid-3` layout):**

| Card | Source | Green / Red |
|---|---|---|
| cron 心跳 | `os.path.getmtime(USAGE_FILE)` | <120s / ≥120s |
| hysteria | `subprocess.run(['systemctl','is-active','hysteria-server'])` | `active` / else |
| xray | same, `xray.service` | `active` / else |
| 磁盘 `/` | `shutil.disk_usage('/')` | `free% > 15` / else |
| TLS 证书 | parse `/root/hysteria/server.crt` `notAfter` | days >14 / else |
| 在线用户 | `sum(load_json(ONLINE_FILE,{}).values())` | always green, just info |

**Refresh:** `<meta http-equiv="refresh" content="30">` on the page itself. No JS, no JSON endpoint.

**Failure mode:** any single probe that throws → that card shows "未知" with grey styling. Other cards unaffected.

**No writes:** the route accepts only GET; everything is read-only system inspection.

### 3.4 Anomaly detection (`hysteria/traffic_limiter.py`)

**When:** end of `main()`, after `accumulate_daily(...)`, before `kick` decision. Independent code path; if it raises, log and continue (don't break kick logic).

**Numerics convention:** the z-score math runs on **raw bytes** (pre-`DISPLAY_MULTIPLIER`). Scaling is purely a display concern and only happens when formatting the alert message body. The `anomaly_min_bytes` threshold is also in **raw bytes**.

**Algorithm per user:**
1. Take the user's last 7 *complete* days from `usage_daily.json` (i.e. `today - 1` back to `today - 7`). Use the `total` field from each day's entry, raw.
2. Need at least 3 non-zero days; otherwise skip (insufficient baseline).
3. Compute `mean`, `stdev` of those days' raw totals.
4. Read today's raw running total from `usage_daily.json` (the file `traffic_limiter` just wrote in this same tick).
5. If `today_raw < anomaly_min_bytes` → skip (noise floor).
6. If `stdev == 0` → require `today_raw > 2 * mean` instead of z-score.
7. Else compute `z = (today_raw - mean) / stdev`. If `z > anomaly_z_threshold`, candidate.

**Dispatch:** for each candidate, check `alert_state.json` — if today already alerted for this user, skip; else write state + call `dispatch({"kind":"anomaly", ...})`.

**Quota threshold check** (same module, runs alongside anomaly):
- Compute `pct = scaled_used / quota` for each guest user with quota > 0
- If pct ≥ 0.80 and not yet alerted this billing-month → dispatch `quota_80`
- If pct ≥ 1.00 and not yet alerted this billing-month → dispatch `quota_100`
- Both keyed off `billing_month_key(now)` so resetting next cycle re-arms them

## 4. Data flow

```
cron tick (60s)
  └─ traffic_limiter.main()
       ├─ pull /traffic?clear=1 + xray statsquery
       ├─ accumulate_month   (existing)
       ├─ accumulate_daily   (existing)
       ├─ check_quota_alerts (NEW)  ──┐
       ├─ check_anomaly      (NEW)  ──┴─→ alerts.dispatch ──→ Telegram + webhook
       └─ kick_overusage     (existing)

HTTP layer
  GET /admin              renders sparkline_svg(uid) per row
  GET /admin/usage.json   payload now includes per-user "spark": [int, int, ...]
  GET /admin/health       renders 6 read-only probe cards (NEW)
  GET /admin/daily        unchanged from prior commit
```

## 5. Files touched / created

**New:**
- `hysteria/alerts.py` — dispatcher module
- `hysteria/anomaly.py` — z-score helper (kept separate from traffic_limiter to enable unit tests without fcntl/systemd noise)
- `docs/superpowers/specs/2026-05-05-observability-and-alerting-design.md` — this file
- `docs/superpowers/plans/2026-05-05-observability-and-alerting-plan.md` — produced by `writing-plans` in the next step

**Modified:**
- `hysteria/traffic_limiter.py` — wire in `check_quota_alerts` and `check_anomaly` calls
- `hysteria/subscription_service.py` — sparkline column + `/admin/health` route + sidebar entry + `/admin/usage.json` payload extension
- `deploy.sh` — copy `alerts.py` and `anomaly.py` to `$HY_DIR` verbatim (no template vars to render). Do **not** create `alerts.json` automatically — the operator writes it post-install when they want alerts on.
- `README.md` — add a short "告警" section pointing at `alerts.json` schema (no `.env.example` change; alerts are not part of the bootstrap requirements)

## 6. Error handling / degradation

| Failure | Behavior |
|---|---|
| `alerts.json` missing or unreadable | dispatcher disabled, no error logged on each tick (logged once at module load) |
| Telegram API 4xx/5xx / timeout | stderr log, no retry, no exception bubbles |
| Webhook 4xx/5xx / timeout | stderr log, no retry |
| `alert_state.json` corrupt | reset to `{}`, log warning, continue |
| Anomaly module raises | caught at `traffic_limiter.main()` boundary, logged, kick logic still runs |
| Health probe raises (e.g. systemctl missing) | per-card "未知" rendering, page still loads |
| Sparkline data missing for user | empty SVG (just bounding box) |
| `usage_daily.json` missing | sparklines all empty, no crash |

## 7. Security

- `alerts.json` chmod 600, owned root, never served by the HTTP handler (path is outside the routes)
- Webhook payload signed with HMAC-SHA256 if `secret` configured
- Health page does NOT expose internal paths, env vars, or secrets — only booleans / counts / dates
- Health page reuses existing `is_logged_in` auth; no new attack surface
- `subprocess.run(['systemctl', ...])` uses fixed argv, not shell — no injection risk

## 8. Testing strategy

**Unit (offline, no real network/systemd):**
- `anomaly.py::detect_user`: feed synthetic histories, assert candidate / skip
- `alerts.py::dispatch`: inject fake transport, assert payload shape and dedup state writes
- `subscription_service.sparkline_svg`: feed 30 known values, assert SVG has correct number of `<rect>`s and the today bar carries the accent class
- `subscription_service.health_card_*`: each probe function with mocked `os.path`, `shutil`, `subprocess`, `ssl.PEM`

**Integration smoke (Windows-friendly, fcntl stub like before):**
- Run `traffic_limiter.main()` against a temp directory with seeded `users.json` / `usage_daily.json` / mocked `urllib`. Assert alert state file is updated as expected.

**Manual verification on first deploy:**
1. Create `alerts.json` with a real Telegram bot + a `requestbin.com` webhook
2. Manually edit a user's quota down so they cross 80%, wait one cron tick, confirm Telegram message arrives
3. Visit `/admin/health` and stop xray (`systemctl stop xray`); confirm card flips red within 30s

## 9. Open design questions

None at spec time — all defaults are pinned in §3 (z=3.0, min_bytes=1 GiB, retention 30d, refresh 30s, deduping per billing month / per day).

## 10. Out of scope, explicitly deferred

- Multi-channel alert routing rules ("dev → telegram, finance → email")
- Per-user alert opt-out
- Alert history page / replay
- Sparkline on the per-user `/panel/<user>` page (Bundle B candidate)
- Configurable health-card thresholds (cron-stale 120s, disk 15%, cert 14d are hardcoded)
- Storing health snapshots over time
