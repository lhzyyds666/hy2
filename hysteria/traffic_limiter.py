#!/usr/bin/env python3
import json
import os
import fcntl
import subprocess
import urllib.request
from contextlib import contextmanager
from datetime import datetime, timedelta
from display import DISPLAY_MULTIPLIER

XRAY_BIN = "/usr/local/bin/xray"
XRAY_API = "127.0.0.1:10085"
XRAY_EMAIL_BACKUP_SUFFIX = "-backup"

USERS_FILE = "/root/hysteria/users.json"
USAGE_FILE = "/root/hysteria/state/usage.json"
USAGE_DAILY_FILE = "/root/hysteria/state/usage_daily.json"
ONLINE_SNAPSHOT_FILE = "/root/hysteria/state/online.json"
RESET_STATE_FILE = "/root/hysteria/state/auto_reset_state.json"
RESET_LOG_FILE = "/root/hysteria/state/usage_reset.log"
USAGE_LOCK_FILE = "/root/hysteria/state/usage.lock"
DAILY_RETENTION_DAYS = 30
API_BASE = "http://127.0.0.1:25413"
API_SECRET = "__HY_API_SECRET__"


def load_json(path, default):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default


def save_json(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=True, indent=2)


@contextmanager
def usage_lock():
    os.makedirs(os.path.dirname(USAGE_LOCK_FILE), exist_ok=True)
    with open(USAGE_LOCK_FILE, "a+", encoding="utf-8") as f:
        fcntl.flock(f.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(f.fileno(), fcntl.LOCK_UN)


def append_reset_log(actor, action, target, before, after, mk):
    line = {
        "time": datetime.utcnow().isoformat(timespec="seconds") + "Z",
        "actor": actor,
        "ip": "",
        "action": action,
        "target": target,
        "month": mk,
        "before": before,
        "after": after,
    }
    os.makedirs(os.path.dirname(RESET_LOG_FILE), exist_ok=True)
    with open(RESET_LOG_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(line, ensure_ascii=True) + "\n")


def get(path):
    req = urllib.request.Request(
        f"{API_BASE}{path}",
        headers={"Authorization": API_SECRET},
        method="GET",
    )
    with urllib.request.urlopen(req, timeout=3) as resp:
        return json.loads(resp.read().decode("utf-8"))


def post(path, obj):
    body = json.dumps(obj).encode("utf-8")
    req = urllib.request.Request(
        f"{API_BASE}{path}",
        data=body,
        headers={"Authorization": API_SECRET, "Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=3):
        return


def billing_month_key(now):
    """Billing cycle resets on the 21st. Before the 21st belongs to the previous cycle.
    Must match subscription_service.month_key() / auth_backend month logic."""
    if now.day >= 21:
        return now.strftime("%Y-%m")
    prev = now.replace(day=1) - timedelta(days=1)
    return prev.strftime("%Y-%m")


def normalize_usage_entry(entry):
    if isinstance(entry, dict):
        tx = int(entry.get("tx", 0))
        rx = int(entry.get("rx", 0))
        total = int(entry.get("total", tx + rx))
        return {"tx": tx, "rx": rx, "total": total}
    total = int(entry or 0)
    return {"tx": 0, "rx": total, "total": total}


def maybe_reset_all_usage_on_day_21(now, users, usage, month):
    if now.day != 21:
        return
    state = load_json(RESET_STATE_FILE, {})
    if state.get("last_reset_month") == month:
        return

    usage.setdefault(month, {})
    before_all = {}
    for uid in users.keys():
        before_all[uid] = normalize_usage_entry(usage[month].get(uid, 0))
        usage[month][uid] = {"tx": 0, "rx": 0, "total": 0}

    save_json(USAGE_FILE, usage)
    append_reset_log(
        actor="system",
        action="reset_usage_all_auto_day21",
        target="all_users",
        before=before_all,
        after={u: {"tx": 0, "rx": 0, "total": 0} for u in users.keys()},
        mk=month,
    )
    save_json(
        RESET_STATE_FILE,
        {
            "last_reset_month": month,
            "last_reset_time": now.isoformat(timespec="seconds"),
        },
    )


def get_xray_traffic():
    try:
        out = subprocess.check_output(
            [XRAY_BIN, "api", "statsquery", f"--server={XRAY_API}",
             "-pattern", "user>>>", "-reset"],
            timeout=3,
            stderr=subprocess.DEVNULL,
        )
        data = json.loads(out.decode("utf-8"))
    except Exception:
        return {}
    result = {}
    for stat in data.get("stat") or []:
        name = stat.get("name", "")
        parts = name.split(">>>")
        if len(parts) != 4 or parts[0] != "user" or parts[2] != "traffic":
            continue
        email = parts[1]
        direction = parts[3]
        uid = email[: -len(XRAY_EMAIL_BACKUP_SUFFIX)] if email.endswith(XRAY_EMAIL_BACKUP_SUFFIX) else email
        val = int(stat.get("value", 0) or 0)
        entry = result.setdefault(uid, {"tx": 0, "rx": 0})
        if direction == "downlink":
            entry["tx"] += val
        elif direction == "uplink":
            entry["rx"] += val
    return result


def merge_traffic(dst, src):
    for uid, stat in src.items():
        cur = dst.setdefault(uid, {"tx": 0, "rx": 0})
        cur["tx"] = int(cur.get("tx", 0)) + int(stat.get("tx", 0))
        cur["rx"] = int(cur.get("rx", 0)) + int(stat.get("rx", 0))


def prune_daily(daily, today):
    cutoff = (today - timedelta(days=DAILY_RETENTION_DAYS - 1)).strftime("%Y-%m-%d")
    for k in list(daily.keys()):
        if k < cutoff:
            del daily[k]


def accumulate_daily(traffic, now):
    day_key = now.strftime("%Y-%m-%d")
    daily = load_json(USAGE_DAILY_FILE, {})
    daily.setdefault(day_key, {})
    for uid, stat in traffic.items():
        cur = normalize_usage_entry(daily[day_key].get(uid, 0))
        tx = int(stat.get("tx", 0))
        rx = int(stat.get("rx", 0))
        cur["tx"] += tx
        cur["rx"] += rx
        cur["total"] += tx + rx
        daily[day_key][uid] = cur
    prune_daily(daily, now.date())
    save_json(USAGE_DAILY_FILE, daily)


import alerts as _alerts
import anomaly as _anomaly
from display import DISPLAY_MULTIPLIER as _DM


def _fmt_bytes(n):
    n = float(max(0, int(n)))
    units = ['B', 'KB', 'MB', 'GB', 'TB']
    i = 0
    while n >= 1024 and i < len(units) - 1:
        n /= 1024.0
        i += 1
    return f"{n:.2f} {units[i]}"


def check_alerts(usage, users, online, now, month_key, *, _opener=None):
    """Detect quota crossings and daily anomalies, dispatch alerts, persist dedup state.

    Wrapped in a top-level try/except by the caller; this function may itself
    raise on filesystem errors but those should never break the kick path.
    """
    cfg = _alerts.load_config()
    if not cfg:
        return  # nothing configured → nothing to send

    state = _alerts.load_state()
    daily = load_json(USAGE_DAILY_FILE, {})
    today_date = now.date()

    today_key = today_date.strftime('%Y-%m-%d')
    z_threshold = float(cfg.get('anomaly_z_threshold', _alerts.DEFAULT_Z_THRESHOLD))
    min_bytes = int(cfg.get('anomaly_min_bytes', _alerts.DEFAULT_MIN_BYTES))

    month_usage = (usage or {}).get(month_key, {})

    for uid, user_cfg in (users or {}).items():
        # ---- quota crossings ----
        quota = int((user_cfg or {}).get('monthly_quota_bytes', 0) or 0)
        if (user_cfg or {}).get('guest') and quota > 0:
            entry = month_usage.get(uid, 0)
            if isinstance(entry, dict):
                raw_total = int(entry.get('total', 0))
            else:
                raw_total = int(entry or 0)
            scaled = int(raw_total * _DM)
            pct = scaled * 100.0 / quota
            if pct >= 100 and not _alerts.already_alerted(state, 'quota_100', uid, month_key):
                _alerts.dispatch({
                    'kind': 'quota_100', 'user': uid,
                    'details': {'used_human': _fmt_bytes(scaled),
                                'total_human': _fmt_bytes(quota),
                                'cycle': month_key},
                }, config=cfg, opener=_opener)
                _alerts.mark_alerted(state, 'quota_100', uid, month_key)
            elif pct >= 80 and not _alerts.already_alerted(state, 'quota_80', uid, month_key):
                _alerts.dispatch({
                    'kind': 'quota_80', 'user': uid,
                    'details': {'used_human': _fmt_bytes(scaled),
                                'total_human': _fmt_bytes(quota),
                                'cycle': month_key},
                }, config=cfg, opener=_opener)
                _alerts.mark_alerted(state, 'quota_80', uid, month_key)

        # ---- anomaly ----
        if _alerts.already_alerted(state, 'anomaly', uid, today_key):
            continue
        hit = _anomaly.detect(uid, daily, today_date,
                              z_threshold=z_threshold, min_bytes=min_bytes)
        if hit is not None:
            _alerts.dispatch({
                'kind': 'anomaly', 'user': uid,
                'details': {'today_human': _fmt_bytes(int(hit['today'] * _DM)),
                            'mean_human': _fmt_bytes(int(hit['mean'] * _DM)),
                            'z': hit['z']},
            }, config=cfg, opener=_opener)
            _alerts.mark_alerted(state, 'anomaly', uid, today_key)

    _alerts.save_state(state)


def main():
    users = load_json(USERS_FILE, {})
    now = datetime.now()
    month_key = billing_month_key(now)
    traffic = get("/traffic?clear=1") or {}
    merge_traffic(traffic, get_xray_traffic())
    with usage_lock():
        usage = load_json(USAGE_FILE, {})
        usage.setdefault(month_key, {})
        maybe_reset_all_usage_on_day_21(now, users, usage, month_key)
        usage = load_json(USAGE_FILE, {})
        usage.setdefault(month_key, {})

        for uid, stat in traffic.items():
            cur = normalize_usage_entry(usage[month_key].get(uid, 0))
            tx = int(stat.get("tx", 0))
            rx = int(stat.get("rx", 0))
            cur["tx"] += tx
            cur["rx"] += rx
            cur["total"] += tx + rx
            usage[month_key][uid] = cur

        save_json(USAGE_FILE, usage)
        accumulate_daily(traffic, now)

    online = get("/online")
    save_json(ONLINE_SNAPSHOT_FILE, online)

    try:
        check_alerts(usage, users, online, now, month_key)
    except Exception as e:
        import sys
        print(f"alerts: skipped due to error: {e}", file=sys.stderr)

    to_kick = []
    for uid, cfg in users.items():
        if not cfg.get("guest"):
            continue
        quota = int(cfg.get("monthly_quota_bytes", 0))
        if quota <= 0:
            continue
        used = normalize_usage_entry(usage[month_key].get(uid, 0))["total"]
        if used * DISPLAY_MULTIPLIER >= quota and int(online.get(uid, 0)) > 0:
            to_kick.append(uid)

    if to_kick:
        post("/kick", to_kick)


if __name__ == "__main__":
    main()
