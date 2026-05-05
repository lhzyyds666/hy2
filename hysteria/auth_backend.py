#!/usr/bin/env python3
import json
import base64
import hashlib
import hmac
import sys
import urllib.request
from datetime import datetime

import user_compat

USERS_FILE = "/root/hysteria/users.json"
USAGE_FILE = "/root/hysteria/state/usage.json"
ONLINE_SNAPSHOT_FILE = "/root/hysteria/state/online.json"
API_BASE = "http://127.0.0.1:25413"
API_SECRET = "__HY_API_SECRET__"


def load_json(path, default):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default


def usage_total(entry):
    if isinstance(entry, dict):
        tx = int(entry.get("tx", 0))
        rx = int(entry.get("rx", 0))
        return int(entry.get("total", tx + rx))
    return int(entry or 0)


def _b64url_decode_nopad(s):
    raw = (s or "").encode("ascii")
    pad = b"=" * ((4 - (len(raw) % 4)) % 4)
    return base64.urlsafe_b64decode(raw + pad)


def verify_password_hash(password, encoded):
    try:
        algo, rounds_s, salt_b64, digest_b64 = str(encoded).split("$", 3)
        if algo != "pbkdf2_sha256":
            return False
        rounds = int(rounds_s)
        salt = _b64url_decode_nopad(salt_b64)
        expected = _b64url_decode_nopad(digest_b64)
        actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, rounds)
        return hmac.compare_digest(actual, expected)
    except Exception:
        return False


def get_online_counts():
    req = urllib.request.Request(
        f"{API_BASE}/online",
        headers={"Authorization": API_SECRET},
        method="GET",
    )
    try:
        with urllib.request.urlopen(req, timeout=1.5) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except Exception:
        return load_json(ONLINE_SNAPSHOT_FILE, {})


def main():
    if len(sys.argv) < 3:
        sys.exit(1)

    auth_payload = sys.argv[2] or ""
    if ":" not in auth_payload:
        sys.exit(1)

    username, password = auth_payload.split(":", 1)
    users = load_json(USERS_FILE, {})
    u = users.get(username)
    if not u:
        sys.exit(1)
    token = str(u.get("sub_token") or "")
    ok = bool(token) and hmac.compare_digest(password, token)
    if not ok and u.get("password_hash"):
        ok = verify_password_hash(password, str(u.get("password_hash") or ""))
    if not ok:
        sys.exit(1)

    if user_compat.is_metered(u):
        now = datetime.now()
        if now.day >= 21:
            month_key = now.strftime("%Y-%m")
        else:
            from datetime import timedelta
            month_key = (now.replace(day=1) - timedelta(days=1)).strftime("%Y-%m")
        usage = load_json(USAGE_FILE, {})
        used = usage_total(usage.get(month_key, {}).get(username, 0))
        quota = int(u.get("monthly_quota_bytes", 0))
        if quota > 0 and used >= quota:
            sys.exit(1)

        max_devices = int(u.get("max_devices", 0))
        if max_devices > 0:
            online = get_online_counts()
            if int(online.get(username, 0)) >= max_devices:
                sys.exit(1)

    sys.stdout.write(username)
    sys.exit(0)


if __name__ == "__main__":
    main()
