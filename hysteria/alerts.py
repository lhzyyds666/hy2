"""Alert dispatcher: telegram + signed webhook, fire-and-forget, dedup-aware.

The dispatcher silently no-ops when alerts.json is missing. State is kept in a
small JSON file so that quota crossings dedupe per billing month and anomaly
events dedupe per day.
"""
import hashlib
import hmac
import json
import logging
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

CONFIG_FILE = Path('/root/hysteria/alerts.json')
STATE_FILE = Path('/root/hysteria/state/alert_state.json')

DEFAULT_Z_THRESHOLD = 3.0
DEFAULT_MIN_BYTES = 1 << 30

log = logging.getLogger('hy2.alerts')

_STATE_KEYS = ('quota_80', 'quota_100', 'anomaly')


def load_config(path=None):
    """Return parsed alerts.json or None if absent/unreadable."""
    p = Path(path) if path is not None else CONFIG_FILE
    try:
        return json.loads(p.read_text(encoding='utf-8'))
    except FileNotFoundError:
        return None
    except (OSError, ValueError) as e:
        log.warning('alerts: cannot read %s: %s', p, e)
        return None


def _empty_state():
    return {k: {} for k in _STATE_KEYS}


def load_state(path=None):
    p = Path(path) if path is not None else STATE_FILE
    try:
        data = json.loads(p.read_text(encoding='utf-8'))
        if not isinstance(data, dict):
            return _empty_state()
        for k in _STATE_KEYS:
            data.setdefault(k, {})
        return data
    except FileNotFoundError:
        return _empty_state()
    except (OSError, ValueError):
        log.warning('alerts: state corrupt, resetting')
        return _empty_state()


def save_state(state, path=None):
    p = Path(path) if path is not None else STATE_FILE
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(state, ensure_ascii=True, indent=2), encoding='utf-8')


def already_alerted(state, kind, user, key):
    """Return True if (kind, user) was last alerted at exactly `key`."""
    return state.get(kind, {}).get(user) == key


def mark_alerted(state, kind, user, key):
    state.setdefault(kind, {})[user] = key


def format_message(event):
    kind = event.get('kind')
    user = event.get('user', '?')
    details = event.get('details') or {}
    if kind == 'quota_80':
        return (f"\U0001F7E1 {user} 已用 80% "
                f"({details.get('used_human','?')} / {details.get('total_human','?')}) "
                f"· 周期 {details.get('cycle','?')}")
    if kind == 'quota_100':
        return (f"\U0001F534 {user} 已耗尽 "
                f"({details.get('used_human','?')} / {details.get('total_human','?')}) "
                f"· 周期 {details.get('cycle','?')}")
    if kind == 'anomaly':
        z = details.get('z', 0.0)
        return (f"⚠️ {user} 今日 {details.get('today_human','?')} "
                f"(基线 {details.get('mean_human','?')}, z={z:.1f})")
    return f"{kind}: {user}"


def _post_telegram(cfg, message, *, opener):
    bot = cfg.get('bot_token')
    chat = cfg.get('chat_id')
    if not bot or not chat:
        return
    url = f'https://api.telegram.org/bot{bot}/sendMessage'
    body = urllib.parse.urlencode({'chat_id': chat, 'text': message}).encode('utf-8')
    req = urllib.request.Request(url, data=body, method='POST')
    try:
        opener.urlopen(req, timeout=5).read()
    except (urllib.error.URLError, OSError) as e:
        log.warning('telegram alert failed: %s', e)


def _post_webhook(cfg, event, *, opener):
    url = cfg.get('url')
    if not url:
        return
    body = json.dumps(event, ensure_ascii=True).encode('utf-8')
    headers = {'Content-Type': 'application/json'}
    secret = cfg.get('secret')
    if secret:
        sig = hmac.new(secret.encode('utf-8'), body, hashlib.sha256).hexdigest()
        headers['X-Hy2-Signature'] = f'sha256={sig}'
    req = urllib.request.Request(url, data=body, method='POST', headers=headers)
    try:
        opener.urlopen(req, timeout=5).read()
    except (urllib.error.URLError, OSError) as e:
        log.warning('webhook alert failed: %s', e)


def dispatch(event, *, config=None, opener=None):
    """Fire `event` to every configured channel. Never raises."""
    cfg = config if config is not None else load_config()
    if not cfg:
        return
    transport = opener if opener is not None else urllib.request
    msg = format_message(event)
    if cfg.get('telegram'):
        _post_telegram(cfg['telegram'], msg, opener=transport)
    if cfg.get('webhook'):
        _post_webhook(cfg['webhook'], event, opener=transport)
