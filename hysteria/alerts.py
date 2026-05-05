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
