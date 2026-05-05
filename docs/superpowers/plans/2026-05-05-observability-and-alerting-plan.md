# Observability & Alerting — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add inline 30-day sparklines to the admin dashboard, a `/admin/health` page, and a `traffic_limiter`-driven alert pipeline (Telegram + signed webhook) for quota crossings and z-score daily anomalies.

**Architecture:** Two new modules (`hysteria/anomaly.py`, `hysteria/alerts.py`) keep the math and dispatch logic out of the file that imports `fcntl`, so they unit-test cleanly on any platform. `traffic_limiter.main()` calls them after the existing daily-accumulation step. `subscription_service.py` gains a server-rendered SVG sparkline column, an extended `/admin/usage.json` payload, and a read-only `/admin/health` route.

**Tech Stack:** Python 3 stdlib only — no new runtime deps. `pytest` added as a dev-time dependency for the test suite.

**Spec:** [`docs/superpowers/specs/2026-05-05-observability-and-alerting-design.md`](../specs/2026-05-05-observability-and-alerting-design.md)

---

## File map

| Path | Purpose |
|---|---|
| `hysteria/anomaly.py` (new) | Pure z-score detector, no I/O |
| `hysteria/alerts.py` (new) | Config + state + dispatchers (telegram, webhook), HMAC signing |
| `hysteria/traffic_limiter.py` (mod) | Wires alerts/anomaly into `main()` |
| `hysteria/subscription_service.py` (mod) | Sparkline SVG + column, `/admin/health` route, `/admin/usage.json` extension, sidebar entry, CSS |
| `deploy.sh` (mod) | Render `alerts.py` and `anomaly.py` to `$HY_DIR` |
| `README.md` (mod) | Short "告警" section |
| `tests/conftest.py` (new) | `fcntl` stub for Windows; shared fixtures |
| `tests/test_anomaly.py` (new) | Unit tests for z-score logic |
| `tests/test_alerts.py` (new) | Unit tests for config / state / dispatch / HMAC |
| `tests/test_alert_integration.py` (new) | Smoke test for `traffic_limiter.check_alerts` |
| `tests/test_sparkline.py` (new) | Unit tests for sparkline SVG rendering |
| `tests/test_health_probes.py` (new) | Unit tests for the 6 health probes |

---

## Task 1: Test scaffold

**Files:**
- Create: `tests/conftest.py`
- Create: `tests/__init__.py`
- Create: `pytest.ini`
- Create: `tests/test_smoke.py`

- [ ] **Step 1.1: Install pytest**

```bash
python -m pip install --user pytest
```

Expected: `Successfully installed pytest-...` (or "already satisfied").

- [ ] **Step 1.2: Create `tests/__init__.py`**

```python
```

(empty file — makes `tests` a package).

- [ ] **Step 1.3: Create `pytest.ini`**

```ini
[pytest]
testpaths = tests
pythonpath = . hysteria
addopts = -v --tb=short
```

- [ ] **Step 1.4: Create `tests/conftest.py`**

```python
"""Shared pytest setup. Stubs `fcntl` on Windows so the production
modules (which import it at top level) can be loaded for testing."""
import sys
import types


def _install_fcntl_stub() -> None:
    if 'fcntl' in sys.modules:
        return
    stub = types.ModuleType('fcntl')
    stub.LOCK_EX = 0
    stub.LOCK_UN = 0
    stub.flock = lambda *_a, **_k: None
    sys.modules['fcntl'] = stub


_install_fcntl_stub()
```

- [ ] **Step 1.5: Create `tests/test_smoke.py`**

```python
"""Sanity check that the test scaffold loads the production modules."""


def test_anomaly_module_will_be_importable_eventually():
    # Until Task 2 lands, this just exercises the test runner itself.
    assert 1 + 1 == 2
```

- [ ] **Step 1.6: Run the suite**

```bash
python -m pytest
```

Expected: 1 passed.

- [ ] **Step 1.7: Commit**

```bash
git add tests/__init__.py tests/conftest.py tests/test_smoke.py pytest.ini
git commit -m "test: scaffold pytest with fcntl stub for Windows dev"
```

---

## Task 2: Anomaly module (TDD)

**Files:**
- Create: `hysteria/anomaly.py`
- Create: `tests/test_anomaly.py`

- [ ] **Step 2.1: Write the failing tests**

Create `tests/test_anomaly.py`:

```python
"""Z-score anomaly detection — math runs on raw bytes, no I/O."""
from datetime import date, timedelta

from anomaly import detect

GiB = 1 << 30


def _hist(uid, today, values):
    """Build a `daily` dict where index 0 of `values` is today, 1 is yesterday, ..."""
    out = {}
    for i, v in enumerate(values):
        dk = (today - timedelta(days=i)).strftime('%Y-%m-%d')
        out[dk] = {uid: {'tx': 0, 'rx': v, 'total': v}}
    return out


def test_returns_none_when_today_below_min_bytes():
    today = date(2026, 5, 5)
    daily = _hist('alice', today, [500_000_000, 1, 1, 1])  # 500 MB today
    assert detect('alice', daily, today) is None


def test_returns_none_when_history_too_short():
    today = date(2026, 5, 5)
    # only 2 prior non-zero days
    daily = _hist('alice', today, [10 * GiB, 100, 100])
    assert detect('alice', daily, today) is None


def test_flags_when_zscore_over_threshold():
    today = date(2026, 5, 5)
    # baseline ~ 1 GiB, today 20 GiB → very high z
    daily = _hist('alice', today, [20 * GiB, GiB, GiB, GiB, GiB, GiB, GiB, GiB])
    out = detect('alice', daily, today, z_threshold=3.0)
    assert out is not None
    assert out['user'] == 'alice'
    assert out['today'] == 20 * GiB
    assert out['z'] > 3.0


def test_does_not_flag_when_zscore_below_threshold():
    today = date(2026, 5, 5)
    # noisy baseline matching today
    daily = _hist('alice', today, [10 * GiB, 8 * GiB, 12 * GiB, 9 * GiB, 11 * GiB,
                                    10 * GiB, 9 * GiB, 11 * GiB])
    assert detect('alice', daily, today, z_threshold=3.0) is None


def test_zero_stdev_requires_double_mean():
    today = date(2026, 5, 5)
    daily = _hist('alice', today, [3 * GiB, GiB, GiB, GiB])  # stdev=0, today=3*mean
    out = detect('alice', daily, today)
    assert out is not None and out['stdev'] == 0.0


def test_zero_stdev_skipped_if_only_slightly_above():
    today = date(2026, 5, 5)
    daily = _hist('alice', today, [int(1.5 * GiB), GiB, GiB, GiB])
    assert detect('alice', daily, today) is None


def test_returns_none_for_unknown_user():
    today = date(2026, 5, 5)
    daily = _hist('alice', today, [10 * GiB] * 8)
    assert detect('bob', daily, today) is None


def test_handles_int_only_legacy_entries():
    today = date(2026, 5, 5)
    daily = {}
    for i in range(8):
        dk = (today - timedelta(days=i)).strftime('%Y-%m-%d')
        daily[dk] = {'alice': (20 * GiB if i == 0 else GiB)}  # int legacy form
    out = detect('alice', daily, today)
    assert out is not None and out['today'] == 20 * GiB
```

- [ ] **Step 2.2: Verify tests fail**

```bash
python -m pytest tests/test_anomaly.py
```

Expected: 8 failures with `ModuleNotFoundError: No module named 'anomaly'`.

- [ ] **Step 2.3: Implement `hysteria/anomaly.py`**

```python
"""Z-score anomaly detection for daily traffic totals.

All math operates on raw bytes (pre-DISPLAY_MULTIPLIER). Scaling is a
display concern handled in the alert formatter, not here.
"""
from datetime import timedelta
from statistics import mean, pstdev

DEFAULT_Z_THRESHOLD = 3.0
DEFAULT_MIN_BYTES = 1 << 30  # 1 GiB


def detect(uid, daily, today, *, z_threshold=DEFAULT_Z_THRESHOLD,
           min_bytes=DEFAULT_MIN_BYTES):
    """Return an anomaly record for `uid` on `today`, or None.

    Args:
        uid:          user id (string)
        daily:        {YYYY-MM-DD: {uid: int | {'tx','rx','total'}}}
        today:        a `datetime.date`
        z_threshold:  flag if z > this
        min_bytes:    floor below which today's traffic is ignored

    Returns: {"user", "today", "mean", "stdev", "z"} or None
    """
    today_total = _entry_total((daily.get(today.strftime('%Y-%m-%d')) or {}).get(uid))
    if today_total < min_bytes:
        return None

    history = []
    for i in range(1, 8):
        dk = (today - timedelta(days=i)).strftime('%Y-%m-%d')
        v = _entry_total((daily.get(dk) or {}).get(uid))
        if v > 0:
            history.append(v)
    if len(history) < 3:
        return None

    h_mean = mean(history)
    h_stdev = pstdev(history)

    if h_stdev == 0:
        if today_total > 2 * h_mean:
            return {'user': uid, 'today': today_total, 'mean': h_mean,
                    'stdev': 0.0, 'z': float('inf')}
        return None

    z = (today_total - h_mean) / h_stdev
    if z > z_threshold:
        return {'user': uid, 'today': today_total, 'mean': h_mean,
                'stdev': h_stdev, 'z': z}
    return None


def _entry_total(entry):
    if not entry:
        return 0
    if isinstance(entry, dict):
        return int(entry.get('total', int(entry.get('tx', 0)) + int(entry.get('rx', 0))))
    return int(entry or 0)
```

- [ ] **Step 2.4: Verify tests pass**

```bash
python -m pytest tests/test_anomaly.py
```

Expected: 8 passed.

- [ ] **Step 2.5: Commit**

```bash
git add hysteria/anomaly.py tests/test_anomaly.py
git commit -m "feat: add z-score anomaly detector for daily traffic"
```

---

## Task 3: Alerts module — config and state

**Files:**
- Create: `hysteria/alerts.py`
- Create: `tests/test_alerts.py`

- [ ] **Step 3.1: Write the failing tests for config + state**

Create `tests/test_alerts.py`:

```python
"""Alerts dispatcher — config loading, state dedup, transports."""
import json
from pathlib import Path

import alerts


# ---------- config loading -----------------------------------------------------

def test_load_config_returns_none_when_missing(tmp_path):
    assert alerts.load_config(tmp_path / 'no.json') is None


def test_load_config_returns_none_on_invalid_json(tmp_path):
    p = tmp_path / 'bad.json'
    p.write_text('{not json')
    assert alerts.load_config(p) is None


def test_load_config_returns_dict_on_valid(tmp_path):
    p = tmp_path / 'a.json'
    p.write_text(json.dumps({'telegram': {'bot_token': 't', 'chat_id': 'c'}}))
    cfg = alerts.load_config(p)
    assert cfg['telegram']['bot_token'] == 't'


# ---------- state file ---------------------------------------------------------

def test_load_state_returns_empty_when_missing(tmp_path):
    s = alerts.load_state(tmp_path / 'no.json')
    assert s == {'quota_80': {}, 'quota_100': {}, 'anomaly': {}}


def test_load_state_resets_on_corruption(tmp_path):
    p = tmp_path / 'corrupt.json'
    p.write_text('garbage')
    s = alerts.load_state(p)
    assert s == {'quota_80': {}, 'quota_100': {}, 'anomaly': {}}


def test_load_state_fills_missing_keys(tmp_path):
    p = tmp_path / 'partial.json'
    p.write_text(json.dumps({'quota_80': {'alice': '2026-05'}}))
    s = alerts.load_state(p)
    assert s['quota_80'] == {'alice': '2026-05'}
    assert s['quota_100'] == {} and s['anomaly'] == {}


def test_save_and_reload_state_roundtrip(tmp_path):
    p = tmp_path / 'state.json'
    s = alerts.load_state(p)
    alerts.mark_alerted(s, 'anomaly', 'bob', '2026-05-05')
    alerts.save_state(s, p)
    s2 = alerts.load_state(p)
    assert alerts.already_alerted(s2, 'anomaly', 'bob', '2026-05-05')
    assert not alerts.already_alerted(s2, 'anomaly', 'bob', '2026-05-04')
    assert not alerts.already_alerted(s2, 'anomaly', 'alice', '2026-05-05')
```

- [ ] **Step 3.2: Verify tests fail**

```bash
python -m pytest tests/test_alerts.py
```

Expected: 7 failures with `ModuleNotFoundError: No module named 'alerts'`.

- [ ] **Step 3.3: Implement config + state in `hysteria/alerts.py`**

```python
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
```

- [ ] **Step 3.4: Verify config + state tests pass**

```bash
python -m pytest tests/test_alerts.py
```

Expected: 7 passed.

- [ ] **Step 3.5: Commit**

```bash
git add hysteria/alerts.py tests/test_alerts.py
git commit -m "feat: alerts module — config loading and dedup state"
```

---

## Task 4: Alerts module — message formatting

**Files:**
- Modify: `hysteria/alerts.py`
- Modify: `tests/test_alerts.py`

- [ ] **Step 4.1: Append failing tests**

Append to `tests/test_alerts.py`:

```python
# ---------- message formatting -------------------------------------------------

def test_format_quota_80():
    msg = alerts.format_message({
        'kind': 'quota_80', 'user': 'alice',
        'details': {'used_human': '12.0 GB', 'total_human': '15.0 GB',
                    'cycle': '2026-05'},
    })
    assert 'alice' in msg and '80%' in msg and '12.0 GB' in msg and '2026-05' in msg


def test_format_quota_100():
    msg = alerts.format_message({
        'kind': 'quota_100', 'user': 'bob',
        'details': {'used_human': '15.5 GB', 'total_human': '15.0 GB',
                    'cycle': '2026-05'},
    })
    assert 'bob' in msg and ('耗尽' in msg or '100' in msg)


def test_format_anomaly():
    msg = alerts.format_message({
        'kind': 'anomaly', 'user': 'carol',
        'details': {'today_human': '40.0 GB', 'mean_human': '5.0 GB',
                    'z': 7.3},
    })
    assert 'carol' in msg and '40.0 GB' in msg and 'z=' in msg


def test_format_unknown_kind_does_not_raise():
    msg = alerts.format_message({'kind': 'mystery', 'user': 'x'})
    assert isinstance(msg, str) and 'x' in msg
```

- [ ] **Step 4.2: Verify formatting tests fail**

```bash
python -m pytest tests/test_alerts.py -k format
```

Expected: 4 failures with `AttributeError: module 'alerts' has no attribute 'format_message'`.

- [ ] **Step 4.3: Append `format_message` to `hysteria/alerts.py`**

```python
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
```

(Unicode escapes used so the source stays ASCII even if your shell has trouble with emoji/CJK paste-through; runtime renders correctly.)

- [ ] **Step 4.4: Verify formatting tests pass**

```bash
python -m pytest tests/test_alerts.py
```

Expected: 11 passed (7 prior + 4 new).

- [ ] **Step 4.5: Commit**

```bash
git add hysteria/alerts.py tests/test_alerts.py
git commit -m "feat: alerts module — message formatting"
```

---

## Task 5: Alerts module — transports + dispatch

**Files:**
- Modify: `hysteria/alerts.py`
- Modify: `tests/test_alerts.py`

- [ ] **Step 5.1: Append failing tests**

Append to `tests/test_alerts.py`:

```python
# ---------- dispatch / transports ---------------------------------------------

class FakeOpener:
    """Mimics urllib.request.urlopen — captures calls and replays canned responses."""
    def __init__(self):
        self.calls = []

    def urlopen(self, req, timeout=None):
        body = req.data.decode('utf-8') if req.data else ''
        self.calls.append({
            'url': req.full_url,
            'method': req.get_method(),
            'headers': dict(req.header_items()),
            'body': body,
        })
        class _Resp:
            def read(self_inner):
                return b''
            def __enter__(self_inner):
                return self_inner
            def __exit__(self_inner, *a):
                return False
        return _Resp()


def test_dispatch_no_op_when_config_none():
    opener = FakeOpener()
    alerts.dispatch({'kind': 'quota_80', 'user': 'a',
                     'details': {'used_human': '1', 'total_human': '2', 'cycle': '2026-05'}},
                    config=None, opener=opener)
    assert opener.calls == []


def test_dispatch_telegram_only():
    cfg = {'telegram': {'bot_token': 'BOT', 'chat_id': 'CHAT'}}
    opener = FakeOpener()
    alerts.dispatch({'kind': 'anomaly', 'user': 'a',
                     'details': {'today_human': '40 GB', 'mean_human': '5 GB', 'z': 7.0}},
                    config=cfg, opener=opener)
    assert len(opener.calls) == 1
    call = opener.calls[0]
    assert 'api.telegram.org/botBOT/sendMessage' in call['url']
    # form-urlencoded body with chat_id and text
    assert 'chat_id=CHAT' in call['body']
    assert 'text=' in call['body']


def test_dispatch_webhook_signs_when_secret_present():
    cfg = {'webhook': {'url': 'https://example.invalid/hook', 'secret': 'topsecret'}}
    opener = FakeOpener()
    event = {'kind': 'quota_100', 'user': 'a',
             'details': {'used_human': '20 GB', 'total_human': '15 GB', 'cycle': '2026-05'}}
    alerts.dispatch(event, config=cfg, opener=opener)
    assert len(opener.calls) == 1
    call = opener.calls[0]
    assert call['url'] == 'https://example.invalid/hook'
    assert call['headers'].get('Content-type') == 'application/json'
    assert call['headers'].get('X-hy2-signature', '').startswith('sha256=')


def test_dispatch_webhook_unsigned_when_no_secret():
    cfg = {'webhook': {'url': 'https://example.invalid/hook'}}
    opener = FakeOpener()
    alerts.dispatch({'kind': 'anomaly', 'user': 'x',
                     'details': {'today_human': '1', 'mean_human': '1', 'z': 4.0}},
                    config=cfg, opener=opener)
    assert 'X-hy2-signature' not in opener.calls[0]['headers']


def test_dispatch_swallows_transport_errors():
    """Network failure must NOT bubble out — the cron tick continues."""
    class BoomOpener:
        def urlopen(self, *a, **k):
            raise OSError('boom')
    cfg = {'telegram': {'bot_token': 't', 'chat_id': 'c'},
           'webhook': {'url': 'https://example.invalid/'}}
    alerts.dispatch({'kind': 'quota_80', 'user': 'x',
                     'details': {'used_human': '1', 'total_human': '2', 'cycle': '2026-05'}},
                    config=cfg, opener=BoomOpener())  # must not raise
```

- [ ] **Step 5.2: Verify dispatch tests fail**

```bash
python -m pytest tests/test_alerts.py -k dispatch
```

Expected: 5 failures with `AttributeError: module 'alerts' has no attribute 'dispatch'`.

- [ ] **Step 5.3: Append transports + dispatch to `hysteria/alerts.py`**

```python
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
```

- [ ] **Step 5.4: Verify dispatch tests pass**

```bash
python -m pytest tests/test_alerts.py
```

Expected: 16 passed.

- [ ] **Step 5.5: Commit**

```bash
git add hysteria/alerts.py tests/test_alerts.py
git commit -m "feat: alerts module — telegram + signed webhook transports"
```

---

## Task 6: Wire alerts into traffic_limiter

**Files:**
- Modify: `hysteria/traffic_limiter.py`
- Create: `tests/test_alert_integration.py`

- [ ] **Step 6.1: Write the failing integration tests**

Create `tests/test_alert_integration.py`:

```python
"""Integration tests for traffic_limiter.check_alerts.

These tests stub fcntl (via conftest) and stub the network so check_alerts can
run without a real cron environment.
"""
from datetime import datetime
from pathlib import Path

import traffic_limiter as tl

GiB = 1 << 30


def _setup(tmp_path, daily, usage, users, online, monkeypatch, alerts_cfg=None):
    monkeypatch.setattr(tl, 'USAGE_DAILY_FILE', str(tmp_path / 'usage_daily.json'),
                        raising=False)
    Path(tl.USAGE_DAILY_FILE).write_text(__import__('json').dumps(daily))

    import alerts
    state_path = tmp_path / 'alert_state.json'
    cfg_path = tmp_path / 'alerts.json'
    monkeypatch.setattr(alerts, 'STATE_FILE', state_path, raising=False)
    monkeypatch.setattr(alerts, 'CONFIG_FILE', cfg_path, raising=False)
    if alerts_cfg is not None:
        cfg_path.write_text(__import__('json').dumps(alerts_cfg))

    sent = []

    class CapturingOpener:
        def urlopen(self, req, timeout=None):
            sent.append({'url': req.full_url, 'body': req.data})
            class _R:
                def read(self_inner): return b''
                def __enter__(self_inner): return self_inner
                def __exit__(self_inner, *a): return False
            return _R()

    return sent, CapturingOpener(), state_path


def test_no_op_when_alerts_config_missing(tmp_path, monkeypatch):
    today = datetime(2026, 5, 5)
    daily = {today.strftime('%Y-%m-%d'): {'alice': {'tx': 0, 'rx': 50 * GiB,
                                                    'total': 50 * GiB}}}
    for i in range(1, 8):
        d = (today.replace(day=today.day - i)).strftime('%Y-%m-%d')
        daily[d] = {'alice': {'tx': 0, 'rx': GiB, 'total': GiB}}
    sent, opener, _ = _setup(tmp_path, daily=daily, usage={}, users={'alice': {}},
                             online={}, monkeypatch=monkeypatch, alerts_cfg=None)
    tl.check_alerts(usage={}, users={'alice': {}}, online={}, now=today,
                    month_key='2026-05', _opener=opener)
    assert sent == []


def test_anomaly_fires_once_per_day(tmp_path, monkeypatch):
    today = datetime(2026, 5, 5)
    daily = {today.strftime('%Y-%m-%d'): {'alice': {'tx': 0, 'rx': 50 * GiB,
                                                    'total': 50 * GiB}}}
    for i in range(1, 8):
        d = (today.replace(day=today.day - i)).strftime('%Y-%m-%d')
        daily[d] = {'alice': {'tx': 0, 'rx': GiB, 'total': GiB}}
    sent, opener, state_path = _setup(
        tmp_path, daily=daily, usage={}, users={'alice': {}}, online={},
        monkeypatch=monkeypatch,
        alerts_cfg={'webhook': {'url': 'https://example.invalid/'}})
    tl.check_alerts(usage={}, users={'alice': {}}, online={}, now=today,
                    month_key='2026-05', _opener=opener)
    assert len(sent) == 1, 'anomaly must fire on first tick'
    tl.check_alerts(usage={}, users={'alice': {}}, online={}, now=today,
                    month_key='2026-05', _opener=opener)
    assert len(sent) == 1, 'second tick same day must NOT re-fire'


def test_quota_80_fires_when_crossed(tmp_path, monkeypatch):
    today = datetime(2026, 5, 5)
    # No daily history → no anomaly. Just quota.
    sent, opener, _ = _setup(
        tmp_path, daily={}, usage={'2026-05': {'alice': {'tx': 0, 'rx': 12 * GiB,
                                                         'total': 12 * GiB}}},
        users={'alice': {'guest': True, 'monthly_quota_bytes': 30 * GiB}},
        online={}, monkeypatch=monkeypatch,
        alerts_cfg={'webhook': {'url': 'https://example.invalid/'}})
    # 12 GiB raw * 2.28 multiplier = ~27.36 GiB, ~91% of 30 GiB → crosses both 80% and 100%? 91% only crosses 80%.
    tl.check_alerts(
        usage={'2026-05': {'alice': {'tx': 0, 'rx': 12 * GiB, 'total': 12 * GiB}}},
        users={'alice': {'guest': True, 'monthly_quota_bytes': 30 * GiB}},
        online={}, now=today, month_key='2026-05', _opener=opener)
    assert len(sent) == 1
    assert b'quota_80' in sent[0]['body']


def test_quota_does_not_refire_same_month(tmp_path, monkeypatch):
    today = datetime(2026, 5, 5)
    sent, opener, _ = _setup(
        tmp_path, daily={},
        usage={'2026-05': {'alice': {'tx': 0, 'rx': 12 * GiB, 'total': 12 * GiB}}},
        users={'alice': {'guest': True, 'monthly_quota_bytes': 30 * GiB}},
        online={}, monkeypatch=monkeypatch,
        alerts_cfg={'webhook': {'url': 'https://example.invalid/'}})
    for _ in range(3):
        tl.check_alerts(
            usage={'2026-05': {'alice': {'tx': 0, 'rx': 12 * GiB, 'total': 12 * GiB}}},
            users={'alice': {'guest': True, 'monthly_quota_bytes': 30 * GiB}},
            online={}, now=today, month_key='2026-05', _opener=opener)
    assert len(sent) == 1
```

- [ ] **Step 6.2: Verify integration tests fail**

```bash
python -m pytest tests/test_alert_integration.py
```

Expected: 4 failures, `AttributeError: module 'traffic_limiter' has no attribute 'check_alerts'`.

- [ ] **Step 6.3: Add `check_alerts` to `hysteria/traffic_limiter.py`**

Append after the existing `accumulate_daily` function:

```python
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
```

Then wire it into `main()` — locate this block:

```python
        save_json(USAGE_FILE, usage)
        accumulate_daily(traffic, now)
```

Replace it with:

```python
        save_json(USAGE_FILE, usage)
        accumulate_daily(traffic, now)

    try:
        check_alerts(usage, users, online if False else load_json(ONLINE_SNAPSHOT_FILE, {}),
                     now, month_key)
    except Exception as e:  # never break kick path
        import sys
        print(f"alerts: skipped due to error: {e}", file=sys.stderr)
```

Wait — the call to `check_alerts` needs `online`, but `online` is only loaded later in `main()` (after the lock). Move `check_alerts` to AFTER the `online = get('/online')` line. Replace this block:

```python
    online = get("/online")
    save_json(ONLINE_SNAPSHOT_FILE, online)
```

with:

```python
    online = get("/online")
    save_json(ONLINE_SNAPSHOT_FILE, online)

    try:
        check_alerts(usage, users, online, now, month_key)
    except Exception as e:
        import sys
        print(f"alerts: skipped due to error: {e}", file=sys.stderr)
```

(Remove the earlier mis-placed try/except block if you added one.)

- [ ] **Step 6.4: Verify integration tests pass**

```bash
python -m pytest tests/test_alert_integration.py
```

Expected: 4 passed.

- [ ] **Step 6.5: Re-run the full suite**

```bash
python -m pytest
```

Expected: all tests passing (smoke + anomaly + alerts + integration).

- [ ] **Step 6.6: Commit**

```bash
git add hysteria/traffic_limiter.py tests/test_alert_integration.py
git commit -m "feat: traffic_limiter dispatches quota + anomaly alerts every tick"
```

---

## Task 7: Sparkline SVG helper

**Files:**
- Modify: `hysteria/subscription_service.py`
- Create: `tests/test_sparkline.py`

- [ ] **Step 7.1: Write failing tests**

Create `tests/test_sparkline.py`:

```python
"""Sparkline SVG rendering — pure function on a list of (date, bytes)."""
import re

import subscription_service as ss


def test_empty_returns_minimal_svg():
    out = ss.sparkline_svg([])
    assert '<svg' in out and '</svg>' in out
    assert '<rect' not in out


def test_zero_values_render_no_bars():
    vals = [(f'2026-05-0{i+1}', 0) for i in range(5)]
    out = ss.sparkline_svg(vals)
    assert out.count('<rect') == 0


def test_today_bar_carries_today_class():
    vals = [(f'2026-05-0{i+1}', i * 1_000_000) for i in range(1, 6)]
    out = ss.sparkline_svg(vals)
    rects = re.findall(r'<rect[^>]*>', out)
    assert any('today' in r for r in rects), 'last bar should carry today class'
    assert sum('today' in r for r in rects) == 1, 'only one today bar'


def test_max_height_does_not_overflow():
    vals = [('2026-05-01', 100), ('2026-05-02', 200), ('2026-05-03', 50)]
    out = ss.sparkline_svg(vals, height=24)
    # extract every height attr from rects
    heights = [int(h) for h in re.findall(r'<rect[^>]*height="(\d+)"', out)]
    assert max(heights) <= 24
    assert all(h >= 1 for h in heights)


def test_title_contains_date_and_bytes():
    vals = [('2026-05-05', 1_500_000_000)]
    out = ss.sparkline_svg(vals)
    assert '<title>' in out and '2026-05-05' in out
    assert 'GB' in out  # fmt_bytes formats as 1.40 GB
```

- [ ] **Step 7.2: Verify tests fail**

```bash
python -m pytest tests/test_sparkline.py
```

Expected: 5 failures, `AttributeError: module 'subscription_service' has no attribute 'sparkline_svg'`.

- [ ] **Step 7.3: Add `sparkline_svg` to `hysteria/subscription_service.py`**

Add immediately above `def render_daily_usage(...)`:

```python
def daily_window_for_user(uid, daily, *, days=30, today=None):
    """Return [(YYYY-MM-DD, scaled_total_bytes), ...] oldest-first for `days`."""
    today = today or datetime.now().date()
    out = []
    for i in reversed(range(days)):
        dk = (today - timedelta(days=i)).strftime('%Y-%m-%d')
        _tx, _rx, total = _scale_daily_entry((daily.get(dk) or {}).get(uid))
        out.append((dk, total))
    return out


def sparkline_svg(values, *, height=24):
    """Render a series of (date, bytes) into a compact bar SVG.

    Last entry carries the `today` class; zero-valued days render no bar.
    """
    n = len(values)
    if n == 0:
        return '<svg class="spark" width="0" height="' + str(height) + '"></svg>'
    max_v = max((v for _, v in values), default=0) or 1
    bar_w = 3
    gap = 1
    width = n * bar_w + (n - 1) * gap
    parts = []
    for i, (dk, v) in enumerate(values):
        if v <= 0:
            continue
        h = max(1, int(round(height * v / max_v)))
        x = i * (bar_w + gap)
        y = height - h
        cls = 'spark-bar today' if i == n - 1 else 'spark-bar'
        title = f'{dk}: {fmt_bytes(v)}'
        parts.append(
            f'<rect class="{cls}" x="{x}" y="{y}" width="{bar_w}" height="{h}">'
            f'<title>{html.escape(title)}</title></rect>'
        )
    return (f'<svg class="spark" width="{width}" height="{height}" '
            f'viewBox="0 0 {width} {height}" aria-label="30 天趋势">'
            f'{"".join(parts)}</svg>')
```

- [ ] **Step 7.4: Verify tests pass**

```bash
python -m pytest tests/test_sparkline.py
```

Expected: 5 passed.

- [ ] **Step 7.5: Commit**

```bash
git add hysteria/subscription_service.py tests/test_sparkline.py
git commit -m "feat: sparkline SVG helper for admin dashboard"
```

---

## Task 8: Sparkline column in /admin and /admin/usage.json

**Files:**
- Modify: `hysteria/subscription_service.py`

This is presentational; we drive correctness by manual verification + a quick render test.

- [ ] **Step 8.1: Add an HTML smoke test**

Append to `tests/test_sparkline.py`:

```python
def test_admin_render_includes_sparkline_column(tmp_path, monkeypatch):
    monkeypatch.setattr(ss, 'USERS_FILE', tmp_path / 'users.json', raising=False)
    monkeypatch.setattr(ss, 'USAGE_FILE', tmp_path / 'usage.json', raising=False)
    monkeypatch.setattr(ss, 'USAGE_DAILY_FILE', tmp_path / 'usage_daily.json', raising=False)
    monkeypatch.setattr(ss, 'ONLINE_FILE', tmp_path / 'online.json', raising=False)

    (tmp_path / 'users.json').write_text('{"alice": {"monthly_quota_bytes": 0}}')
    (tmp_path / 'usage.json').write_text('{}')
    (tmp_path / 'usage_daily.json').write_text(
        '{"2026-05-05": {"alice": {"tx":0,"rx":1000000000,"total":1000000000}}}')
    (tmp_path / 'online.json').write_text('{}')

    out = ss.render_admin('panel.example.com', 'http://panel.example.com')
    # New column header
    assert '30 天趋势' in out or '趋势' in out
    # SVG present in the row
    assert 'class="spark"' in out
```

- [ ] **Step 8.2: Verify it fails**

```bash
python -m pytest tests/test_sparkline.py::test_admin_render_includes_sparkline_column
```

Expected: failure (column not yet rendered).

- [ ] **Step 8.3: Modify `row_form` to accept `daily` and emit the spark cell**

Two surgical edits in `hysteria/subscription_service.py`:

**Edit A** — change the function signature. Find:

```python
def row_form(user, cfg, online, host, base_url, usage_month=None):
    tx, rx, used = scaled_usage_for_user(user, usage_month)
```

Replace with:

```python
def row_form(user, cfg, online, host, base_url, usage_month=None, daily=None):
    tx, rx, used = scaled_usage_for_user(user, usage_month)
    spark_cell = ''
    if daily is not None:
        spark_cell = f'<td class="spark-cell" data-role="spark">{sparkline_svg(daily_window_for_user(user, daily, days=30))}</td>'
```

**Edit B** — slot the cell into the row between the user `<td>` (closing `</td>` after the online-count line) and the usage `<td>`. Find:

```python
    </div>
  </div>
</td>
<td>
  <div class="row" style="justify-content:space-between;margin-bottom:4px;">
    <span class="bold" data-role="used">{fmt_bytes(used)}</span>
```

Replace with:

```python
    </div>
  </div>
</td>
{spark_cell}
<td>
  <div class="row" style="justify-content:space-between;margin-bottom:4px;">
    <span class="bold" data-role="used">{fmt_bytes(used)}</span>
```

- [ ] **Step 8.4: Update `render_admin` to load daily and add the column header**

In `render_admin`:
1. Load daily once: `daily = load_json(USAGE_DAILY_FILE, {})`
2. Pass it: `''.join(row_form(u, cfg, online, host, base_url, usage_month, daily) for u, cfg in users.items())`
3. In the `<thead><tr>` row, insert a new `<th>30 天趋势</th>` between "用户" and "本月用量"
4. Update the empty-state colspan from `4` to `5`

- [ ] **Step 8.5: Extend `/admin/usage.json` to include `spark_html`**

In `handle_get`, locate the `/admin/usage.json` branch and replace the inner loop with:

```python
            users = load_json_cached(USERS_FILE, {})
            online = load_json_cached(ONLINE_FILE, {})
            usage_month = load_json_cached(USAGE_FILE, {}).get(month_key(), {})
            daily = load_json_cached(USAGE_DAILY_FILE, {})
            user_list = []
            total_used = 0
            for u, cfg in users.items():
                tx, rx, used = scaled_usage_for_user(u, usage_month)
                total = user_total_quota(cfg)
                total_used += used
                user_list.append({
                    'user': u,
                    'tx': tx,
                    'rx': rx,
                    'used': used,
                    'total': total,
                    'percent': pct(used, total),
                    'online': int(online.get(u, 0)),
                    'spark_html': sparkline_svg(daily_window_for_user(u, daily, days=30)),
                })
            payload = json.dumps({'total_used': total_used, 'users': user_list}, ensure_ascii=True)
```

- [ ] **Step 8.6: Update the admin polling JS to refresh the spark cell**

In `render_admin`'s `<script>` block, locate the `index.set(tr.dataset.user, {...})` block. Add a `spark` field:

```javascript
    index.set(tr.dataset.user, {{
      tr: tr,
      online: tr.querySelector('[data-role="online"]'),
      used: tr.querySelector('[data-role="used"]'),
      bar: tr.querySelector('[data-role="bar"]'),
      detail: tr.querySelector('[data-role="detail"]'),
      spark: tr.querySelector('[data-role="spark"]'),
      lastUsed: -1, lastOnline: -1, lastPercent: -1, lastSpark: '',
    }});
```

And in the `tick()` per-user update loop, append:

```javascript
        if (u.spark_html && u.spark_html !== row.lastSpark) {{
          if (row.spark) row.spark.innerHTML = u.spark_html;
          row.lastSpark = u.spark_html;
        }}
```

- [ ] **Step 8.7: Add CSS for sparkline**

Locate the `.daily-table { ... }` block and add directly above it:

```css
/* ── Admin row sparkline ──────────────────────────────────── */
.spark { display: block; }
.spark-bar { fill: var(--text-muted); }
.spark-bar.today { fill: var(--accent); }
.spark-cell { padding-top: 14px; padding-bottom: 14px; min-width: 130px; }
```

- [ ] **Step 8.8: Verify**

```bash
python -m pytest tests/test_sparkline.py
```

Expected: 6 passed (5 prior + new admin render test).

```bash
python -m py_compile hysteria/subscription_service.py
```

Expected: no output (no syntax errors).

- [ ] **Step 8.9: Commit**

```bash
git add hysteria/subscription_service.py tests/test_sparkline.py
git commit -m "feat: 30-day sparkline column on admin dashboard with live refresh"
```

---

## Task 9: Health page probes

**Files:**
- Modify: `hysteria/subscription_service.py`
- Create: `tests/test_health_probes.py`

- [ ] **Step 9.1: Write failing tests**

Create `tests/test_health_probes.py`:

```python
"""Health page probes — each one read-only and individually testable."""
from datetime import datetime, timedelta
from unittest.mock import patch

import subscription_service as ss


def test_probe_cron_fresh(tmp_path, monkeypatch):
    f = tmp_path / 'usage.json'
    f.write_text('{}')
    monkeypatch.setattr(ss, 'USAGE_FILE', f, raising=False)
    out = ss.probe_cron_heartbeat()
    assert out['ok'] is True
    assert '秒前' in out['label']


def test_probe_cron_stale(tmp_path, monkeypatch):
    import os
    f = tmp_path / 'usage.json'
    f.write_text('{}')
    old = (datetime.now() - timedelta(seconds=600)).timestamp()
    os.utime(f, (old, old))
    monkeypatch.setattr(ss, 'USAGE_FILE', f, raising=False)
    out = ss.probe_cron_heartbeat()
    assert out['ok'] is False


def test_probe_cron_missing(tmp_path, monkeypatch):
    monkeypatch.setattr(ss, 'USAGE_FILE', tmp_path / 'nope.json', raising=False)
    out = ss.probe_cron_heartbeat()
    assert out['ok'] is False
    assert out['label'] == '未知'


def test_probe_systemd_active():
    fake = type('R', (), {'stdout': 'active\n', 'returncode': 0})()
    with patch.object(ss.subprocess, 'run', return_value=fake):
        out = ss.probe_systemd('xray.service')
        assert out['ok'] is True


def test_probe_systemd_inactive():
    fake = type('R', (), {'stdout': 'inactive\n', 'returncode': 3})()
    with patch.object(ss.subprocess, 'run', return_value=fake):
        out = ss.probe_systemd('xray.service')
        assert out['ok'] is False


def test_probe_systemd_missing():
    with patch.object(ss.subprocess, 'run', side_effect=FileNotFoundError):
        out = ss.probe_systemd('xray.service')
        assert out['ok'] is False
        assert out['label'] == '未知'


def test_probe_disk():
    fake = type('U', (), {'total': 100, 'free': 50, 'used': 50})()
    with patch.object(ss.shutil, 'disk_usage', return_value=fake):
        out = ss.probe_disk()
        assert out['ok'] is True
        assert '50' in out['label']


def test_probe_disk_low():
    fake = type('U', (), {'total': 100, 'free': 5, 'used': 95})()
    with patch.object(ss.shutil, 'disk_usage', return_value=fake):
        out = ss.probe_disk()
        assert out['ok'] is False


def test_probe_online_sums_values(tmp_path, monkeypatch):
    f = tmp_path / 'online.json'
    f.write_text('{"alice": 2, "bob": 3}')
    monkeypatch.setattr(ss, 'ONLINE_FILE', f, raising=False)
    out = ss.probe_online()
    assert out['ok'] is True
    assert '5' in out['label']


def test_render_health_page_loads(tmp_path, monkeypatch):
    f = tmp_path / 'usage.json'; f.write_text('{}')
    g = tmp_path / 'online.json'; g.write_text('{}')
    monkeypatch.setattr(ss, 'USAGE_FILE', f, raising=False)
    monkeypatch.setattr(ss, 'ONLINE_FILE', g, raising=False)
    with patch.object(ss.subprocess, 'run', side_effect=FileNotFoundError):
        with patch.object(ss.shutil, 'disk_usage',
                          return_value=type('U', (), {'total': 100, 'free': 50, 'used': 50})()):
            html_out = ss.render_health('panel.example.com')
    assert '健康状态' in html_out
    assert 'cron' in html_out.lower() or '心跳' in html_out
```

- [ ] **Step 9.2: Verify tests fail**

```bash
python -m pytest tests/test_health_probes.py
```

Expected: 10 failures, `AttributeError: module 'subscription_service' has no attribute 'probe_cron_heartbeat'` etc.

- [ ] **Step 9.3: Add `import shutil, subprocess` (top of `subscription_service.py`)**

Locate the existing import block (around the `import json` line) and ensure these are imported at module scope:

```python
import shutil
import subprocess
```

(`subprocess` is already imported lazily inside `xray_reload_async` — promote that to top-level so probes can access `ss.subprocess` for monkeypatching.)

- [ ] **Step 9.4: Add probes + render_health**

Add immediately above `def render_reset_logs(...)`:

```python
def probe_cron_heartbeat():
    """How long since the cron tick last wrote usage.json. Stale if >120s."""
    try:
        mt = USAGE_FILE.stat().st_mtime
        age = int(time.time() - mt)
        return {'ok': age < 120, 'label': f'{age} 秒前'}  # "{age} 秒前"
    except Exception:
        return {'ok': False, 'label': '未知'}  # "未知"


def probe_systemd(unit):
    """`systemctl is-active <unit>` → ok if 'active'."""
    try:
        out = subprocess.run(['systemctl', 'is-active', unit],
                             capture_output=True, text=True, timeout=3)
        v = (out.stdout or '').strip()
        return {'ok': v == 'active', 'label': v or '未知'}
    except Exception:
        return {'ok': False, 'label': '未知'}


def probe_disk():
    try:
        u = shutil.disk_usage('/')
        free_pct = u.free * 100 / u.total
        return {'ok': free_pct > 15, 'label': f'{free_pct:.0f}% free'}
    except Exception:
        return {'ok': False, 'label': '未知'}


def probe_cert(path=None):
    p = Path(path) if path else Path('/root/hysteria/server.crt')
    try:
        out = subprocess.run(['openssl', 'x509', '-enddate', '-noout', '-in', str(p)],
                             capture_output=True, text=True, timeout=3)
        end_str = out.stdout.split('=', 1)[1].strip()
        end_dt = datetime.strptime(end_str, '%b %d %H:%M:%S %Y %Z')
        days = (end_dt - datetime.utcnow()).days
        return {'ok': days > 14, 'label': f'{days} 天剩余'}  # "{days} 天剩余"
    except Exception:
        return {'ok': False, 'label': '未知'}


def probe_online():
    try:
        data = load_json(ONLINE_FILE, {})
        n = sum(int(v) for v in data.values())
        return {'ok': True, 'label': f'{n} 在线'}  # "{n} 在线"
    except Exception:
        return {'ok': False, 'label': '未知'}


def _health_card(title, probe_result):
    cls = 'ok' if probe_result['ok'] else 'bad'
    return (f'<div class="card stat health-{cls}">'
            f'<div class="k">{html.escape(title)}</div>'
            f'<div class="v">{html.escape(probe_result["label"])}</div>'
            f'</div>')


def render_health(host):
    cards = [
        _health_card('cron 心跳', probe_cron_heartbeat()),
        _health_card('hysteria', probe_systemd('hysteria-server.service')),
        _health_card('xray', probe_systemd('xray.service')),
        _health_card('磁盘', probe_disk()),
        _health_card('TLS 证书', probe_cert()),
        _health_card('在线用户', probe_online()),
    ]
    content = (
        '<div class="grid grid-3">' + ''.join(cards) + '</div>'
        '<meta http-equiv="refresh" content="30">'
    )
    return render_admin_shell('health', '健康状态', content,  # "健康状态"
                              badge=host, subtitle='30 秒自动刷新')
```

- [ ] **Step 9.5: Add the sidebar entry and 'pulse' icon**

Locate `_ICONS = {` and add:

```python
    'pulse': '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>',
```

Locate `_SIDEBAR_NAV = [` and insert:

```python
    ('health', '/admin/health', '健康状态', 'pulse'),  # "健康状态"
```

(Place it after `('daily', ...)` and before `('config', ...)`.)

- [ ] **Step 9.6: Add the route**

In `handle_get`, locate the `/admin/daily` route block and insert directly after it:

```python
        if path == '/admin/health':
            if not is_logged_in(self):
                self.redirect('/login')
                return
            self.send_response_body(200, render_health(host),
                                    'text/html; charset=utf-8', send_payload)
            return
```

- [ ] **Step 9.7: Add CSS**

Append to BASE_CSS, immediately above the daily-table block:

```css
/* ── Health cards ─────────────────────────────────────────── */
.health-ok .v  { color: var(--ok); }
.health-bad .v { color: var(--danger); }
.health-ok::before, .health-bad::before { content: ''; display:block;
  width: 6px; height: 6px; border-radius: 50%; margin-bottom: 6px; }
.health-ok::before  { background: var(--ok);     box-shadow: 0 0 6px var(--ok-glow); }
.health-bad::before { background: var(--danger); box-shadow: 0 0 6px var(--danger-glow); }
```

- [ ] **Step 9.8: Verify tests pass**

```bash
python -m pytest tests/test_health_probes.py
```

Expected: 10 passed.

- [ ] **Step 9.9: Run the full suite**

```bash
python -m pytest
```

Expected: all tests passing.

- [ ] **Step 9.10: Commit**

```bash
git add hysteria/subscription_service.py tests/test_health_probes.py
git commit -m "feat: /admin/health page with cron/systemd/disk/TLS/online probes"
```

---

## Task 10: Deploy + README

**Files:**
- Modify: `deploy.sh`
- Modify: `README.md`
- Modify: `README.zh-CN.md`

- [ ] **Step 10.1: Add render lines for new modules**

In `deploy.sh`, locate the block:

```bash
render "$REPO_DIR/hysteria/auth_backend.py"          "$HY_DIR/auth_backend.py"
render "$REPO_DIR/hysteria/subscription_service.py"  "$HY_DIR/subscription_service.py"
render "$REPO_DIR/hysteria/traffic_limiter.py"       "$HY_DIR/traffic_limiter.py"
```

Replace with:

```bash
render "$REPO_DIR/hysteria/auth_backend.py"          "$HY_DIR/auth_backend.py"
render "$REPO_DIR/hysteria/subscription_service.py"  "$HY_DIR/subscription_service.py"
render "$REPO_DIR/hysteria/traffic_limiter.py"       "$HY_DIR/traffic_limiter.py"
render "$REPO_DIR/hysteria/alerts.py"                "$HY_DIR/alerts.py"
render "$REPO_DIR/hysteria/anomaly.py"               "$HY_DIR/anomaly.py"
```

- [ ] **Step 10.2: Lint deploy.sh**

```bash
bash -n deploy.sh
```

Expected: no output (no syntax errors).

- [ ] **Step 10.3: Add a "告警" section to `README.zh-CN.md`**

Append at the end (after any existing trailing content):

```markdown
## 告警（可选）

放一份 `/root/hysteria/alerts.json`（chmod 600）开启 Telegram / webhook 告警：

\`\`\`json
{
  "telegram": {"bot_token": "...", "chat_id": "..."},
  "webhook":  {"url": "https://example.com/hook", "secret": "可选-hmac-key"},
  "anomaly_z_threshold": 3.0,
  "anomaly_min_bytes": 1073741824
}
\`\`\`

- 配额跨过 80% / 100% → 每用户每月一次推送
- 当日相对最近 7 日均值 z-score > 阈值 → 每用户每日一次推送
- webhook 带 `secret` 时附 `X-Hy2-Signature: sha256=<hmac>`

文件不存在时告警通道静默关闭。健康总览见 `/admin/health`。
```

(Use literal triple-backtick blocks, not the escaped \`\`\` shown above.)

- [ ] **Step 10.4: Add the equivalent English section to `README.md`**

Append:

```markdown
## Alerts (optional)

Drop a `/root/hysteria/alerts.json` (chmod 600) to enable Telegram / webhook alerts:

\`\`\`json
{
  "telegram": {"bot_token": "...", "chat_id": "..."},
  "webhook":  {"url": "https://example.com/hook", "secret": "optional-hmac-key"},
  "anomaly_z_threshold": 3.0,
  "anomaly_min_bytes": 1073741824
}
\`\`\`

- 80% / 100% quota crossings → one push per user per billing month
- Daily total > z-score threshold vs. trailing 7-day mean → one push per user per day
- Webhook payloads are HMAC-SHA256 signed via `X-Hy2-Signature` when `secret` is set

If the file is absent, the dispatcher is a no-op. Live infra heartbeat is at `/admin/health`.
```

- [ ] **Step 10.5: Commit**

```bash
git add deploy.sh README.md README.zh-CN.md
git commit -m "docs: alerts.json setup + deploy renders alerts/anomaly modules"
```

---

## Task 11: Final integration smoke + manual verification checklist

**Files:**
- (no new files; this is an in-session verification gate)

- [ ] **Step 11.1: Run the entire suite**

```bash
python -m pytest -q
```

Expected: all green, 0 failures.

- [ ] **Step 11.2: Verify nothing imports `display.DISPLAY_MULTIPLIER` outside the alert/limiter scope**

```bash
python -c "import ast, pathlib
for p in pathlib.Path('hysteria').glob('*.py'):
    src = p.read_text(encoding='utf-8')
    if 'DISPLAY_MULTIPLIER' in src:
        print(p.name, '✓')"
```

Expected: lists exactly `traffic_limiter.py`, `subscription_service.py`. Nothing else.

- [ ] **Step 11.3: Confirm `/admin/health` is auth-gated**

Inspect `handle_get` for the route block; the first line inside must be `if not is_logged_in(self): self.redirect('/login'); return`. (Already added in Task 9.6 — this is a paranoia check.)

- [ ] **Step 11.4: Confirm `alerts.dispatch` cannot raise**

```bash
python -m pytest tests/test_alerts.py::test_dispatch_swallows_transport_errors -v
```

Expected: PASS.

- [ ] **Step 11.5: Manual deploy verification (operator runs on the VPS)**

Document this in your PR description:

```
1. SSH to the VPS, write /root/hysteria/alerts.json with:
   { "webhook": {"url": "https://requestbin.com/...", "secret": "x"} }
2. chmod 600 /root/hysteria/alerts.json
3. Pick a guest user with quota < (current usage / 0.8); wait one cron tick (≤60s)
4. Confirm the requestbin sees a POST with quota_80 payload + X-Hy2-Signature header
5. Open /admin in browser; confirm sparkline column shows bars
6. Open /admin/health; stop xray (`systemctl stop xray`); confirm card flips red within 30s
7. Restore xray (`systemctl start xray`)
```

- [ ] **Step 11.6: Final commit if any tweaks landed**

```bash
git status
git log --oneline -15
```

Expected: clean tree, ~10 commits over Tasks 1-10.

---

## Self-review checklist

- [x] Spec §3.1 sparkline → Tasks 7+8
- [x] Spec §3.2 alerts module (config, state, dispatch, HMAC) → Tasks 3+4+5
- [x] Spec §3.3 health page (6 probes) → Task 9
- [x] Spec §3.4 anomaly detection (z-score, min_bytes, zero-stdev) → Task 2
- [x] Spec §4 data flow (limiter → check_alerts → dispatch) → Task 6
- [x] Spec §5 file map → matches plan File map
- [x] Spec §6 error handling (missing config, transport failure, corrupt state, probe exception) → covered by tests in Tasks 3, 5, 9 and `try/except` wrap in Task 6
- [x] Spec §7 security (file mode 600, HMAC, no injection in subprocess) → see Task 5 HMAC, Task 9 fixed argv subprocess calls
- [x] Spec §8 testing strategy → unit + integration tests in Tasks 2, 3, 5, 6, 7, 9; manual verification in Task 11
