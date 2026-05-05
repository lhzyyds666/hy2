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
    assert 'bob' in msg and '耗尽' in msg and '15.5 GB' in msg and '2026-05' in msg


def test_format_anomaly():
    msg = alerts.format_message({
        'kind': 'anomaly', 'user': 'carol',
        'details': {'today_human': '40.0 GB', 'mean_human': '5.0 GB',
                    'z': 7.3},
    })
    assert 'carol' in msg and '40.0 GB' in msg and 'z=7.3' in msg


def test_format_unknown_kind_does_not_raise():
    msg = alerts.format_message({'kind': 'mystery', 'user': 'x'})
    assert isinstance(msg, str) and 'x' in msg and 'mystery' in msg


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
