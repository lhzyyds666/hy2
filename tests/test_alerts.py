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
