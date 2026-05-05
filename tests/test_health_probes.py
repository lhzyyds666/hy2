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
