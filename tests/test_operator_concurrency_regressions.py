"""Concurrency and unlimited-device regressions for operator forms."""

from contextlib import contextmanager
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from http.server import ThreadingHTTPServer
import hashlib
import http.client
import json
from urllib.parse import urlencode
from zoneinfo import ZoneInfo

import pytest

import subscription_service as ss


NOW = datetime(2026, 7, 18, 12, tzinfo=ZoneInfo("Asia/Shanghai"))


@contextmanager
def _running_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), ss.Handler)
    thread = __import__("threading").Thread(
        target=server.serve_forever,
        daemon=True,
    )
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def _write_json(path, value):
    path.write_text(json.dumps(value), encoding="utf-8")


def _seed(tmp_path, monkeypatch, users):
    paths = {}
    payloads = {
        "USERS_FILE": users,
        "USAGE_FILE": {},
        "USAGE_DAILY_FILE": {},
        "USAGE_HOURLY_FILE": {},
        "USAGE_PRESERVED_FILE": {},
        "ONLINE_FILE": {},
        "DEVICE_ADMISSIONS_FILE": {},
        "META_FILE": {
            "admin_user": "admin",
            "admin_pass_hash": "unused",
            "admin_token": "admin-token",
            "settlement_day": 1,
            "cycle_length_days": 30,
            "cycle_anchor_date": "2026-07-01",
        },
        "SESSIONS_FILE": {},
        "USER_SESSIONS_FILE": {},
    }
    for name, payload in payloads.items():
        path = tmp_path / f"{name.lower()}.json"
        _write_json(path, payload)
        monkeypatch.setattr(ss, name, path)
        paths[name] = path
    template = tmp_path / "template.yaml"
    template.write_text(
        "proxies: []\n"
        "proxy-groups: []\n"
        "rules:\n"
        "  - DOMAIN,first.example,DIRECT\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(ss, "TEMPLATE_FILE", template)
    monkeypatch.setattr(
        ss,
        "TEMPLATE_VERSIONS_FILE",
        tmp_path / "template_versions.json",
    )
    monkeypatch.setattr(ss, "USAGE_LOCK_FILE", tmp_path / "usage.lock")
    monkeypatch.setattr(ss, "TEMPLATE_LOCK_FILE", tmp_path / "template.lock")
    monkeypatch.setattr(ss, "local_now", lambda: NOW)
    monkeypatch.setattr(ss, "is_logged_in", lambda _handler: True)
    monkeypatch.setattr(
        ss,
        "_sync_static_access_from_users",
        lambda _users, **_kwargs: (False, False),
    )
    return paths, template


def _post(server, path, form):
    connection = http.client.HTTPConnection(
        "127.0.0.1",
        server.server_port,
        timeout=3,
    )
    connection.request(
        "POST",
        path,
        body=urlencode(form),
        headers={
            "Host": "panel.test",
            "Content-Type": "application/x-www-form-urlencoded",
            "Sec-Fetch-Site": "same-origin",
        },
    )
    response = connection.getresponse()
    body = response.read().decode("utf-8")
    result = (
        response.status,
        dict(response.getheaders()),
        body,
    )
    connection.close()
    return result


def _edit_form(cfg, **overrides):
    form = {
        "user": "alice",
        "user_revision": ss.user_config_revision(cfg),
        "max_devices": str(cfg.get("max_devices", 2)),
        "quota_gb": "1",
        "quota_extra_gb": "0",
        "note": str(cfg.get("note") or ""),
    }
    form.update(overrides)
    return form


def test_zero_device_limit_round_trips_as_unlimited(
    tmp_path,
    monkeypatch,
):
    cfg = {
        "sub_token": "token",
        "monthly_quota_bytes": 1 << 30,
        "quota_extra_bytes": 0,
        "max_devices": 0,
    }
    paths, _template = _seed(
        tmp_path,
        monkeypatch,
        {"alice": cfg},
    )

    with _running_server() as server:
        status, headers, _body = _post(
            server,
            "/admin/update",
            _edit_form(cfg, max_devices="0"),
        )

    assert status == 302
    assert headers["Location"] == "/admin?msg=updated+alice"
    saved = json.loads(paths["USERS_FILE"].read_text())["alice"]
    assert saved["max_devices"] == 0

    monkeypatch.setattr(
        ss,
        "scaled_usage_for_user",
        lambda *_args, **_kwargs: (0, 0, 0),
    )
    row = ss.row_form(
        "alice",
        saved,
        {},
        "panel.test",
        "https://panel.test",
    )
    assert 'data-max-devices="0"' in row
    assert "不限设备" in row
    panel = ss.render_user_panel(
        "panel.test",
        "https://panel.test",
        "alice",
        "token",
        saved,
    )
    assert "设备不限" in panel
    assert "/ 0" not in panel


def test_out_of_range_device_limit_is_rejected_without_clamping(
    tmp_path,
    monkeypatch,
):
    cfg = {
        "sub_token": "token",
        "monthly_quota_bytes": 1 << 30,
        "max_devices": 7,
    }
    paths, _template = _seed(tmp_path, monkeypatch, {"alice": cfg})

    with _running_server() as server:
        status, _headers, body = _post(
            server,
            "/admin/update",
            _edit_form(cfg, max_devices="101"),
        )

    assert status == 422
    assert "0–100" in body
    saved = json.loads(paths["USERS_FILE"].read_text())["alice"]
    assert saved["max_devices"] == 7


def test_stale_user_edit_returns_409_and_preserves_both_states(
    tmp_path,
    monkeypatch,
):
    opened = {
        "sub_token": "token",
        "monthly_quota_bytes": 1 << 30,
        "max_devices": 2,
        "note": "opened value",
    }
    paths, _template = _seed(
        tmp_path,
        monkeypatch,
        {"alice": opened},
    )
    concurrent = dict(opened)
    concurrent["monthly_quota_bytes"] = 9 << 30
    concurrent["note"] = "newer value"
    _write_json(paths["USERS_FILE"], {"alice": concurrent})

    with _running_server() as server:
        status, _headers, body = _post(
            server,
            "/admin/update",
            _edit_form(
                opened,
                quota_gb="1",
                note="my unsaved note",
            ),
        )

    assert status == 409
    assert "未保存的非敏感草稿" in body
    assert "my unsaved note" in body
    saved = json.loads(paths["USERS_FILE"].read_text())["alice"]
    assert saved == concurrent


def test_stale_disable_form_cannot_reverse_a_newer_disabled_state(
    tmp_path,
    monkeypatch,
):
    opened = {
        "sub_token": "token",
        "monthly_quota_bytes": 1 << 30,
        "max_devices": 2,
        "disabled": False,
    }
    paths, _template = _seed(
        tmp_path,
        monkeypatch,
        {"alice": opened},
    )
    concurrent = dict(opened)
    concurrent["disabled"] = True
    _write_json(paths["USERS_FILE"], {"alice": concurrent})
    old_revision = ss.user_config_revision(opened)

    with _running_server() as server:
        status, _headers, body = _post(
            server,
            (
                "/admin/toggle-user"
                f"?revision={old_revision}&desired=disabled"
            ),
            {"user": "alice"},
        )

    assert status == 409
    assert "本次操作没有执行" in body
    saved = json.loads(paths["USERS_FILE"].read_text())["alice"]
    assert saved["disabled"] is True


def test_stale_template_save_keeps_new_file_and_old_draft(
    tmp_path,
    monkeypatch,
):
    paths, template = _seed(tmp_path, monkeypatch, {})
    del paths
    opened_revision = hashlib.sha256(template.read_bytes()).hexdigest()
    template.write_text(
        "proxies: []\n"
        "proxy-groups: []\n"
        "rules:\n"
        "  - DOMAIN,newer.example,DIRECT\n",
        encoding="utf-8",
    )
    newer = template.read_text(encoding="utf-8")
    draft = json.dumps(
        {
            "proxies": [],
            "proxy-groups": [],
            "rules": ["DOMAIN,my-draft.example,DIRECT"],
        },
        ensure_ascii=False,
    )

    with _running_server() as server:
        status, _headers, body = _post(
            server,
            "/admin/config/save",
            {
                "template_revision": opened_revision,
                "config_json": draft,
            },
        )

    assert status == 409
    assert "my-draft.example" in body
    assert "本次保存未覆盖新版本" in body
    assert template.read_text(encoding="utf-8") == newer


def test_stale_rule_index_never_deletes_the_rule_now_at_that_index(
    tmp_path,
    monkeypatch,
):
    _paths, template = _seed(tmp_path, monkeypatch, {})
    opened_revision = hashlib.sha256(template.read_bytes()).hexdigest()
    ss.add_template_rule("DOMAIN,newer.example,REJECT")

    with pytest.raises(ss.TemplateConflictError):
        ss.delete_template_rule(
            0,
            expected_revision=opened_revision,
            expected_rule="DOMAIN,first.example,DIRECT",
        )

    assert ss.load_template_rules() == [
        "DOMAIN,newer.example,REJECT",
        "DOMAIN,first.example,DIRECT",
    ]


def test_rule_compare_and_swap_accepts_unicode_rule_values(
    tmp_path,
    monkeypatch,
):
    _paths, template = _seed(tmp_path, monkeypatch, {})
    template.write_text(
        "proxies: []\n"
        "proxy-groups: []\n"
        "rules:\n"
        "  - DOMAIN,unicode.example,🚀 节点选择\n",
        encoding="utf-8",
    )
    revision = hashlib.sha256(template.read_bytes()).hexdigest()

    assert ss.delete_template_rule(
        0,
        expected_revision=revision,
        expected_rule="DOMAIN,unicode.example,🚀 节点选择",
    )
    assert ss.load_template_rules() == []


def test_user_pin_racing_common_update_always_references_complete_snapshot(
    tmp_path,
    monkeypatch,
):
    paths, _template = _seed(
        tmp_path,
        monkeypatch,
        {
            "alice": {
                "sub_token": "token",
                "monthly_quota_bytes": 1 << 30,
                "max_devices": 2,
            },
        },
    )
    updated = {
        "proxies": [],
        "proxy-groups": [],
        "rules": ["DOMAIN,updated.example,DIRECT"],
    }

    with ThreadPoolExecutor(max_workers=2) as pool:
        pin_future = pool.submit(ss.set_user_template_mode, "alice", "pin")
        update_future = pool.submit(ss.replace_template_config, updated)
        assert pin_future.result(timeout=3) is True
        update_future.result(timeout=3)

    user = json.loads(paths["USERS_FILE"].read_text(encoding="utf-8"))["alice"]
    revision = user[ss.USER_TEMPLATE_REVISION_KEY]
    snapshots = json.loads(
        ss.TEMPLATE_VERSIONS_FILE.read_text(encoding="utf-8"),
    )
    snapshot_text = snapshots["templates"][revision]["yaml"]
    assert hashlib.sha256(snapshot_text.encode("utf-8")).hexdigest() == revision
    assert (
        "first.example" in snapshot_text
        or "updated.example" in snapshot_text
    )
