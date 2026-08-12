"""Focused regressions for account lifecycle and authorization safety.

Every runtime path is redirected into ``tmp_path``. Generated proxy config
writes, reloads, service stops, and kicks are mocked so this suite can never
touch host services.
"""

from contextlib import contextmanager
from datetime import datetime
import html
import http.client
from http.server import ThreadingHTTPServer
import json
from pathlib import Path
from types import SimpleNamespace
import threading
import time
from urllib.parse import urlencode
import uuid

import pytest

import state_store
import subscription_service as ss


@contextmanager
def _running_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), ss.Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def _request(server, method, path, *, form=None, headers=None):
    body = urlencode(form or {}) if form is not None else None
    request_headers = {"Host": "panel.test"}
    request_headers.update(headers or {})
    if body is not None:
        request_headers.setdefault(
            "Origin",
            "http://panel.test",
        )
        request_headers.setdefault(
            "Content-Type",
            "application/x-www-form-urlencoded",
        )
        request_headers.setdefault(
            "Content-Length",
            str(len(body.encode("utf-8"))),
        )
    conn = http.client.HTTPConnection(
        "127.0.0.1",
        server.server_port,
        timeout=5,
    )
    conn.request(method, path, body=body, headers=request_headers)
    response = conn.getresponse()
    payload = response.read()
    result = SimpleNamespace(
        status=response.status,
        headers={
            key.lower(): value for key, value in response.getheaders()
        },
        body=payload,
    )
    conn.close()
    return result


def _write_json(path, value):
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(value), encoding="utf-8")


def _write_valid_template(path, domain):
    Path(path).write_text(
        json.dumps({
            "proxies": [
                {
                    "name": "test-node",
                    "type": "socks5",
                    "server": "127.0.0.1",
                    "port": 1080,
                },
            ],
            "proxy-groups": [
                {
                    "name": ss.NODE_GROUP,
                    "type": "select",
                    "proxies": ["test-node", "DIRECT"],
                },
            ],
            "rules": [f"DOMAIN,{domain},DIRECT", "MATCH,DIRECT"],
        }),
        encoding="utf-8",
    )


def _configure_state(tmp_path, monkeypatch, *, users=None):
    paths = {
        "USERS_FILE": tmp_path / "users.json",
        "META_FILE": tmp_path / "subscription_meta.json",
        "SESSIONS_FILE": tmp_path / "panel_sessions.json",
        "USER_SESSIONS_FILE": tmp_path / "user_panel_sessions.json",
        "USAGE_FILE": tmp_path / "usage.json",
        "USAGE_DAILY_FILE": tmp_path / "usage_daily.json",
        "USAGE_HOURLY_FILE": tmp_path / "usage_hourly.json",
        "USAGE_PRESERVED_FILE": tmp_path / "usage_preserved.json",
        "ONLINE_FILE": tmp_path / "online.json",
        "DEVICE_ADMISSIONS_FILE": tmp_path / "device_admissions.json",
        "RESET_LOG_FILE": tmp_path / "usage_reset.log",
        "USAGE_LOCK_FILE": tmp_path / "usage.lock",
        "TEMPLATE_FILE": tmp_path / "template.yaml",
        "TEMPLATE_LOCK_FILE": tmp_path / "template.lock",
        "TEMPLATE_VERSIONS_FILE": (
            tmp_path / "template_versions.json"
        ),
        "DISPLAY_MULTIPLIER_STATE_FILE": (
            tmp_path / "display_multiplier.json"
        ),
    }
    for name, path in paths.items():
        monkeypatch.setattr(ss, name, path)
    alert_state = tmp_path / "alert_state.json"
    monkeypatch.setattr(ss.alerts, "STATE_FILE", alert_state)
    paths["ALERT_STATE_FILE"] = alert_state

    _write_json(
        paths["META_FILE"],
        {
            "admin_user": "admin",
            "admin_pass_hash": "unused-but-present",
            "admin_token": "admin-token",
            "settlement_day": 1,
            "cycle_length_days": 30,
            "cycle_anchor_date": "2026-01-01",
        },
    )
    _write_json(paths["USERS_FILE"], users or {})
    for name in (
        "SESSIONS_FILE",
        "USER_SESSIONS_FILE",
        "USAGE_FILE",
        "USAGE_DAILY_FILE",
        "USAGE_HOURLY_FILE",
        "USAGE_PRESERVED_FILE",
        "ONLINE_FILE",
        "DEVICE_ADMISSIONS_FILE",
        "ALERT_STATE_FILE",
    ):
        _write_json(paths[name], {})
    return paths


def _forbid_generated_proxy_io(monkeypatch):
    def forbidden(*_args, **_kwargs):
        pytest.fail("test attempted generated proxy/systemd I/O")

    monkeypatch.setattr(ss.xray_config, "reload_async", forbidden)
    monkeypatch.setattr(ss.tuic_config, "reload_async", forbidden)
    monkeypatch.setattr(ss.xray_config, "apply_user_plan", forbidden)
    monkeypatch.setattr(ss.tuic_config, "sync_user_plan", forbidden)
    monkeypatch.setattr(ss.static_access, "recover_if_pending", forbidden)


def _seed_token_session(state, *, user="alice", token="old-token", sid="old-session"):
    _write_json(
        state["USER_SESSIONS_FILE"],
        {
            sid: {
                "user": user,
                "exp": int(time.time()) + 3600,
                "credential_kind": ss.USER_SESSION_SUBSCRIPTION_TOKEN,
                "credential_generation": ss._credential_generation(token),
            },
        },
    )
    return sid


def _user_revision(state, user="alice"):
    users = json.loads(state["USERS_FILE"].read_text(encoding="utf-8"))
    return ss.user_config_revision(users[user])


def _service_stop_result(service, *, ok):
    return ss.static_access.ServiceActionResult(
        service=service,
        action="stop_fail_closed",
        attempted=True,
        ok=ok,
        effect_confirmed=ok,
        marker_persisted=True,
        code="stopped" if ok else "nonzero_exit",
        retryable=not ok,
    )


def _make_only_revocation_due(path):
    tasks = json.loads(Path(path).read_text(encoding="utf-8"))
    assert len(tasks) == 1
    task_id = next(iter(tasks))
    assert ss.revocation_queue.release_claim(
        path,
        task_id,
        delay=1,
        now=int(time.time()) - 2,
    )
    return task_id


def test_reset_audit_log_is_restricted_even_when_upgrading_old_file(
    tmp_path, monkeypatch
):
    state = _configure_state(tmp_path, monkeypatch)
    state["RESET_LOG_FILE"].write_text("legacy\n", encoding="utf-8")
    state["RESET_LOG_FILE"].chmod(0o644)
    handler = object.__new__(ss.Handler)
    handler.client_address = ("127.0.0.1", 12345)
    handler.headers = {}

    handler.write_reset_log(
        "admin",
        "reset_usage_user",
        "alice",
        10,
        0,
    )

    assert state["RESET_LOG_FILE"].stat().st_mode & 0o777 == 0o600


def test_token_panel_get_exchanges_query_for_revocable_clean_session(
    tmp_path, monkeypatch
):
    state = _configure_state(
        tmp_path,
        monkeypatch,
        users={
            "alice": {
                "sub_token": "secret-token",
                "vless_uuid": (
                    "11111111-1111-4111-8111-111111111111"
                ),
                "monthly_quota_bytes": 1024,
                "max_devices": 2,
                "panel_password_must_change": True,
            },
        },
    )

    with _running_server() as server:
        exchanged = _request(
            server,
            "GET",
            "/panel/alice?token=secret-token",
            headers={
                "X-Forwarded-Proto": "https",
                "X-Forwarded-Port": "443",
            },
        )
        assert exchanged.status == 303
        assert exchanged.headers["location"] == "/user/panel"
        assert "secret-token" not in exchanged.headers["location"]
        cookie = exchanged.headers["set-cookie"]
        assert cookie.startswith("usid=")
        assert "; Secure" in cookie
        sid = cookie.split("usid=", 1)[1].split(";", 1)[0]

        clean = _request(
            server,
            "GET",
            "/user/panel",
            headers={"Cookie": f"usid={sid}"},
        )
        change_password = _request(
            server,
            "GET",
            "/user/change-password",
            headers={"Cookie": f"usid={sid}"},
        )

    session = json.loads(
        state["USER_SESSIONS_FILE"].read_text(encoding="utf-8")
    )[sid]
    assert session["credential_kind"] == (
        ss.USER_SESSION_SUBSCRIPTION_TOKEN
    )
    assert session["credential_generation"] == ss._credential_generation(
        "secret-token"
    )
    assert clean.status == 200
    assert "当前会话地址".encode("utf-8") in clean.body
    assert "修改密码".encode("utf-8") not in clean.body
    assert "退出登录".encode("utf-8") in clean.body
    assert change_password.status == 302
    assert change_password.headers["location"] == "/user/login"


def test_admin_bearer_get_exchanges_to_clean_password_bound_session(
    tmp_path, monkeypatch
):
    state = _configure_state(tmp_path, monkeypatch)

    with _running_server() as server:
        exchanged = _request(
            server,
            "GET",
            "/admin?msg=hello&token=admin-token&range=day",
            headers={
                "X-Forwarded-Proto": "https",
                "X-Forwarded-Port": "443",
            },
        )
        assert exchanged.status == 303
        assert exchanged.headers["location"] == (
            "/admin?msg=hello&range=day"
        )
        assert "admin-token" not in exchanged.headers["location"]
        cookie = exchanged.headers["set-cookie"]
        assert cookie.startswith("sid=")
        assert "; Secure" in cookie
        sid = cookie.split("sid=", 1)[1].split(";", 1)[0]

        clean = _request(
            server,
            "GET",
            "/logout",
            headers={"Cookie": f"sid={sid}"},
        )

    session = json.loads(
        state["SESSIONS_FILE"].read_text(encoding="utf-8")
    )[sid]
    assert session["credential_generation"] == ss._credential_generation(
        "unused-but-present"
    )
    assert clean.status == 200


def test_rotated_token_revokes_exchanged_panel_session(
    tmp_path, monkeypatch
):
    state = _configure_state(
        tmp_path,
        monkeypatch,
        users={
            "alice": {
                "sub_token": "old-token",
                "vless_uuid": (
                    "11111111-1111-4111-8111-111111111111"
                ),
                "monthly_quota_bytes": 1024,
                "max_devices": 2,
            },
        },
    )

    with _running_server() as server:
        exchanged = _request(
            server, "GET", "/panel/alice?token=old-token",
        )
        cookie = exchanged.headers["set-cookie"]
        sid = cookie.split("usid=", 1)[1].split(";", 1)[0]
        users = json.loads(
            state["USERS_FILE"].read_text(encoding="utf-8")
        )
        users["alice"]["sub_token"] = "new-token"
        _write_json(state["USERS_FILE"], users)

        stale = _request(
            server,
            "GET",
            "/user/panel",
            headers={"Cookie": f"usid={sid}"},
        )

    assert stale.status == 302
    assert stale.headers["location"] == "/user/login"
    assert sid not in json.loads(
        state["USER_SESSIONS_FILE"].read_text(encoding="utf-8")
    )


def test_head_token_panel_does_not_create_session(
    tmp_path, monkeypatch
):
    state = _configure_state(
        tmp_path,
        monkeypatch,
        users={
            "alice": {
                "sub_token": "secret-token",
                "monthly_quota_bytes": 1024,
                "max_devices": 2,
            },
        },
    )

    with _running_server() as server:
        response = _request(
            server, "HEAD", "/panel/alice?token=secret-token",
        )

    assert response.status == 200
    assert "set-cookie" not in response.headers
    assert json.loads(
        state["USER_SESSIONS_FILE"].read_text(encoding="utf-8")
    ) == {}


def test_token_session_is_not_blocked_by_password_change_gate(
    tmp_path, monkeypatch
):
    _configure_state(
        tmp_path,
        monkeypatch,
        users={
            "alice": {
                "sub_token": "secret-token",
                "panel_password_must_change": True,
                "monthly_quota_bytes": 1024,
                "max_devices": 2,
            },
        },
    )

    with _running_server() as server:
        exchanged = _request(
            server, "GET", "/panel/alice?token=secret-token",
        )
        sid = (
            exchanged.headers["set-cookie"]
            .split("usid=", 1)[1]
            .split(";", 1)[0]
        )
        payload = _request(
            server,
            "GET",
            "/user/panel.json",
            headers={"Cookie": f"usid={sid}"},
        )

    assert exchanged.status == 303
    assert payload.status == 200
    assert json.loads(payload.body)["total_bytes"] == 1024


def test_user_rule_pack_post_is_scoped_to_authenticated_user(
    tmp_path, monkeypatch,
):
    state = _configure_state(
        tmp_path,
        monkeypatch,
        users={
            "alice": {
                "sub_token": "alice-token",
                "monthly_quota_bytes": 1024,
                "max_devices": 2,
            },
            "bob": {
                "sub_token": "bob-token",
                "monthly_quota_bytes": 1024,
                "max_devices": 2,
            },
        },
    )
    sid = _seed_token_session(
        state, user="alice", token="alice-token", sid="alice-session",
    )

    with _running_server() as server:
        response = _request(
            server,
            "POST",
            "/user/rule-pack/apply",
            form={"pack": "overleaf", "user": "bob"},
            headers={"Cookie": f"usid={sid}"},
        )

    users = json.loads(state["USERS_FILE"].read_text(encoding="utf-8"))
    assert response.status == 302
    assert response.headers["location"] == (
        "/user/panel?msg=rule_pack_applied"
    )
    assert any("overleaf.com" in rule for rule in users["alice"]["clash_rules"])
    assert "clash_rules" not in users["bob"]


def test_user_rule_pack_post_requires_an_active_user_session(
    tmp_path, monkeypatch,
):
    state = _configure_state(
        tmp_path,
        monkeypatch,
        users={
            "alice": {
                "sub_token": "alice-token",
                "monthly_quota_bytes": 1024,
                "max_devices": 2,
                "disabled": True,
            },
        },
    )
    sid = _seed_token_session(
        state, user="alice", token="alice-token", sid="alice-session",
    )

    with _running_server() as server:
        inactive = _request(
            server,
            "POST",
            "/user/rule-pack/apply",
            form={"pack": "easyconnect"},
            headers={"Cookie": f"usid={sid}"},
        )
        logged_out = _request(
            server,
            "POST",
            "/user/rule-pack/apply",
            form={"pack": "easyconnect"},
        )

    user = json.loads(state["USERS_FILE"].read_text(encoding="utf-8"))["alice"]
    assert inactive.status == 302
    assert inactive.headers["location"] == "/user/panel"
    assert logged_out.status == 302
    assert logged_out.headers["location"] == "/user/login"
    assert "clash_rules" not in user


def test_user_template_choice_is_session_scoped_and_merge_preserves_rules(
    tmp_path, monkeypatch,
):
    state = _configure_state(
        tmp_path,
        monkeypatch,
        users={
            "alice": {
                "sub_token": "alice-token",
                "monthly_quota_bytes": 1024,
                "max_devices": 2,
                "clash_rules": ["DOMAIN,my-rule.example,DIRECT"],
            },
            "bob": {
                "sub_token": "bob-token",
                "monthly_quota_bytes": 1024,
                "max_devices": 2,
            },
        },
    )
    _write_valid_template(state["TEMPLATE_FILE"], "old-common.example")
    sid = _seed_token_session(
        state, user="alice", token="alice-token", sid="alice-session",
    )

    with _running_server() as server:
        pinned = _request(
            server,
            "POST",
            "/user/template-mode",
            form={"action": "pin", "user": "bob"},
            headers={"Cookie": f"usid={sid}"},
        )
        users = json.loads(state["USERS_FILE"].read_text(encoding="utf-8"))
        old_revision = users["alice"][ss.USER_TEMPLATE_REVISION_KEY]
        _write_valid_template(state["TEMPLATE_FILE"], "new-common.example")
        before_merge = _request(
            server,
            "GET",
            "/sub/alice?token=alice-token",
        )
        merged = _request(
            server,
            "POST",
            "/user/template-mode",
            form={"action": "merge"},
            headers={"Cookie": f"usid={sid}"},
        )
        after_merge = _request(
            server,
            "GET",
            "/sub/alice?token=alice-token",
        )

    users = json.loads(state["USERS_FILE"].read_text(encoding="utf-8"))
    assert pinned.status == 302
    assert pinned.headers["location"] == "/user/panel?msg=template_pinned"
    assert users["alice"][ss.USER_TEMPLATE_MODE_KEY] == ss.TEMPLATE_MODE_PINNED
    assert users["alice"][ss.USER_TEMPLATE_REVISION_KEY] != old_revision
    assert users["alice"]["clash_rules"] == [
        "DOMAIN,my-rule.example,DIRECT",
    ]
    assert ss.USER_TEMPLATE_MODE_KEY not in users["bob"]
    snapshots = json.loads(
        state["TEMPLATE_VERSIONS_FILE"].read_text(encoding="utf-8"),
    )
    assert old_revision in snapshots["templates"]
    assert len(snapshots["templates"]) == 2

    assert before_merge.status == 200
    assert before_merge.headers["x-subscription-template-mode"] == "pinned"
    assert before_merge.headers["x-subscription-template-revision"] == old_revision
    assert b"old-common.example" in before_merge.body
    assert b"new-common.example" not in before_merge.body
    assert b"my-rule.example" in before_merge.body
    assert merged.status == 302
    assert merged.headers["location"] == "/user/panel?msg=template_merged"
    assert after_merge.status == 200
    assert after_merge.headers["x-subscription-template-mode"] == "pinned"
    assert b"new-common.example" in after_merge.body
    assert b"old-common.example" not in after_merge.body
    assert b"my-rule.example" in after_merge.body


def test_user_template_choice_requires_an_active_session(tmp_path, monkeypatch):
    state = _configure_state(
        tmp_path,
        monkeypatch,
        users={
            "alice": {
                "sub_token": "alice-token",
                "monthly_quota_bytes": 1024,
                "max_devices": 2,
                "disabled": True,
            },
        },
    )
    _write_valid_template(state["TEMPLATE_FILE"], "common.example")
    sid = _seed_token_session(
        state, user="alice", token="alice-token", sid="alice-session",
    )

    with _running_server() as server:
        inactive = _request(
            server,
            "POST",
            "/user/template-mode",
            form={"action": "pin"},
            headers={"Cookie": f"usid={sid}"},
        )
        logged_out = _request(
            server,
            "POST",
            "/user/template-mode",
            form={"action": "pin"},
        )

    user = json.loads(state["USERS_FILE"].read_text(encoding="utf-8"))["alice"]
    assert inactive.status == 302
    assert inactive.headers["location"] == "/user/panel"
    assert logged_out.status == 302
    assert logged_out.headers["location"] == "/user/login"
    assert ss.USER_TEMPLATE_MODE_KEY not in user
    assert not state["TEMPLATE_VERSIONS_FILE"].exists()


def test_subscription_fails_closed_when_pinned_snapshot_is_missing(
    tmp_path, monkeypatch,
):
    state = _configure_state(
        tmp_path,
        monkeypatch,
        users={
            "alice": {
                "sub_token": "alice-token",
                "monthly_quota_bytes": 1024,
                "max_devices": 2,
                ss.USER_TEMPLATE_MODE_KEY: ss.TEMPLATE_MODE_PINNED,
                ss.USER_TEMPLATE_REVISION_KEY: "a" * 64,
            },
        },
    )
    _write_valid_template(state["TEMPLATE_FILE"], "must-not-leak.example")

    with _running_server() as server:
        response = _request(
            server,
            "GET",
            "/sub/alice?token=alice-token",
        )

    assert response.status == 503
    assert "固定模板版本暂不可用".encode("utf-8") in response.body
    assert b"must-not-leak.example" not in response.body


@pytest.mark.parametrize(
    ("inactive_fields", "expected_error", "expected_message"),
    [
        (
            {"disabled": True},
            "disabled",
            "账号已停用，请联系管理员",
        ),
        (
            {"expires_at": "2020-01-01"},
            "expired",
            "账号已到期，请联系管理员续费",
        ),
    ],
)
def test_inactive_password_session_gets_safe_status_page_and_no_live_data(
    tmp_path,
    monkeypatch,
    inactive_fields,
    expected_error,
    expected_message,
):
    panel_hash = "current-panel-hash"
    cfg = {
        "sub_token": "never-render-this-token",
        "panel_pass_hash": panel_hash,
        "monthly_quota_bytes": 1024,
        "max_devices": 2,
        **inactive_fields,
    }
    _configure_state(
        tmp_path,
        monkeypatch,
        users={"alice": cfg},
    )
    sid = ss.create_user_session(
        "alice",
        ss._credential_generation(panel_hash),
        ss.USER_SESSION_PANEL_PASSWORD,
    )

    with _running_server() as server:
        panel = _request(
            server,
            "GET",
            "/user/panel",
            headers={"Cookie": f"usid={sid}"},
        )
        payload = _request(
            server,
            "GET",
            "/user/panel.json",
            headers={"Cookie": f"usid={sid}"},
        )
        password_page = _request(
            server,
            "GET",
            "/user/change-password",
            headers={"Cookie": f"usid={sid}"},
        )

    assert panel.status == 403
    assert expected_message.encode("utf-8") in panel.body
    assert b"never-render-this-token" not in panel.body
    assert b"var pollUrl" not in panel.body
    assert 'href="/user/change-password"'.encode() not in panel.body
    assert "退出登录".encode("utf-8") in panel.body
    assert payload.status == 403
    assert json.loads(payload.body) == {"error": expected_error}
    assert password_page.status == 302
    assert password_page.headers["location"] == "/user/panel"


@pytest.mark.parametrize(
    ("draft", "expected_message"),
    [
        ("   ", "配置内容不能为空"),
        (
            '{"proxies": ["keep & <draft>"],',
            "JSON 格式错误，请检查语法",
        ),
        (
            '{"proxies": {"must": "stay"}}',
            "模板结构无效",
        ),
    ],
)
def test_config_validation_error_preserves_submitted_draft(
    tmp_path, monkeypatch, draft, expected_message
):
    _configure_state(tmp_path, monkeypatch)
    monkeypatch.setattr(ss, "TEMPLATE_FILE", tmp_path / "config.yaml")
    monkeypatch.setattr(
        ss,
        "TEMPLATE_LOCK_FILE",
        tmp_path / "config.yaml.lock",
    )

    with _running_server() as server:
        response = _request(
            server,
            "POST",
            "/admin/config/save?token=admin-token",
            form={"config_json": draft},
        )

    body = response.body.decode("utf-8")
    assert response.status == 422
    assert expected_message in body
    assert html.escape(draft) in body
    assert 'aria-invalid="true" autofocus' in body
    assert not (tmp_path / "config.yaml").exists()


def test_config_save_failure_keeps_valid_draft_for_retry(
    tmp_path, monkeypatch
):
    _configure_state(tmp_path, monkeypatch)
    draft = json.dumps(
        {
            "proxies": [
                {"name": "keep-this-draft", "type": "hysteria2"}
            ],
            "proxy-groups": [],
            "rules": [],
        },
        ensure_ascii=False,
        indent=2,
    )
    monkeypatch.setattr(
        ss,
        "replace_template_config",
        lambda _data, expected_revision=None: (_ for _ in ()).throw(
            state_store.StateStoreError("simulated disk failure")
        ),
    )

    with _running_server() as server:
        response = _request(
            server,
            "POST",
            "/admin/config/save?token=admin-token",
            form={"config_json": draft},
        )

    body = response.body.decode("utf-8")
    assert response.status == 503
    assert "服务器未修改模板" in body
    assert "keep-this-draft" in body
    assert html.escape(draft) in body
    assert 'aria-invalid="true" autofocus' in body


def test_add_existing_user_rejects_token_rotation_bypass(
    tmp_path, monkeypatch
):
    old_uuid = "11111111-1111-4111-8111-111111111111"
    new_uuid = uuid.UUID("22222222-2222-4222-8222-222222222222")
    state = _configure_state(
        tmp_path,
        monkeypatch,
        users={
            "alice": {
                "sub_token": "old-token",
                "vless_uuid": old_uuid,
                "max_devices": 9,
                "disabled": True,
                "panel_pass_hash": "hidden-panel-hash",
                "password_hash": "hidden-proxy-hash",
                "custom_extension": {
                    "routing_group": "private",
                    "flags": ["keep", "all"],
                },
                "profile_override": "low-latency",
                "clash_rules": ["DOMAIN,internal.example,DIRECT"],
                "fake_ip_filter": ["+.internal.example"],
                "tun_route_exclude_address": ["10.0.0.0/8"],
            },
        },
    )
    _forbid_generated_proxy_io(monkeypatch)
    monkeypatch.setattr(
        ss,
        "_sync_static_access_from_users",
        lambda _users, **_kwargs: (False, False),
    )
    monkeypatch.setattr(
        ss.secrets,
        "token_urlsafe",
        lambda _length: "rotated-token",
    )
    monkeypatch.setattr(ss.uuid, "uuid4", lambda: new_uuid)

    with _running_server() as server:
        response = _request(
            server,
            "POST",
            "/admin/add?token=admin-token",
            form={
                "user": "alice",
                "quota_gb": "42",
                "quota_extra_gb": "3",
                "reset_token": "on",
            },
        )

    assert response.status == 422
    assert "完整的连接撤销与审计流程" in response.body.decode("utf-8")
    cfg = json.loads(
        state["USERS_FILE"].read_text(encoding="utf-8")
    )["alice"]
    assert cfg["sub_token"] == "old-token"
    assert cfg["vless_uuid"] == old_uuid
    assert cfg["max_devices"] == 9
    assert cfg["disabled"] is True
    assert cfg["panel_pass_hash"] == "hidden-panel-hash"
    assert cfg["password_hash"] == "hidden-proxy-hash"
    assert cfg["custom_extension"] == {
        "routing_group": "private",
        "flags": ["keep", "all"],
    }
    assert cfg["profile_override"] == "low-latency"
    assert cfg["clash_rules"] == ["DOMAIN,internal.example,DIRECT"]
    assert cfg["fake_ip_filter"] == ["+.internal.example"]
    assert cfg["tun_route_exclude_address"] == ["10.0.0.0/8"]


@pytest.mark.parametrize("actor", ["self", "admin"])
def test_self_and_admin_rotation_invalidate_both_exported_credentials(
    tmp_path, monkeypatch, actor
):
    old_uuid = "11111111-1111-4111-8111-111111111111"
    new_uuid = uuid.UUID("33333333-3333-4333-8333-333333333333")
    state = _configure_state(
        tmp_path,
        monkeypatch,
        users={
            "alice": {
                "sub_token": "old-token",
                "vless_uuid": old_uuid,
                "monthly_quota_bytes": 1024,
                "max_devices": 2,
                "disabled": False,
            },
        },
    )
    _forbid_generated_proxy_io(monkeypatch)
    snapshots = []

    def capture_sync(users, **_kwargs):
        snapshots.append(json.loads(json.dumps(users)))
        return False, False

    monkeypatch.setattr(ss, "_sync_static_access_from_users", capture_sync)
    monkeypatch.setattr(
        ss.secrets,
        "token_urlsafe",
        lambda _length: "new-token",
    )
    monkeypatch.setattr(ss.uuid, "uuid4", lambda: new_uuid)
    kicked = []
    monkeypatch.setattr(
        ss,
        "hy_kick",
        lambda usernames: kicked.append(list(usernames)),
    )

    if actor == "self":
        old_sid = _seed_token_session(state)
        path = "/panel/alice/rotate-token"
        form = {
            "token": "old-token",
            "rotation_id": "rotation-request-id-00000001",
        }
        headers = {"Cookie": f"usid={old_sid}"}
    else:
        path = "/admin/rotate-token?token=admin-token"
        form = {
            "user": "alice",
            "user_revision": _user_revision(state),
        }
        headers = None

    with _running_server() as server:
        response = _request(
            server,
            "POST",
            path,
            form=form,
            headers=headers,
        )

    assert response.status == (303 if actor == "self" else 302)
    if actor == "self":
        assert response.headers["location"] == (
            "/user/panel?msg=token_rotated"
        )
        assert "new-token" not in response.headers["location"]
        assert response.headers["set-cookie"].startswith("usid=")
    cfg = json.loads(
        state["USERS_FILE"].read_text(encoding="utf-8")
    )["alice"]
    assert cfg["sub_token"] == "new-token"
    assert cfg["vless_uuid"] == str(new_uuid)
    assert cfg["sub_token"] != "old-token"
    assert cfg["vless_uuid"] != old_uuid
    assert snapshots[-1]["alice"]["sub_token"] == "new-token"
    assert snapshots[-1]["alice"]["vless_uuid"] == str(new_uuid)
    assert kicked == [["alice"]]


def test_self_rotation_delivers_new_token_in_clean_revocable_session(
    tmp_path, monkeypatch
):
    state = _configure_state(
        tmp_path,
        monkeypatch,
        users={
            "alice": {
                "sub_token": "old-token",
                "vless_uuid": (
                    "11111111-1111-4111-8111-111111111111"
                ),
                "monthly_quota_bytes": 1024,
                "max_devices": 2,
                "disabled": False,
            },
        },
    )
    old_sid = "old-token-session"
    _write_json(
        state["USER_SESSIONS_FILE"],
        {
            old_sid: {
                "user": "alice",
                "exp": int(time.time()) + 3600,
                "credential_kind": (
                    ss.USER_SESSION_SUBSCRIPTION_TOKEN
                ),
                "credential_generation": ss._credential_generation(
                    "old-token"
                ),
            },
        },
    )
    _forbid_generated_proxy_io(monkeypatch)
    monkeypatch.setattr(
        ss,
        "_sync_static_access_from_users",
        lambda _users, **_kwargs: (False, False),
    )

    def mint(length):
        return {
            18: "new-token",
            24: "new-session",
        }[length]

    monkeypatch.setattr(ss.secrets, "token_urlsafe", mint)
    monkeypatch.setattr(
        ss.uuid,
        "uuid4",
        lambda: uuid.UUID(
            "33333333-3333-4333-8333-333333333333"
        ),
    )
    kicked = []
    monkeypatch.setattr(
        ss,
        "hy_kick",
        lambda users: kicked.append(list(users)),
    )

    with _running_server() as server:
        rotated = _request(
            server,
            "POST",
            "/panel/alice/rotate-token",
            form={
                "token": "old-token",
                "rotation_id": "rotation-request-id-00000002",
            },
            headers={"Cookie": f"usid={old_sid}"},
        )
        stale = _request(
            server,
            "GET",
            "/user/panel",
            headers={"Cookie": f"usid={old_sid}"},
        )
        recovered = _request(
            server,
            "GET",
            rotated.headers["location"],
            headers={"Cookie": "usid=new-session"},
        )

    assert rotated.status == 303
    assert rotated.headers["location"] == (
        "/user/panel?msg=token_rotated"
    )
    assert "token=" not in rotated.headers["location"]
    assert rotated.headers["set-cookie"].startswith(
        "usid=new-session;"
    )
    sessions = json.loads(
        state["USER_SESSIONS_FILE"].read_text(encoding="utf-8")
    )
    assert old_sid not in sessions
    assert sessions["new-session"]["credential_kind"] == (
        ss.USER_SESSION_SUBSCRIPTION_TOKEN
    )
    assert sessions["new-session"]["credential_generation"] == (
        ss._credential_generation("new-token")
    )
    assert stale.status == 302
    assert stale.headers["location"] == "/user/login"
    assert recovered.status == 200
    assert "Token 已重置".encode("utf-8") in recovered.body
    assert b"new-token" in recovered.body
    assert b"old-token" not in recovered.body
    assert kicked == [["alice"]]


def test_self_rotation_survives_committed_static_sync_failure(
    tmp_path, monkeypatch
):
    state = _configure_state(
        tmp_path,
        monkeypatch,
        users={
            "alice": {
                "sub_token": "old-token",
                "vless_uuid": (
                    "11111111-1111-4111-8111-111111111111"
                ),
                "monthly_quota_bytes": 1024,
                "max_devices": 2,
                "disabled": False,
            },
        },
    )
    _forbid_generated_proxy_io(monkeypatch)
    monkeypatch.setattr(ss, "_using_live_core_state", lambda: True)
    monkeypatch.setattr(
        ss,
        "_sync_static_access_from_users",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            state_store.CriticalStateUnavailable(
                "simulated derived-state failure"
            )
        ),
    )

    def mint(length):
        return {
            18: "new-token",
            24: "new-session",
        }[length]

    monkeypatch.setattr(ss.secrets, "token_urlsafe", mint)
    monkeypatch.setattr(
        ss.uuid,
        "uuid4",
        lambda: uuid.UUID(
            "33333333-3333-4333-8333-333333333333"
        ),
    )
    stops = []
    monkeypatch.setattr(
        ss.static_access,
        "stop_fail_closed",
        lambda service, *, reason, live, **_kwargs: (
            stops.append((service, reason, live)) or True
        ),
    )
    kicked = []
    monkeypatch.setattr(
        ss,
        "hy_kick",
        lambda users: kicked.append(list(users)),
    )
    old_sid = _seed_token_session(state)

    with _running_server() as server:
        rotated = _request(
            server,
            "POST",
            "/panel/alice/rotate-token",
            form={
                "token": "old-token",
                "rotation_id": "rotation-request-id-00000003",
            },
            headers={"Cookie": f"usid={old_sid}"},
        )
        recovered = _request(
            server,
            "GET",
            rotated.headers["location"],
            headers={"Cookie": "usid=new-session"},
        )

    assert rotated.status == 303
    assert rotated.headers["location"] == (
        "/user/panel?msg=token_rotated_sync_pending"
    )
    assert "new-token" not in rotated.headers["location"]
    assert len(stops) == len(ss.static_access.SERVICES)
    assert {service for service, _reason, _live in stops} == set(
        ss.static_access.SERVICES
    )
    assert all(live is True for _service, _reason, live in stops)
    assert all(
        isinstance(reason, ss.CredentialRotationCommitted)
        for _service, reason, _live in stops
    )
    assert all(
        "new-token" not in str(reason)
        for _service, reason, _live in stops
    )
    stored = json.loads(
        state["USERS_FILE"].read_text(encoding="utf-8")
    )["alice"]
    assert stored["sub_token"] == "new-token"
    session = json.loads(
        state["USER_SESSIONS_FILE"].read_text(encoding="utf-8")
    )["new-session"]
    assert session["credential_generation"] == (
        ss._credential_generation("new-token")
    )
    assert recovered.status == 200
    assert "Xray/TUIC".encode("utf-8") in recovered.body
    assert "Hysteria".encode("utf-8") in recovered.body
    assert kicked == [["alice"]]


def test_self_rotation_renders_one_time_recovery_when_session_save_fails(
    tmp_path, monkeypatch
):
    state = _configure_state(
        tmp_path,
        monkeypatch,
        users={
            "alice": {
                "sub_token": "old-token",
                "vless_uuid": (
                    "11111111-1111-4111-8111-111111111111"
                ),
                "monthly_quota_bytes": 1024,
                "max_devices": 2,
                "disabled": False,
            },
        },
    )
    _forbid_generated_proxy_io(monkeypatch)
    monkeypatch.setattr(
        ss,
        "_sync_static_access_from_users",
        lambda _users, **_kwargs: (False, False),
    )
    monkeypatch.setattr(
        ss.secrets,
        "token_urlsafe",
        lambda length: "new-token" if length == 18 else "unused",
    )
    monkeypatch.setattr(
        ss.uuid,
        "uuid4",
        lambda: uuid.UUID(
            "33333333-3333-4333-8333-333333333333"
        ),
    )
    monkeypatch.setattr(
        ss,
        "create_user_session",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            state_store.StateStoreError("session store unavailable")
        ),
    )
    monkeypatch.setattr(ss, "hy_kick", lambda _users: None)
    old_sid = _seed_token_session(state)

    with _running_server() as server:
        response = _request(
            server,
            "POST",
            "/panel/alice/rotate-token",
            form={
                "token": "old-token",
                "rotation_id": "rotation-request-id-00000004",
            },
            headers={"Cookie": f"usid={old_sid}"},
        )

    assert response.status == 200
    assert "location" not in response.headers
    assert "set-cookie" not in response.headers
    assert response.headers["cache-control"] == "no-store"
    assert "登录会话未能保存".encode("utf-8") in response.body
    assert b"new-token" in response.body
    assert b"old-token" not in response.body
    assert (
        json.loads(
            state["USERS_FILE"].read_text(encoding="utf-8")
        )["alice"]["sub_token"]
        == "new-token"
    )


def test_rotation_post_replace_fsync_failure_is_delivered_fail_closed(
    tmp_path, monkeypatch
):
    state = _configure_state(
        tmp_path,
        monkeypatch,
        users={
            "alice": {
                "sub_token": "old-token",
                "vless_uuid": "11111111-1111-4111-8111-111111111111",
                "disabled": False,
            },
        },
    )
    old_sid = _seed_token_session(state)
    monkeypatch.setattr(ss, "_using_live_core_state", lambda: True)
    monkeypatch.setattr(
        ss,
        "_sync_static_access_from_users",
        lambda *_args, **_kwargs: pytest.fail(
            "durability-uncertain generation must not sync static auth"
        ),
    )
    monkeypatch.setattr(
        ss.secrets,
        "token_urlsafe",
        lambda length: "new-token" if length == 18 else "new-session",
    )
    monkeypatch.setattr(
        ss.uuid,
        "uuid4",
        lambda: uuid.UUID("33333333-3333-4333-8333-333333333333"),
    )
    real_fsync_dir = state_store._fsync_dir
    fsync_calls = 0

    def fail_users_directory_fsync_once(path):
        nonlocal fsync_calls
        fsync_calls += 1
        if fsync_calls == 3:
            raise OSError("simulated post-replace directory fsync failure")
        return real_fsync_dir(path)

    monkeypatch.setattr(
        state_store,
        "_fsync_dir",
        fail_users_directory_fsync_once,
    )
    reasons = []
    monkeypatch.setattr(
        ss.static_access,
        "stop_fail_closed",
        lambda service, *, reason, live, **_kwargs: (
            reasons.append((service, reason, live)) or True
        ),
    )
    monkeypatch.setattr(ss, "hy_kick", lambda _users: None)

    with _running_server() as server:
        response = _request(
            server,
            "POST",
            "/panel/alice/rotate-token",
            form={
                "token": "old-token",
                "rotation_id": "rotation-request-id-00000005",
            },
            headers={"Cookie": f"usid={old_sid}"},
        )

    assert response.status == 303
    assert response.headers["location"] == (
        "/user/panel?msg=token_rotated_sync_pending"
    )
    assert "token=" not in response.headers["location"]
    stored = json.loads(state["USERS_FILE"].read_text())["alice"]
    assert stored["sub_token"] == "new-token"
    assert stored["vless_uuid"] == (
        "33333333-3333-4333-8333-333333333333"
    )
    assert len(reasons) == len(ss.static_access.SERVICES)
    assert all(
        isinstance(reason, ss.CredentialRotationCommitted)
        and reason.durability_uncertain
        and "new-token" not in str(reason)
        for _service, reason, _live in reasons
    )
    # A forced live-mode assertion must not escape this test's state root.
    assert ss._rotation_receipts_path().parent == tmp_path
    assert ss._revocation_queue_path().parent == tmp_path


def test_replay_after_crash_between_canonical_save_and_sync_reuses_token(
    tmp_path, monkeypatch
):
    state = _configure_state(
        tmp_path,
        monkeypatch,
        users={
            "alice": {
                "sub_token": "old-token",
                "vless_uuid": "11111111-1111-4111-8111-111111111111",
                "disabled": False,
            },
        },
    )
    old_sid = _seed_token_session(state)
    generated = []

    def mint(length):
        assert length == 18
        generated.append("new-token")
        return "new-token"

    monkeypatch.setattr(ss.secrets, "token_urlsafe", mint)
    monkeypatch.setattr(
        ss.uuid,
        "uuid4",
        lambda: uuid.UUID("33333333-3333-4333-8333-333333333333"),
    )
    sync_calls = 0

    def crash_then_sync(_users, **_kwargs):
        nonlocal sync_calls
        sync_calls += 1
        if sync_calls == 1:
            raise SystemExit("simulated process crash before response")
        return False, False

    monkeypatch.setattr(
        ss,
        "_sync_static_access_from_users",
        crash_then_sync,
    )
    kwargs = {
        "request_id": "rotation-request-id-00000006",
        "session_id": old_sid,
    }

    with pytest.raises(SystemExit, match="simulated process crash"):
        ss._recoverable_user_rotation(
            "alice",
            "old-token",
            **kwargs,
        )
    replay = ss._recoverable_user_rotation(
        "alice",
        "old-token",
        **kwargs,
    )

    assert replay.status == "ok"
    assert replay.replayed is True
    assert replay.new_token == "new-token"
    assert generated == ["new-token"]
    assert sync_calls == 2
    assert (
        json.loads(state["USERS_FILE"].read_text())["alice"]["sub_token"]
        == "new-token"
    )


def test_concurrent_identical_replay_returns_one_generation_to_both(
    tmp_path, monkeypatch
):
    from concurrent.futures import ThreadPoolExecutor

    state = _configure_state(
        tmp_path,
        monkeypatch,
        users={
            "alice": {
                "sub_token": "old-token",
                "vless_uuid": "11111111-1111-4111-8111-111111111111",
                "disabled": False,
            },
        },
    )
    old_sid = _seed_token_session(state)
    generated = []
    generation_lock = threading.Lock()

    def mint(length):
        assert length == 18
        with generation_lock:
            generated.append(length)
        return "shared-new-token"

    monkeypatch.setattr(ss.secrets, "token_urlsafe", mint)
    monkeypatch.setattr(
        ss.uuid,
        "uuid4",
        lambda: uuid.UUID("33333333-3333-4333-8333-333333333333"),
    )
    monkeypatch.setattr(
        ss,
        "_sync_static_access_from_users",
        lambda *_args, **_kwargs: (False, False),
    )
    barrier = threading.Barrier(2)

    def rotate():
        barrier.wait(timeout=3)
        return ss._recoverable_user_rotation(
            "alice",
            "old-token",
            request_id="rotation-request-id-00000066",
            session_id=old_sid,
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _index: rotate(), range(2)))

    assert [result.status for result in results] == ["ok", "ok"]
    assert {result.new_token for result in results} == {
        "shared-new-token"
    }
    assert generated == [18]


def test_pre_replace_failure_replays_prepared_generation_without_rekey(
    tmp_path, monkeypatch
):
    state = _configure_state(
        tmp_path,
        monkeypatch,
        users={
            "alice": {
                "sub_token": "old-token",
                "vless_uuid": "11111111-1111-4111-8111-111111111111",
                "disabled": False,
            },
        },
    )
    old_sid = _seed_token_session(state)
    token_generations = 0

    def mint(length):
        nonlocal token_generations
        if length == 18:
            token_generations += 1
            return "new-token"
        return "new-session"

    monkeypatch.setattr(ss.secrets, "token_urlsafe", mint)
    monkeypatch.setattr(
        ss.uuid,
        "uuid4",
        lambda: uuid.UUID("33333333-3333-4333-8333-333333333333"),
    )
    monkeypatch.setattr(
        ss,
        "_sync_static_access_from_users",
        lambda *_args, **_kwargs: (False, False),
    )
    monkeypatch.setattr(ss, "hy_kick", lambda _users: None)
    real_save = ss._save_users_for_rotation
    save_calls = 0

    def fail_before_replace_once(*args, **kwargs):
        nonlocal save_calls
        save_calls += 1
        if save_calls == 1:
            raise OSError("simulated failure before replace")
        return real_save(*args, **kwargs)

    monkeypatch.setattr(
        ss,
        "_save_users_for_rotation",
        fail_before_replace_once,
    )
    form = {
        "token": "old-token",
        "rotation_id": "rotation-request-id-00000007",
    }
    headers = {"Cookie": f"usid={old_sid}"}

    with _running_server() as server:
        failed = _request(
            server,
            "POST",
            "/panel/alice/rotate-token",
            form=form,
            headers=headers,
        )
        replay = _request(
            server,
            "POST",
            "/panel/alice/rotate-token",
            form=form,
            headers=headers,
        )

    assert failed.status == 503
    assert replay.status == 303
    assert replay.headers["location"] == "/user/panel?msg=token_rotated"
    assert token_generations == 1
    assert (
        json.loads(state["USERS_FILE"].read_text())["alice"]["sub_token"]
        == "new-token"
    )


def test_lost_response_after_session_save_replays_same_receipt(
    tmp_path, monkeypatch
):
    state = _configure_state(
        tmp_path,
        monkeypatch,
        users={
            "alice": {
                "sub_token": "old-token",
                "vless_uuid": "11111111-1111-4111-8111-111111111111",
                "disabled": False,
            },
        },
    )
    old_sid = _seed_token_session(state)
    token_generations = 0
    session_generations = 0

    def mint(length):
        nonlocal token_generations, session_generations
        if length == 18:
            token_generations += 1
            return "new-token"
        session_generations += 1
        return f"new-session-{session_generations}"

    monkeypatch.setattr(ss.secrets, "token_urlsafe", mint)
    monkeypatch.setattr(
        ss.uuid,
        "uuid4",
        lambda: uuid.UUID("33333333-3333-4333-8333-333333333333"),
    )
    monkeypatch.setattr(
        ss,
        "_sync_static_access_from_users",
        lambda *_args, **_kwargs: (False, False),
    )
    monkeypatch.setattr(ss, "hy_kick", lambda _users: None)
    real_bind = ss.rotation_recovery.bind_replacement_session
    bind_calls = 0

    def lose_first_response(*args, **kwargs):
        nonlocal bind_calls
        bind_calls += 1
        if bind_calls == 1:
            raise state_store.StateStoreError(
                "simulated crash after session save"
            )
        return real_bind(*args, **kwargs)

    monkeypatch.setattr(
        ss.rotation_recovery,
        "bind_replacement_session",
        lose_first_response,
    )
    form = {
        "token": "old-token",
        "rotation_id": "rotation-request-id-00000008",
    }
    headers = {"Cookie": f"usid={old_sid}"}

    with _running_server() as server:
        recovery = _request(
            server,
            "POST",
            "/panel/alice/rotate-token",
            form=form,
            headers=headers,
        )
        replay = _request(
            server,
            "POST",
            "/panel/alice/rotate-token",
            form=form,
            headers=headers,
        )

    assert recovery.status == 200
    assert recovery.headers["cache-control"] == "no-store"
    assert recovery.headers["referrer-policy"] == "no-referrer"
    assert b"new-token" in recovery.body
    assert replay.status == 303
    assert "token=" not in replay.headers["location"]
    assert token_generations == 1
    # Two sessions were minted; the recovery renderer also creates one fresh
    # hidden idempotency key using the same token_urlsafe length.
    assert session_generations == 3


def test_admin_interleave_before_session_mint_returns_secret_free_conflict(
    tmp_path, monkeypatch
):
    state = _configure_state(
        tmp_path,
        monkeypatch,
        users={
            "alice": {
                "sub_token": "old-token",
                "vless_uuid": "11111111-1111-4111-8111-111111111111",
                "disabled": False,
            },
        },
    )
    old_sid = _seed_token_session(state)
    monkeypatch.setattr(
        ss.secrets,
        "token_urlsafe",
        lambda length: "self-new-token" if length == 18 else "unused",
    )
    monkeypatch.setattr(
        ss.uuid,
        "uuid4",
        lambda: uuid.UUID("33333333-3333-4333-8333-333333333333"),
    )
    monkeypatch.setattr(
        ss,
        "_sync_static_access_from_users",
        lambda *_args, **_kwargs: (False, False),
    )
    monkeypatch.setattr(ss, "hy_kick", lambda _users: None)

    def admin_wins_before_mint(
        _task_id, _result, **_kwargs
    ):
        users = json.loads(state["USERS_FILE"].read_text())
        users["alice"]["sub_token"] = "admin-new-token"
        users["alice"]["vless_uuid"] = (
            "44444444-4444-4444-8444-444444444444"
        )
        state_store.save_json(state["USERS_FILE"], users)
        return True

    monkeypatch.setattr(
        ss,
        "_record_kick_attempt",
        admin_wins_before_mint,
    )

    with _running_server() as server:
        response = _request(
            server,
            "POST",
            "/panel/alice/rotate-token",
            form={
                "token": "old-token",
                "rotation_id": "rotation-request-id-00000009",
            },
            headers={"Cookie": f"usid={old_sid}"},
        )

    assert response.status == 409
    assert "set-cookie" not in response.headers
    assert b"self-new-token" not in response.body
    assert b"admin-new-token" not in response.body
    assert "后续更新".encode("utf-8") in response.body


def test_unconfirmed_static_stop_is_warned_and_persisted_for_retry(
    tmp_path, monkeypatch
):
    state = _configure_state(
        tmp_path,
        monkeypatch,
        users={
            "alice": {
                "sub_token": "old-token",
                "vless_uuid": "11111111-1111-4111-8111-111111111111",
                "disabled": False,
            },
        },
    )
    old_sid = _seed_token_session(state)
    monkeypatch.setattr(ss, "_using_live_core_state", lambda: True)
    monkeypatch.setattr(
        ss.secrets,
        "token_urlsafe",
        lambda length: "new-token" if length == 18 else "new-session",
    )
    monkeypatch.setattr(
        ss.uuid,
        "uuid4",
        lambda: uuid.UUID("33333333-3333-4333-8333-333333333333"),
    )
    monkeypatch.setattr(
        ss,
        "_sync_static_access_from_users",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            state_store.CriticalStateUnavailable("sync failed")
        ),
    )

    def stop_result(service, **_kwargs):
        ok = service == ss.static_access.TUIC_SERVICE
        return ss.static_access.ServiceActionResult(
            service=service,
            action="stop_fail_closed",
            attempted=True,
            ok=ok,
            effect_confirmed=ok,
            marker_persisted=True,
            code="stopped" if ok else "nonzero_exit",
            retryable=not ok,
        )

    monkeypatch.setattr(
        ss.static_access,
        "stop_fail_closed",
        stop_result,
    )
    monkeypatch.setattr(ss, "hy_kick", lambda _users: None)

    with _running_server() as server:
        response = _request(
            server,
            "POST",
            "/panel/alice/rotate-token",
            form={
                "token": "old-token",
                "rotation_id": "rotation-request-id-00000010",
            },
            headers={"Cookie": f"usid={old_sid}"},
        )

    assert response.status == 303
    assert response.headers["location"] == (
        "/user/panel?msg=token_rotated_revocation_retry"
    )
    tasks = json.loads(ss._revocation_queue_path().read_text())
    assert len(tasks) == 1
    task = next(iter(tasks.values()))
    assert task["static_services"] == [ss.static_access.XRAY_SERVICE]
    assert "new-token" not in json.dumps(task)


def test_failed_hysteria_kick_uses_retry_notice_and_keeps_task(
    tmp_path, monkeypatch
):
    state = _configure_state(
        tmp_path,
        monkeypatch,
        users={
            "alice": {
                "sub_token": "old-token",
                "vless_uuid": "11111111-1111-4111-8111-111111111111",
                "disabled": False,
            },
        },
    )
    old_sid = _seed_token_session(state)
    monkeypatch.setattr(
        ss.secrets,
        "token_urlsafe",
        lambda length: "new-token" if length == 18 else "new-session",
    )
    monkeypatch.setattr(
        ss.uuid,
        "uuid4",
        lambda: uuid.UUID("33333333-3333-4333-8333-333333333333"),
    )
    monkeypatch.setattr(
        ss,
        "_sync_static_access_from_users",
        lambda *_args, **_kwargs: (False, False),
    )
    monkeypatch.setattr(
        ss,
        "hy_kick",
        lambda _users: ss.CredentialActionResult(
            action="hysteria_kick",
            target="alice",
            attempted=True,
            ok=False,
            code="TimeoutError",
            retryable=True,
        ),
    )

    with _running_server() as server:
        response = _request(
            server,
            "POST",
            "/panel/alice/rotate-token",
            form={
                "token": "old-token",
                "rotation_id": "rotation-request-id-00000011",
            },
            headers={"Cookie": f"usid={old_sid}"},
        )

    assert response.status == 303
    assert response.headers["location"] == (
        "/user/panel?msg=token_rotated_revocation_retry"
    )
    task = next(
        iter(
            json.loads(
                ss._revocation_queue_path().read_text(encoding="utf-8")
            ).values()
        )
    )
    assert task["kick_successes"] == 0


def test_reload_schedule_failure_reports_confirmed_static_pause(
    tmp_path, monkeypatch
):
    state = _configure_state(
        tmp_path,
        monkeypatch,
        users={
            "alice": {
                "sub_token": "old-token",
                "vless_uuid": "11111111-1111-4111-8111-111111111111",
                "disabled": False,
            },
        },
    )
    old_sid = _seed_token_session(state)
    monkeypatch.setattr(ss, "_using_live_core_state", lambda: True)
    monkeypatch.setattr(
        ss.secrets,
        "token_urlsafe",
        lambda length: "new-token" if length == 18 else "new-session",
    )
    monkeypatch.setattr(
        ss.uuid,
        "uuid4",
        lambda: uuid.UUID("33333333-3333-4333-8333-333333333333"),
    )
    monkeypatch.setattr(
        ss,
        "_sync_static_access_from_users",
        lambda *_args, **_kwargs: (True, False),
    )
    monkeypatch.setattr(ss.xray_config, "reload_async", lambda: False)
    monkeypatch.setattr(
        ss.static_access,
        "stop_fail_closed",
        lambda service, **_kwargs: ss.static_access.ServiceActionResult(
            service=service,
            action="stop_fail_closed",
            attempted=True,
            ok=True,
            effect_confirmed=True,
            marker_persisted=True,
            code="stopped",
            retryable=False,
        ),
    )
    monkeypatch.setattr(ss, "hy_kick", lambda _users: None)

    with _running_server() as server:
        response = _request(
            server,
            "POST",
            "/panel/alice/rotate-token",
            form={
                "token": "old-token",
                "rotation_id": "rotation-request-id-00000012",
            },
            headers={"Cookie": f"usid={old_sid}"},
        )

    assert response.status == 303
    assert response.headers["location"] == (
        "/user/panel?msg=token_rotated_static_pending"
    )


def test_admin_rotation_uses_pre_mutation_actor_snapshot(
    tmp_path, monkeypatch
):
    state = _configure_state(
        tmp_path,
        monkeypatch,
        users={
            "alice": {
                "sub_token": "old-token",
                "vless_uuid": "11111111-1111-4111-8111-111111111111",
            },
        },
    )
    monkeypatch.setattr(
        ss.secrets,
        "token_urlsafe",
        lambda length: "new-token" if length == 18 else "task-nonce",
    )
    monkeypatch.setattr(
        ss.uuid,
        "uuid4",
        lambda: uuid.UUID("33333333-3333-4333-8333-333333333333"),
    )
    monkeypatch.setattr(
        ss,
        "_sync_static_access_from_users",
        lambda *_args, **_kwargs: (False, False),
    )
    monkeypatch.setattr(ss, "hy_kick", lambda _users: None)
    actor_calls = 0

    def actor_snapshot(_handler):
        nonlocal actor_calls
        actor_calls += 1
        if actor_calls > 1:
            raise state_store.LockTimeout(
                "simulated post-commit session lock timeout"
            )
        return "snapshot-admin"

    monkeypatch.setattr(ss.Handler, "get_admin_actor", actor_snapshot)

    with _running_server() as server:
        response = _request(
            server,
            "POST",
            "/admin/rotate-token?token=admin-token",
            form={
                "user": "alice",
                "user_revision": _user_revision(state),
            },
        )

    assert response.status == 302
    assert actor_calls == 1
    assert (
        json.loads(state["USERS_FILE"].read_text())["alice"]["sub_token"]
        == "new-token"
    )
    log = state["RESET_LOG_FILE"].read_text(encoding="utf-8")
    assert '"actor": "snapshot-admin"' in log


def test_admin_post_replace_durability_uncertainty_is_not_misreported(
    tmp_path, monkeypatch
):
    state = _configure_state(
        tmp_path,
        monkeypatch,
        users={
            "alice": {
                "sub_token": "old-token",
                "vless_uuid": "11111111-1111-4111-8111-111111111111",
            },
        },
    )
    monkeypatch.setattr(ss, "_using_live_core_state", lambda: True)
    monkeypatch.setattr(
        ss.secrets,
        "token_urlsafe",
        lambda length: "new-token" if length == 18 else "task-nonce",
    )
    monkeypatch.setattr(
        ss.uuid,
        "uuid4",
        lambda: uuid.UUID("33333333-3333-4333-8333-333333333333"),
    )
    monkeypatch.setattr(
        ss,
        "_sync_static_access_from_users",
        lambda *_args, **_kwargs: pytest.fail(
            "uncertain canonical generation must not be reconciled"
        ),
    )
    real_fsync = state_store._fsync_dir
    calls = 0

    def fail_second_fsync(path):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("simulated admin users.json fsync failure")
        return real_fsync(path)

    monkeypatch.setattr(state_store, "_fsync_dir", fail_second_fsync)
    stopped = []
    monkeypatch.setattr(
        ss.static_access,
        "stop_fail_closed",
        lambda service, **_kwargs: stopped.append(service) or True,
    )
    monkeypatch.setattr(ss, "hy_kick", lambda _users: None)

    with _running_server() as server:
        response = _request(
            server,
            "POST",
            "/admin/rotate-token?token=admin-token",
            form={
                "user": "alice",
                "user_revision": _user_revision(state),
            },
        )

    assert response.status == 302
    assert "err%3Arotated_pending+alice" in response.headers["location"]
    assert set(stopped) == set(ss.static_access.SERVICES)
    assert (
        json.loads(state["USERS_FILE"].read_text())["alice"]["sub_token"]
        == "new-token"
    )


def test_hard_delete_purges_all_user_keyed_history_and_preserves_others(
    tmp_path, monkeypatch
):
    state = _configure_state(
        tmp_path,
        monkeypatch,
        users={
            "alice": {
                "sub_token": "alice-token",
                "vless_uuid": "11111111-1111-4111-8111-111111111111",
            },
            "bob": {
                "sub_token": "bob-token",
                "vless_uuid": "22222222-2222-4222-8222-222222222222",
            },
        },
    )
    entry_a = {"tx": 2, "rx": 3, "total": 5}
    entry_b = {"tx": 7, "rx": 11, "total": 18}
    for name, bucket_key in (
        ("USAGE_FILE", "2026-07"),
        ("USAGE_DAILY_FILE", "2026-07-18"),
        ("USAGE_HOURLY_FILE", "2026-07-18T12"),
        ("USAGE_PRESERVED_FILE", "2026-07-01"),
    ):
        _write_json(
            state[name],
            {
                bucket_key: {
                    "alice": entry_a,
                    "bob": entry_b,
                },
            },
        )
    _write_json(state["ONLINE_FILE"], {"alice": 2, "bob": 1})
    _write_json(
        state["DEVICE_ADMISSIONS_FILE"],
        {
            "alice": {"observed": 0, "pending": [100.0]},
            "bob": {"observed": 0, "pending": [100.0]},
        },
    )
    _write_json(
        state["ALERT_STATE_FILE"],
        {
            "quota_80": {"alice": "cycle-a", "bob": "cycle-b"},
            "quota_100": {"alice": "cycle-a", "bob": "cycle-b"},
            "anomaly": {"alice": "day-a", "bob": "day-b"},
            "expiry_soon": {"alice": "exp-a", "bob": "exp-b"},
            "expiry_expired": {"alice": "exp-a", "bob": "exp-b"},
            "future_dedup_kind": {"alice": "x", "bob": "y"},
        },
    )
    future = int(time.time()) + 3600
    _write_json(
        state["USER_SESSIONS_FILE"],
        {
            "alice-1": {"user": "alice", "exp": future},
            "alice-2": {"user": "alice", "exp": future},
            "bob-1": {"user": "bob", "exp": future},
        },
    )
    _forbid_generated_proxy_io(monkeypatch)
    synced = []
    monkeypatch.setattr(
        ss,
        "_sync_static_access_from_users",
        lambda users, **_kwargs: (
            synced.append(json.loads(json.dumps(users))) or False,
            False,
        ),
    )
    kicked = []
    monkeypatch.setattr(
        ss,
        "hy_kick",
        lambda usernames: kicked.append(list(usernames)),
    )

    with _running_server() as server:
        response = _request(
            server,
            "POST",
            "/admin/delete?token=admin-token",
            form={
                "user": "alice",
                "user_revision": _user_revision(state),
            },
        )

    assert response.status == 302
    assert set(json.loads(state["USERS_FILE"].read_text())) == {"bob"}
    for name, bucket_key in (
        ("USAGE_FILE", "2026-07"),
        ("USAGE_DAILY_FILE", "2026-07-18"),
        ("USAGE_HOURLY_FILE", "2026-07-18T12"),
        ("USAGE_PRESERVED_FILE", "2026-07-01"),
    ):
        bucket = json.loads(state[name].read_text())[bucket_key]
        assert set(bucket) == {"bob"}
        assert bucket["bob"] == entry_b
    assert json.loads(state["ONLINE_FILE"].read_text()) == {"bob": 1}
    assert json.loads(
        state["DEVICE_ADMISSIONS_FILE"].read_text()
    ) == {
        "bob": {"observed": 0, "pending": [100.0]},
    }
    alert_state = json.loads(state["ALERT_STATE_FILE"].read_text())
    assert all(
        "alice" not in bucket
        for bucket in alert_state.values()
        if isinstance(bucket, dict)
    )
    assert all(
        bucket.get("bob") is not None
        for bucket in alert_state.values()
        if isinstance(bucket, dict)
    )
    sessions = json.loads(state["USER_SESSIONS_FILE"].read_text())
    assert sessions == {
        "bob-1": {"user": "bob", "exp": future},
    }
    assert set(synced[-1]) == {"bob"}
    assert kicked == [["alice"]]


def test_delete_wal_replays_when_users_replace_never_happens(
    tmp_path, monkeypatch,
):
    state = _configure_state(
        tmp_path,
        monkeypatch,
        users={
            "alice": {
                "sub_token": "alice-token",
                "vless_uuid": "11111111-1111-4111-8111-111111111111",
            },
        },
    )
    _write_json(
        state["USAGE_FILE"],
        {"2026-07": {"alice": {"total": 17}}},
    )
    real_save_json = ss.save_json
    failed = False

    def fail_users_before_replace(path, data):
        nonlocal failed
        if Path(path) == state["USERS_FILE"] and not failed:
            failed = True
            raise state_store.StateStoreError(
                "simulated failure before users replace"
            )
        return real_save_json(path, data)

    monkeypatch.setattr(ss, "save_json", fail_users_before_replace)
    monkeypatch.setattr(
        ss,
        "_sync_static_access_from_users",
        lambda *_args, **_kwargs: pytest.fail(
            "static auth must not sync before canonical delete commits"
        ),
    )
    monkeypatch.setattr(
        ss.static_access,
        "stop_fail_closed",
        lambda service, **_kwargs: _service_stop_result(
            service, ok=True,
        ),
    )
    kicks = []
    monkeypatch.setattr(
        ss,
        "hy_kick",
        lambda users: kicks.append(list(users)),
    )

    with _running_server() as server:
        response = _request(
            server,
            "POST",
            "/admin/delete?token=admin-token",
            form={
                "user": "alice",
                "user_revision": _user_revision(state),
            },
        )

    assert response.status == 302
    assert "err%3Adeleted_retry+alice" in response.headers["location"]
    assert "alice" in json.loads(state["USERS_FILE"].read_text())
    assert "alice" in json.loads(
        state["USAGE_FILE"].read_text()
    )["2026-07"]
    queue_path = ss._revocation_queue_path()
    task_id = _make_only_revocation_due(queue_path)
    task = json.loads(queue_path.read_text())[task_id]
    assert task["previous_generation"].startswith(
        ss._DELETE_PREVIOUS_PREFIX
    )
    assert task["target_generation"] == ss._DELETE_TARGET_GENERATION

    assert ss._process_one_revocation_task() is True
    assert json.loads(state["USERS_FILE"].read_text()) == {}
    assert json.loads(state["USAGE_FILE"].read_text())["2026-07"] == {}
    assert json.loads(queue_path.read_text()) == {}
    assert kicks == [["alice"], ["alice"]]


def test_delete_post_replace_fsync_uncertainty_defers_history_cleanup(
    tmp_path, monkeypatch,
):
    state = _configure_state(
        tmp_path,
        monkeypatch,
        users={
            "alice": {
                "sub_token": "alice-token",
                "vless_uuid": "11111111-1111-4111-8111-111111111111",
            },
        },
    )
    _write_json(
        state["USAGE_FILE"],
        {"2026-07": {"alice": {"total": 29}}},
    )
    real_fsync_dir = state_store._fsync_dir
    fsync_calls = 0

    def fail_users_directory_fsync(path):
        nonlocal fsync_calls
        fsync_calls += 1
        if fsync_calls == 2:
            raise OSError("simulated users directory fsync failure")
        return real_fsync_dir(path)

    monkeypatch.setattr(
        state_store,
        "_fsync_dir",
        fail_users_directory_fsync,
    )
    monkeypatch.setattr(
        ss,
        "_sync_static_access_from_users",
        lambda *_args, **_kwargs: pytest.fail(
            "uncertain delete must not sync before a durability barrier"
        ),
    )
    monkeypatch.setattr(
        ss.static_access,
        "stop_fail_closed",
        lambda service, **_kwargs: _service_stop_result(
            service, ok=True,
        ),
    )
    kicks = []
    monkeypatch.setattr(
        ss,
        "hy_kick",
        lambda users: kicks.append(list(users)),
    )

    with _running_server() as server:
        response = _request(
            server,
            "POST",
            "/admin/delete?token=admin-token",
            form={
                "user": "alice",
                "user_revision": _user_revision(state),
            },
        )

    assert response.status == 302
    assert "err%3Adeleted_retry+alice" in response.headers["location"]
    assert json.loads(state["USERS_FILE"].read_text()) == {}
    # The visible replace is not yet a safe point for destructive cleanup.
    assert "alice" in json.loads(
        state["USAGE_FILE"].read_text()
    )["2026-07"]

    queue_path = ss._revocation_queue_path()
    tasks = json.loads(queue_path.read_text())
    for task in tasks.values():
        task["created_at"] = 1
        task["expires_at"] = 1 + ss.revocation_queue.TASK_TTL_SECONDS
        task["next_attempt_at"] = 1
        task["lease_until"] = 0
    _write_json(queue_path, tasks)
    assert next(iter(tasks.values()))["expires_at"] < int(time.time())
    _make_only_revocation_due(queue_path)
    assert ss._process_one_revocation_task() is True
    assert json.loads(state["USAGE_FILE"].read_text())["2026-07"] == {}
    assert json.loads(queue_path.read_text()) == {}
    assert kicks == [["alice"], ["alice"]]


def test_delete_static_sync_failure_is_fail_closed_and_retried(
    tmp_path, monkeypatch,
):
    state = _configure_state(
        tmp_path,
        monkeypatch,
        users={
            "alice": {
                "sub_token": "alice-token",
                "vless_uuid": "11111111-1111-4111-8111-111111111111",
            },
        },
    )
    sync_calls = []

    def fail_once_then_sync(users, **_kwargs):
        sync_calls.append(json.loads(json.dumps(users)))
        if len(sync_calls) == 1:
            raise state_store.CriticalStateUnavailable(
                "simulated static sync failure"
            )
        return False, False

    monkeypatch.setattr(
        ss, "_sync_static_access_from_users", fail_once_then_sync,
    )
    stopped = []
    monkeypatch.setattr(
        ss.static_access,
        "stop_fail_closed",
        lambda service, **_kwargs: (
            stopped.append(service)
            or _service_stop_result(service, ok=False)
        ),
    )
    kicks = []
    monkeypatch.setattr(
        ss,
        "hy_kick",
        lambda users: kicks.append(list(users)),
    )

    with _running_server() as server:
        response = _request(
            server,
            "POST",
            "/admin/delete?token=admin-token",
            form={
                "user": "alice",
                "user_revision": _user_revision(state),
            },
        )

    assert response.status == 302
    assert "err%3Adeleted_retry+alice" in response.headers["location"]
    assert set(stopped) == set(ss.static_access.SERVICES)
    queue_path = ss._revocation_queue_path()
    _make_only_revocation_due(queue_path)

    assert ss._process_one_revocation_task() is True
    assert len(sync_calls) == 2
    assert sync_calls[0] == {}
    assert sync_calls[1] == {}
    assert kicks == [["alice"], ["alice"]]
    assert json.loads(queue_path.read_text()) == {}


def test_delete_history_mid_commit_failure_is_idempotently_replayed(
    tmp_path, monkeypatch,
):
    state = _configure_state(
        tmp_path,
        monkeypatch,
        users={
            "alice": {
                "sub_token": "alice-token",
                "vless_uuid": "11111111-1111-4111-8111-111111111111",
            },
        },
    )
    for name, key in (
        ("USAGE_FILE", "2026-07"),
        ("USAGE_DAILY_FILE", "2026-07-18"),
    ):
        _write_json(
            state[name],
            {key: {"alice": {"total": 41}}},
        )
    real_save_json = ss.save_json
    failed = False

    def fail_daily_once(path, data):
        nonlocal failed
        if Path(path) == state["USAGE_DAILY_FILE"] and not failed:
            failed = True
            raise state_store.StateStoreError(
                "simulated history cleanup interruption"
            )
        return real_save_json(path, data)

    monkeypatch.setattr(ss, "save_json", fail_daily_once)
    monkeypatch.setattr(
        ss,
        "_sync_static_access_from_users",
        lambda *_args, **_kwargs: (False, False),
    )
    kicks = []
    monkeypatch.setattr(
        ss,
        "hy_kick",
        lambda users: kicks.append(list(users)),
    )

    with _running_server() as server:
        response = _request(
            server,
            "POST",
            "/admin/delete?token=admin-token",
            form={
                "user": "alice",
                "user_revision": _user_revision(state),
            },
        )

    assert response.status == 302
    assert "err%3Adeleted_retry+alice" in response.headers["location"]
    assert json.loads(state["USERS_FILE"].read_text()) == {}
    assert json.loads(state["USAGE_FILE"].read_text())["2026-07"] == {}
    assert "alice" in json.loads(
        state["USAGE_DAILY_FILE"].read_text()
    )["2026-07-18"]

    queue_path = ss._revocation_queue_path()
    tasks = json.loads(queue_path.read_text())
    for task in tasks.values():
        task["created_at"] = 1
        task["expires_at"] = 1 + ss.revocation_queue.TASK_TTL_SECONDS
        task["next_attempt_at"] = 1
        task["lease_until"] = 0
    _write_json(queue_path, tasks)
    _make_only_revocation_due(queue_path)
    assert ss._process_one_revocation_task() is True
    assert json.loads(
        state["USAGE_DAILY_FILE"].read_text()
    )["2026-07-18"] == {}
    assert json.loads(queue_path.read_text()) == {}
    assert kicks == [["alice"], ["alice"]]


def test_delete_retry_never_purges_same_name_new_incarnation(
    tmp_path, monkeypatch,
):
    old_cfg = {
        "sub_token": "old-token",
        "vless_uuid": "11111111-1111-4111-8111-111111111111",
    }
    state = _configure_state(
        tmp_path,
        monkeypatch,
        users={"alice": old_cfg},
    )
    sync_snapshots = []
    monkeypatch.setattr(
        ss,
        "_sync_static_access_from_users",
        lambda users, **_kwargs: (
            sync_snapshots.append(json.loads(json.dumps(users)))
            or (False, False)
        ),
    )
    schedule_calls = 0

    def defer_first_handoff(service, *, changed):
        del changed
        nonlocal schedule_calls
        schedule_calls += 1
        ok = schedule_calls > len(ss.static_access.SERVICES)
        return ss.CredentialActionResult(
            action="static_reload",
            target=service,
            attempted=True,
            ok=ok,
            code="scheduled" if ok else "not_scheduled",
            retryable=not ok,
        )

    monkeypatch.setattr(
        ss, "_schedule_static_reload", defer_first_handoff,
    )
    monkeypatch.setattr(
        ss.static_access,
        "stop_fail_closed",
        lambda service, **_kwargs: _service_stop_result(
            service, ok=False,
        ),
    )
    kicks = []
    monkeypatch.setattr(
        ss,
        "hy_kick",
        lambda users: kicks.append(list(users)),
    )

    with _running_server() as server:
        response = _request(
            server,
            "POST",
            "/admin/delete?token=admin-token",
            form={
                "user": "alice",
                "user_revision": _user_revision(state),
            },
        )

    assert response.status == 302
    assert json.loads(state["USERS_FILE"].read_text()) == {}
    new_cfg = {
        "sub_token": "new-token",
        "vless_uuid": "22222222-2222-4222-8222-222222222222",
    }
    state_store.save_json(state["USERS_FILE"], {"alice": new_cfg})
    _write_json(
        state["USAGE_FILE"],
        {"2026-07": {"alice": {"total": 73}}},
    )
    future = int(time.time()) + 3600
    _write_json(
        state["USER_SESSIONS_FILE"],
        {"new-session": {"user": "alice", "exp": future}},
    )

    queue_path = ss._revocation_queue_path()
    tasks = json.loads(queue_path.read_text())
    for task in tasks.values():
        task["created_at"] = 1
        task["expires_at"] = 1 + ss.revocation_queue.TASK_TTL_SECONDS
        task["next_attempt_at"] = 1
        task["lease_until"] = 0
    _write_json(queue_path, tasks)
    _make_only_revocation_due(queue_path)
    assert ss._process_one_revocation_task() is True
    assert json.loads(state["USERS_FILE"].read_text()) == {
        "alice": new_cfg,
    }
    assert json.loads(state["USAGE_FILE"].read_text()) == {
        "2026-07": {"alice": {"total": 73}},
    }
    assert "new-session" in json.loads(
        state["USER_SESSIONS_FILE"].read_text()
    )
    assert sync_snapshots[-1]["alice"]["sub_token"] == "new-token"
    assert kicks == [["alice"], ["alice"]]
    assert json.loads(queue_path.read_text()) == {}


def test_generic_auth_write_durability_uncertainty_stops_static_proxies(
    tmp_path, monkeypatch,
):
    state = _configure_state(
        tmp_path,
        monkeypatch,
        users={
            "alice": {
                "sub_token": "alice-token",
                "vless_uuid": "11111111-1111-4111-8111-111111111111",
                "disabled": False,
            },
        },
    )
    monkeypatch.setattr(ss, "_using_live_core_state", lambda: True)
    monkeypatch.setattr(
        ss,
        "_sync_static_access_from_users",
        lambda *_args, **_kwargs: pytest.fail(
            "uncertain users generation must not sync static auth"
        ),
    )
    real_fsync_dir = state_store._fsync_dir
    failed = False

    def fail_first_directory_fsync(path):
        nonlocal failed
        if not failed:
            failed = True
            raise OSError("simulated users directory fsync failure")
        return real_fsync_dir(path)

    monkeypatch.setattr(
        state_store,
        "_fsync_dir",
        fail_first_directory_fsync,
    )
    stopped = []
    monkeypatch.setattr(
        ss.static_access,
        "stop_fail_closed",
        lambda service, **_kwargs: (
            stopped.append(service)
            or _service_stop_result(service, ok=True)
        ),
    )
    monkeypatch.setattr(
        ss,
        "hy_kick",
        lambda *_args, **_kwargs: pytest.fail(
            "request must not claim a kick after uncertain generic commit"
        ),
    )

    with _running_server() as server:
        response = _request(
            server,
            "POST",
            (
                "/admin/toggle-user?token=admin-token"
                "&desired=disabled"
            ),
            form={
                "user": "alice",
                "user_revision": _user_revision(state),
            },
        )

    assert response.status == 503
    assert set(stopped) == set(ss.static_access.SERVICES)
    assert json.loads(
        state["USERS_FILE"].read_text()
    )["alice"]["disabled"] is True
    assert "已确认静态代理暂停".encode("utf-8") in response.body


def test_session_files_enforce_per_identity_and_global_caps(
    tmp_path, monkeypatch
):
    session_file = tmp_path / "bounded_sessions.json"
    monkeypatch.setattr(ss, "SESSION_MAX_PER_IDENTITY", 3)
    monkeypatch.setattr(ss, "SESSION_MAX_GLOBAL", 5)

    alice_ids = [
        ss._create_session(session_file, "alice")
        for _index in range(7)
    ]
    sessions = json.loads(session_file.read_text(encoding="utf-8"))
    assert len(sessions) == 3
    assert all(info["user"] == "alice" for info in sessions.values())
    assert alice_ids[-1] in sessions

    latest_ids = {}
    for username in ("bob", "carol", "dave", "erin"):
        latest_ids[username] = ss._create_session(
            session_file,
            username,
        )

    sessions = json.loads(session_file.read_text(encoding="utf-8"))
    assert len(sessions) == 5
    counts = {}
    for info in sessions.values():
        counts[info["user"]] = counts.get(info["user"], 0) + 1
    assert max(counts.values()) <= 3
    assert latest_ids["erin"] in sessions


def test_corrupt_optional_sessions_on_unauthenticated_mutation_does_not_stop(
    tmp_path, monkeypatch
):
    state = _configure_state(
        tmp_path,
        monkeypatch,
        users={
            "alice": {
                "sub_token": "alice-token",
                "vless_uuid": "11111111-1111-4111-8111-111111111111",
            },
        },
    )
    state["SESSIONS_FILE"].write_text('{"broken":', encoding="utf-8")
    stop_calls = []
    monkeypatch.setattr(
        ss.static_access,
        "stop_fail_closed",
        lambda *args, **kwargs: stop_calls.append((args, kwargs)),
    )
    monkeypatch.setattr(
        ss,
        "_sync_static_access_from_users",
        lambda *_args, **_kwargs: pytest.fail(
            "unauthenticated request reached config reconciliation"
        ),
    )
    monkeypatch.setattr(
        ss,
        "hy_kick",
        lambda *_args, **_kwargs: pytest.fail(
            "unauthenticated request kicked a user"
        ),
    )

    with _running_server() as server:
        response = _request(
            server,
            "POST",
            "/admin/delete",
            form={"user": "alice"},
        )

    assert response.status == 503
    assert "代理服务未受影响".encode("utf-8") in response.body
    assert stop_calls == []
    assert "alice" in json.loads(state["USERS_FILE"].read_text())


def test_generated_config_failure_is_critical_and_stops_static_services(
    tmp_path, monkeypatch
):
    state = _configure_state(
        tmp_path,
        monkeypatch,
        users={
            "alice": {
                "sub_token": "old-token",
                "vless_uuid": "11111111-1111-4111-8111-111111111111",
                "disabled": False,
            },
        },
    )
    monkeypatch.setattr(ss, "_using_live_core_state", lambda: True)
    monkeypatch.setattr(
        ss.xray_config,
        "apply_user_plan",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            RuntimeError("simulated generated config failure")
        ),
    )
    monkeypatch.setattr(
        ss.tuic_config,
        "sync_user_plan",
        lambda *_args, **_kwargs: pytest.fail(
            "TUIC reconciliation ran after Xray failed"
        ),
    )
    monkeypatch.setattr(
        ss.static_access,
        "recover_if_pending",
        lambda *_args, **_kwargs: pytest.fail(
            "recovery ran before safe config reconciliation"
        ),
    )
    stop_calls = []

    def record_stop(service, *, reason, live, **_kwargs):
        stop_calls.append((service, reason, live))
        return True

    monkeypatch.setattr(
        ss.static_access,
        "stop_fail_closed",
        record_stop,
    )
    monkeypatch.setattr(
        ss.xray_config,
        "reload_async",
        lambda: pytest.fail("reload ran after reconciliation failure"),
    )
    monkeypatch.setattr(
        ss.tuic_config,
        "reload_async",
        lambda: pytest.fail("reload ran after reconciliation failure"),
    )
    monkeypatch.setattr(
        ss,
        "hy_kick",
        lambda users: kicked.append(list(users)),
    )
    kicked = []

    with _running_server() as server:
        response = _request(
            server,
            "POST",
            "/admin/rotate-token?token=admin-token",
            form={
                "user": "alice",
                "user_revision": _user_revision(state),
            },
        )

    assert response.status == 302
    assert "err%3Arotated_pending+alice" in response.headers["location"]
    assert len(stop_calls) == len(ss.static_access.SERVICES)
    assert {call[0] for call in stop_calls} == set(
        ss.static_access.SERVICES
    )
    assert all(call[2] is True for call in stop_calls)
    assert all(
        isinstance(call[1], state_store.CriticalStateUnavailable)
        for call in stop_calls
    )
    # User state was committed before the generated-config failure, which is
    # why stopping the stale static services is mandatory.
    assert (
        json.loads(state["USERS_FILE"].read_text())["alice"]["sub_token"]
        != "old-token"
    )
    assert kicked == [["alice"]]


def test_panel_reads_multiplier_changes_immediately_without_restart(
    tmp_path, monkeypatch
):
    state = _configure_state(
        tmp_path,
        monkeypatch,
        users={
            "alice": {
                "sub_token": "alice-token",
                "vless_uuid": "11111111-1111-4111-8111-111111111111",
                "monthly_quota_bytes": 10_000,
                "disabled": False,
            },
        },
    )
    fixed_now = datetime(2026, 7, 18, 12, 0, 0)
    monkeypatch.setattr(ss, "local_now", lambda: fixed_now)
    monkeypatch.delenv("HY_DISPLAY_MULTIPLIER", raising=False)
    _write_json(
        state["USAGE_DAILY_FILE"],
        {
            "2026-07-18": {
                "alice": {"tx": 4, "rx": 6, "total": 10},
            },
        },
    )
    _write_json(
        state["DISPLAY_MULTIPLIER_STATE_FILE"],
        {"enabled": True, "multiplier": 1.5},
    )
    _forbid_generated_proxy_io(monkeypatch)
    monkeypatch.setattr(
        ss,
        "restart_subscription_async",
        lambda: pytest.fail("multiplier read required a restart"),
    )

    with _running_server() as server:
        before = _request(
            server,
            "GET",
            "/panel/alice.json?token=alice-token",
        )
        _write_json(
            state["DISPLAY_MULTIPLIER_STATE_FILE"],
            {"enabled": True, "multiplier": 3.0},
        )
        after = _request(
            server,
            "GET",
            "/panel/alice.json?token=alice-token",
        )

    assert before.status == after.status == 200
    assert json.loads(before.body)["used_bytes"] == 15
    assert json.loads(after.body)["used_bytes"] == 30


def test_exact_access_plan_excludes_expired_and_over_quota_users(
    tmp_path, monkeypatch
):
    _configure_state(tmp_path, monkeypatch)
    monkeypatch.delenv("HY_DISPLAY_MULTIPLIER", raising=False)
    _write_json(
        tmp_path / "display_multiplier.json",
        {"enabled": True, "multiplier": 2.0},
    )
    now = datetime(2026, 7, 18, 12, 0, 0)
    users = {
        "active": {
            "sub_token": "active-token",
            "vless_uuid": "11111111-1111-4111-8111-111111111111",
            "disabled": False,
        },
        "expired": {
            "sub_token": "expired-token",
            "vless_uuid": "22222222-2222-4222-8222-222222222222",
            "expires_at": "2026-07-17",
            "disabled": False,
        },
        "over-quota": {
            "sub_token": "over-token",
            "vless_uuid": "33333333-3333-4333-8333-333333333333",
            "metered": True,
            "monthly_quota_bytes": 100,
            "disabled": False,
        },
    }
    daily = {
        "2026-07-18": {
            "over-quota": {"tx": 20, "rx": 40, "total": 60},
        },
    }
    meta = {
        "settlement_day": 1,
        "cycle_length_days": 30,
        "cycle_anchor_date": "2026-01-01",
    }

    plan = ss._build_static_access_plan(
        users,
        daily,
        meta,
        now=now,
    )

    assert plan == {
        "active": "11111111-1111-4111-8111-111111111111",
        "expired": None,
        "over-quota": None,
    }
