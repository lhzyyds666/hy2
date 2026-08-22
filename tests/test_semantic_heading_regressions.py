"""Regression guards for admin-page heading semantics.

These checks validate rendered markup only. They deliberately do not claim
browser, visual, or screen-reader verification.
"""

from datetime import datetime
import html
from html.parser import HTMLParser
from pathlib import Path
import re
from types import SimpleNamespace

import health_widgets
import incident_console
import subscription_service as ss
import usage_dashboard


ROOT = Path(__file__).resolve().parents[1]
NOW = datetime.fromisoformat("2026-07-18T12:00:00+08:00")


class _HeadingAudit(HTMLParser):
    """Collect heading order and detect headings promoted from table rows."""

    def __init__(self):
        super().__init__()
        self.headings = []
        self.cell_bold_texts = []
        self._cell_depth = 0
        self._active_heading = None
        self._active_cell_bold = None

    def handle_starttag(self, tag, attrs):
        values = dict(attrs)
        if tag in {"td", "th"}:
            self._cell_depth += 1

        if tag in {"h1", "h2", "h3", "h4", "h5", "h6"}:
            record = {
                "level": int(tag[1]),
                "text": [],
                "in_table_cell": self._cell_depth > 0,
            }
            self.headings.append(record)
            self._active_heading = record

        classes = set(values.get("class", "").split())
        if tag == "div" and "bold" in classes and self._cell_depth:
            self._active_cell_bold = []

    def handle_data(self, data):
        if self._active_heading is not None:
            self._active_heading["text"].append(data)
        if self._active_cell_bold is not None:
            self._active_cell_bold.append(data)

    def handle_endtag(self, tag):
        if tag in {"h1", "h2", "h3", "h4", "h5", "h6"}:
            self._active_heading = None
        if tag == "div" and self._active_cell_bold is not None:
            text = " ".join("".join(self._active_cell_bold).split())
            self.cell_bold_texts.append(text)
            self._active_cell_bold = None
        if tag in {"td", "th"}:
            self._cell_depth = max(0, self._cell_depth - 1)


def _audit(markup):
    parser = _HeadingAudit()
    parser.feed(markup)
    for heading in parser.headings:
        heading["text"] = " ".join("".join(heading["text"]).split())
    return parser


def _shell(_active, title, content, **_kwargs):
    return f"<h1>{html.escape(title)}</h1>{content}"


def _assert_valid_outline(markup, expected_levels):
    audit = _audit(markup)
    levels = [heading["level"] for heading in audit.headings]
    assert levels == expected_levels
    assert all(not heading["in_table_cell"] for heading in audit.headings)
    assert all(current <= previous + 1
               for previous, current in zip(levels, levels[1:]))
    return audit


def test_usage_pages_have_contiguous_h1_h2_h3_outlines(monkeypatch):
    stats = {
        "current_hour_bytes": 0,
        "today_bytes": 0,
        "yesterday_bytes": 0,
        "last_7d_bytes": 0,
        "cycle_bytes": 0,
        "cycle_day": 1,
        "cycle_total_days": 30,
        "online": 0,
    }
    hourly = [
        {"hour": f"2026-07-18T{hour:02d}", "bytes": 0}
        for hour in range(24)
    ]
    heatmap = [
        {"date": f"2026-07-{day:02d}", "hours": [0] * 24}
        for day in range(12, 19)
    ]
    monkeypatch.setattr(
        usage_dashboard,
        "build_analytics_json_payload",
        lambda _ctx, *, now, include_charts=True: {
            "stats": stats,
            "hourly_totals": hourly,
            "heatmap": heatmap,
            "top_n": [],
        },
    )
    monkeypatch.setattr(
        usage_dashboard,
        "build_user_json_payload",
        lambda _ctx, _uid, *, now, include_charts=True: {
            "uid": "alice",
            "metered": True,
            "disabled": False,
            "expired": False,
            "expiry_label": "长期有效",
            "note": "",
            "online": 0,
            "max_devices": 2,
            "cycle_used_bytes": 0,
            "cycle_quota_bytes": 0,
            "quota_extra_bytes": 0,
            "current_hour_bytes": 0,
            "today_bytes": 0,
            "recent_alerts": [],
            "hourly_bars": hourly,
            "heatmap": heatmap,
        },
    )
    common = {
        "local_now": lambda: NOW,
        "fmt_bytes": lambda value: f"{value} B",
        "render_admin_shell": _shell,
        "local_tz_label": "Asia/Shanghai",
        "asset_version": "test",
    }
    usage_ctx = SimpleNamespace(**common)
    usage_page = usage_dashboard.render_usage_page(usage_ctx, "panel.test")
    user_page = usage_dashboard.render_user_detail_page(
        usage_ctx, "alice", "panel.test"
    )

    daily_ctx = SimpleNamespace(
        **common,
        users_file="users",
        usage_daily_file="daily",
        daily_retention_days=30,
        display_multiplier=1.0,
        load_json=lambda _path, default: default,
    )
    daily_page = usage_dashboard.render_daily_usage(
        daily_ctx, "panel.test", days=14
    )

    _assert_valid_outline(daily_page, [1, 2])
    _assert_valid_outline(usage_page, [1, 2, 2, 2])
    _assert_valid_outline(user_page, [1, 2, 3, 3, 3])


def _render_health_widgets(monkeypatch):
    monkeypatch.setattr(
        health_widgets,
        "build_line_radar",
        lambda _ctx, now=None: {
            "window_hours": 24,
            "total_bytes": 0,
            "recommendation": "default",
            "reason": "保持默认模板",
            "rows": [{
                "label": "Hysteria UDP",
                "note": "低延迟优先",
                "ok": True,
                "status": "active",
                "bytes": 0,
                "share": 0.0,
                "active_users": 1,
                "online": 0,
                "profile": "game",
            }],
        },
    )
    summary = {
        "window_hours": 24,
        "current_multiplier": 1.0,
        "suggested_multiplier": None,
        "egress_multiplier": None,
        "delta_percent": None,
        "app_raw_bytes": 0,
        "net_total_bytes": 0,
        "included_sample_count": 0,
        "sample_count": 0,
        "confidence": "none",
        "ifaces": [],
    }
    monkeypatch.setattr(
        health_widgets,
        "summarize_cost_calibration",
        lambda _ctx, now=None: summary,
    )
    monkeypatch.setattr(
        health_widgets.cost_calibrator,
        "summarize_windows",
        lambda *_args, **_kwargs: [],
    )
    monkeypatch.setattr(
        health_widgets.cost_calibrator,
        "load_auto_policy",
        lambda _path: {
            "enabled": False,
            "mode": "total",
            "min_confidence": "medium",
            "max_delta_percent": 25.0,
            "min_delta_percent": 5.0,
            "cooldown_hours": 24.0,
            "last_checked_at": "",
        },
    )
    ctx = SimpleNamespace(
        subscription_profiles={"default": {"label": "默认"}},
        fmt_bytes=lambda value: f"{value} B",
        local_now=lambda: NOW,
        display_multiplier=1.0,
        cost_calibration_file="calibration",
        multiplier_auto_policy_file="policy",
        display_multiplier_state_file="runtime",
        load_json=lambda _path, default: default,
    )
    return (
        health_widgets.render_line_radar(ctx, now=NOW),
        health_widgets.render_cost_calibrator(ctx, now=NOW),
    )


def test_incident_and_health_regions_are_h2_but_table_labels_are_not(
    monkeypatch,
):
    line_radar, cost_calibrator = _render_health_widgets(monkeypatch)
    payload = {
        "stats": {"current_hour_bytes": 0, "online": 0},
        "peak_hour": {
            "bytes": 0,
            "hour": "",
            "users": [{"user": "alice", "bytes": 0}],
        },
        "users": [{
            "user": "alice",
            "quota_percent": 0.0,
            "quota_bytes": 100,
            "cycle_used_bytes": 0,
            "last_24h_bytes": 0,
            "note": "测试用户",
            "expiry_label": "长期有效",
            "metered": True,
            "disabled": False,
            "expired": False,
            "online": 0,
        }],
        "line_radar": {
            "recommendation": "default",
            "reason": "保持默认模板",
        },
        "alerts": [],
    }
    monkeypatch.setattr(
        incident_console,
        "build_incident_payload",
        lambda _ctx, *, now: payload,
    )
    ctx = SimpleNamespace(
        local_now=lambda: NOW,
        render_alert=lambda value: value,
        flash_text=lambda value: value,
        fmt_bytes=lambda value: f"{value} B",
        subscription_profiles={"default": {"label": "默认"}},
        render_line_radar=lambda **_kwargs: line_radar,
        render_cost_calibrator=lambda **_kwargs: cost_calibrator,
        render_admin_shell=_shell,
    )
    page = incident_console.render_incidents(ctx, "panel.test")
    audit = _assert_valid_outline(page, [1, 2, 2, 2, 2, 2])
    heading_texts = [heading["text"] for heading in audit.headings]

    assert heading_texts == [
        "事故处理",
        "峰值小时相关用户",
        "近期告警状态",
        "处置候选用户",
        "线路质量雷达",
        "成本校准器",
    ]
    assert "alice" not in heading_texts
    assert "Hysteria UDP" not in heading_texts
    assert {"alice", "Hysteria UDP"} <= set(audit.cell_bold_texts)


def test_user_panel_sections_follow_its_h1_without_div_titles(
    tmp_path,
    monkeypatch,
):
    daily = tmp_path / "usage_daily.json"
    online = tmp_path / "online.json"
    meta = tmp_path / "meta.json"
    template = tmp_path / "template.yaml"
    daily.write_text("{}", encoding="utf-8")
    online.write_text("{}", encoding="utf-8")
    meta.write_text(
        '{"settlement_day":1,"cycle_length_days":30,'
        '"cycle_anchor_date":"2026-07-01"}',
        encoding="utf-8",
    )
    template.write_text(
        "proxies: []\nproxy-groups: []\nrules: []\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(ss, "USAGE_DAILY_FILE", daily)
    monkeypatch.setattr(ss, "ONLINE_FILE", online)
    monkeypatch.setattr(ss, "META_FILE", meta)
    monkeypatch.setattr(ss, "TEMPLATE_FILE", template)
    monkeypatch.setattr(ss, "local_now", lambda: NOW)

    page = ss.render_user_panel(
        "panel.test",
        "https://panel.test",
        "alice",
        "secret-token",
        {
            "sub_token": "secret-token",
            "monthly_quota_bytes": 1024,
            "max_devices": 2,
        },
        session_auth=True,
    )
    audit = _assert_valid_outline(page, [1, 2, 2, 2, 2, 2, 2, 2])

    assert [heading["text"] for heading in audit.headings] == [
        "用户面板",
        "流量进度",
        "快速导入",
        "通用模板与我的规则",
        "我的规则",
        "近 30 天用量趋势",
        "订阅链接",
        "登录面板地址",
    ]


def test_section_title_css_resets_heading_user_agent_styles():
    styles = (ROOT / "hysteria" / "admin.css").read_text(encoding="utf-8")
    match = re.search(
        r"^\.section-title \{(?P<body>[^}]*)\}",
        styles,
        flags=re.MULTILINE,
    )

    assert match is not None
    declarations = match.group("body")
    for declaration in (
        "margin: 0;",
        "color: var(--text-strong);",
        "font-family: inherit;",
        "font-size: inherit;",
        "font-weight: 680;",
        "font-variant-numeric: tabular-nums;",
        "letter-spacing: normal;",
        "line-height: inherit;",
    ):
        assert declaration in declarations
    assert ".chart-card > .section-title { font-size: 13px; }" in styles
