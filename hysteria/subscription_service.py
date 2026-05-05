#!/usr/bin/env python3
import html
import base64
import hashlib
import hmac
import json
import fcntl
import os
import re
import secrets
import shutil
import subprocess
import time
import uuid
import urllib.request

import alerts
import user_compat
import xray_config
from contextlib import contextmanager
from datetime import datetime, timedelta
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

USERS_FILE = Path('/root/hysteria/users.json')
USAGE_FILE = Path('/root/hysteria/state/usage.json')
USAGE_DAILY_FILE = Path('/root/hysteria/state/usage_daily.json')
ONLINE_FILE = Path('/root/hysteria/state/online.json')
META_FILE = Path('/root/hysteria/subscription_meta.json')
TEMPLATE_FILE = Path('/root/hysteria/template.yaml')
SESSIONS_FILE = Path('/root/hysteria/state/panel_sessions.json')
RESET_LOG_FILE = Path('/root/hysteria/state/usage_reset.log')
USAGE_LOCK_FILE = Path('/root/hysteria/state/usage.lock')
HY_API_BASE = 'http://127.0.0.1:25413'
HY_API_SECRET = '__HY_API_SECRET__'


DISPLAY_MULTIPLIER = 2.28


def hy_kick(usernames):
    """Force-disconnect active hysteria sessions for the given usernames."""
    if not usernames:
        return
    try:
        body = json.dumps(list(usernames)).encode('utf-8')
        req = urllib.request.Request(
            f'{HY_API_BASE}/kick',
            data=body,
            headers={'Authorization': HY_API_SECRET, 'Content-Type': 'application/json'},
            method='POST',
        )
        with urllib.request.urlopen(req, timeout=3):
            return
    except Exception:
        pass
LISTEN = ('127.0.0.1', 8081)
SESSION_TTL = 86400

_STATIC_DIR = Path(__file__).resolve().parent
BASE_CSS_BYTES = (_STATIC_DIR / 'admin.css').read_bytes()
BASE_CSS_ETAG = '"' + hashlib.sha1(BASE_CSS_BYTES).hexdigest()[:16] + '"'
ADMIN_POLL_JS_BYTES = (_STATIC_DIR / 'admin_poll.js').read_bytes()
ADMIN_POLL_JS_ETAG = '"' + hashlib.sha1(ADMIN_POLL_JS_BYTES).hexdigest()[:16] + '"'


def load_json(path, default):
    try:
        return json.loads(path.read_text(encoding='utf-8'))
    except Exception:
        return default


_JSON_CACHE = {}


def load_json_cached(path, default, ttl=2.0):
    """Cache JSON file reads keyed on (path, mtime). Cleared automatically when the file mtime changes."""
    try:
        mt = path.stat().st_mtime
    except OSError:
        return default
    key = str(path)
    now = time.monotonic()
    hit = _JSON_CACHE.get(key)
    if hit and hit[0] == mt and (now - hit[1]) < ttl:
        return hit[2]
    data = load_json(path, default)
    _JSON_CACHE[key] = (mt, now, data)
    return data


def save_json(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=True, indent=2) + "\n", encoding='utf-8')


@contextmanager
def usage_lock():
    USAGE_LOCK_FILE.parent.mkdir(parents=True, exist_ok=True)
    with USAGE_LOCK_FILE.open('a+', encoding='utf-8') as f:
        fcntl.flock(f.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(f.fileno(), fcntl.LOCK_UN)


def parse_int_field(raw, default, min_value, max_value):
    try:
        value = int(str(raw).strip())
    except Exception:
        return default
    return max(min_value, min(max_value, value))


def sanitize_host(raw_host):
    h = (raw_host or '').strip()
    if not h:
        return '127.0.0.1'
    if ',' in h:
        h = h.split(',', 1)[0].strip()
    if '/' in h or '\\' in h or '@' in h:
        return '127.0.0.1'
    if h.count(':') <= 1 and ':' in h:
        name, port = h.rsplit(':', 1)
        if name and port.isdigit() and 1 <= int(port) <= 65535:
            h = name
    allowed = set('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-[]:')
    if any(ch not in allowed for ch in h):
        return '127.0.0.1'
    return h or '127.0.0.1'


def safe_base_url(host, forwarded_proto):
    scheme = (forwarded_proto or 'http').split(',')[0].strip().lower()
    if scheme not in ('http', 'https'):
        scheme = 'http'
    return f'{scheme}://{host}'


def _b64url_nopad(data):
    return base64.urlsafe_b64encode(data).decode('ascii').rstrip('=')


def hash_secret(secret):
    salt = secrets.token_bytes(16)
    rounds = 200000
    digest = hashlib.pbkdf2_hmac('sha256', secret.encode('utf-8'), salt, rounds)
    return f'pbkdf2_sha256${rounds}${_b64url_nopad(salt)}${_b64url_nopad(digest)}'


def migrate_plaintext_passwords():
    users = load_json(USERS_FILE, {})
    changed = False
    for _, cfg in users.items():
        plain = str(cfg.get('password') or '')
        if plain:
            cfg['password_hash'] = hash_secret(plain)
            cfg.pop('password', None)
            changed = True
        if cfg.get('password') is not None:
            cfg.pop('password', None)
            changed = True
    if changed:
        save_json(USERS_FILE, users)


def ensure_meta():
    meta = load_json(META_FILE, {})
    changed = False
    if not meta.get('admin_token'):
        meta['admin_token'] = secrets.token_urlsafe(24)
        changed = True
    if not meta.get('admin_user'):
        meta['admin_user'] = 'admin'
        changed = True
    if not meta.get('admin_pass') and not meta.get('admin_pass_hash'):
        meta['admin_pass_hash'] = hash_secret(secrets.token_urlsafe(12))
        changed = True
    if changed:
        save_json(META_FILE, meta)
    return meta


def migrate_admin_password():
    meta = load_json(META_FILE, {})
    plain = str(meta.get('admin_pass') or '')
    if plain:
        meta['admin_pass_hash'] = hash_secret(plain)
        del meta['admin_pass']
        save_json(META_FILE, meta)


def month_key():
    """Billing cycle resets on the 21st. Before the 21st belongs to the previous cycle."""
    now = datetime.now()
    if now.day >= 21:
        return now.strftime('%Y-%m')
    first = now.replace(day=1)
    prev = first - timedelta(days=1)
    return prev.strftime('%Y-%m')


def usage_for_user(username, usage_month=None):
    if usage_month is None:
        usage_month = load_json(USAGE_FILE, {}).get(month_key(), {})
    current = usage_month.get(username, 0)
    if isinstance(current, dict):
        tx = int(current.get('tx', 0))
        rx = int(current.get('rx', 0))
        total = int(current.get('total', tx + rx))
        return tx, rx, total
    total = int(current or 0)
    return 0, total, total


def scaled_usage_for_user(username, usage_month=None):
    tx, rx, total = usage_for_user(username, usage_month)
    m = DISPLAY_MULTIPLIER
    return int(tx * m), int(rx * m), int(total * m)


def user_total_quota(user_cfg):
    return int(user_cfg.get('monthly_quota_bytes', 0) or 0)


def build_yaml(username, auth_secret):
    if not TEMPLATE_FILE.exists():
        return ''
    text = TEMPLATE_FILE.read_text(encoding='utf-8')
    text = re.sub(
        r'(?m)^(\s*password:\s*).*$',
        lambda m: f'{m.group(1)}{username}:{auth_secret}',
        text,
        count=1,
    )
    users = load_json(USERS_FILE, {})
    vless_uuid = str((users.get(username) or {}).get('vless_uuid') or '').strip()
    if vless_uuid:
        text = re.sub(
            r'(?m)^(\s*uuid:\s*).*$',
            lambda m: f'{m.group(1)}{vless_uuid}',
            text,
        )
    return text


def fmt_bytes(num):
    n = float(max(0, int(num)))
    units = ['B', 'KB', 'MB', 'GB', 'TB']
    idx = 0
    while n >= 1024 and idx < len(units) - 1:
        n /= 1024.0
        idx += 1
    return f"{n:.2f} {units[idx]}"


def pct(used, total):
    if total <= 0:
        return 0.0
    return min(100.0, max(0.0, used * 100.0 / total))


def verify_secret(plain, stored_hash):
    """Verify a plaintext value against a pbkdf2 hash."""
    try:
        _, rounds_s, salt_b64, digest_b64 = stored_hash.split('$')
        rounds = int(rounds_s)
        salt = base64.urlsafe_b64decode(salt_b64 + '==')
        expected = base64.urlsafe_b64decode(digest_b64 + '==')
        candidate = hashlib.pbkdf2_hmac('sha256', plain.encode('utf-8'), salt, rounds)
        return hmac.compare_digest(candidate, expected)
    except Exception:
        return False


# In-memory login failure tracker: {ip: [timestamp, ...]}
_login_failures: dict = {}
_LOGIN_MAX = 3        # max failures
_LOGIN_WINDOW = 3600  # seconds (1 hour)


def _is_rate_limited(ip):
    now = time.time()
    times = [t for t in _login_failures.get(ip, []) if now - t < _LOGIN_WINDOW]
    _login_failures[ip] = times
    return len(times) >= _LOGIN_MAX


def _record_failure(ip):
    _login_failures.setdefault(ip, []).append(time.time())


def _clear_failures(ip):
    _login_failures.pop(ip, None)


def check_user_token(user, token):
    users = load_json(USERS_FILE, {})
    cfg = users.get(user)
    if not cfg:
        return None
    expected = str(cfg.get('sub_token') or '')
    if not token or not hmac.compare_digest(token, expected):
        return None
    return cfg


def parse_cookies(handler):
    raw = handler.headers.get('Cookie', '')
    ck = SimpleCookie()
    try:
        ck.load(raw)
    except Exception:
        return {}
    return {k: v.value for k, v in ck.items()}


def get_sessions():
    sessions = load_json(SESSIONS_FILE, {})
    now = int(time.time())
    alive = {}
    for sid, info in sessions.items():
        exp = int(info.get('exp', 0))
        if exp > now:
            alive[sid] = info
    if alive != sessions:
        save_json(SESSIONS_FILE, alive)
    return alive


def create_session(username='admin'):
    sessions = get_sessions()
    sid = secrets.token_urlsafe(24)
    sessions[sid] = {'user': username, 'exp': int(time.time()) + SESSION_TTL}
    save_json(SESSIONS_FILE, sessions)
    return sid


def delete_session(sid):
    if not sid:
        return
    sessions = get_sessions()
    if sid in sessions:
        del sessions[sid]
        save_json(SESSIONS_FILE, sessions)


def is_logged_in(handler):
    q = parse_qs(urlparse(handler.path).query)
    token = (q.get('token') or [''])[0]
    meta = ensure_meta()
    admin_token = str(meta.get('admin_token') or '')
    if token and hmac.compare_digest(token, admin_token):
        return True
    sid = parse_cookies(handler).get('sid', '')
    sessions = get_sessions()
    return sid in sessions


def html_page(title, body, body_class=''):
    cls = f' class="{body_class}"' if body_class else ''
    return (
        f'<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">'
        f'<meta name="viewport" content="width=device-width,initial-scale=1">'
        f'<meta name="color-scheme" content="dark">'
        f'<title>{html.escape(title)}</title>'
        f'<link rel="stylesheet" href="/static/style.css">'
        f'</head><body{cls}>{body}</body></html>'
    )


# Inline SVG icons (24×24 stroke icons, sized down via .sidebar-link svg).
_ICONS = {
    'dashboard': '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="7" height="9" rx="1.5"/><rect x="14" y="3" width="7" height="5" rx="1.5"/><rect x="14" y="12" width="7" height="9" rx="1.5"/><rect x="3" y="16" width="7" height="5" rx="1.5"/></svg>',
    'config': '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12.22 2h-.44a2 2 0 0 0-2 2v.18a2 2 0 0 1-1 1.73l-.43.25a2 2 0 0 1-2 0l-.15-.08a2 2 0 0 0-2.73.73l-.22.38a2 2 0 0 0 .73 2.73l.15.1a2 2 0 0 1 1 1.72v.51a2 2 0 0 1-1 1.74l-.15.09a2 2 0 0 0-.73 2.73l.22.38a2 2 0 0 0 2.73.73l.15-.08a2 2 0 0 1 2 0l.43.25a2 2 0 0 1 1 1.73V20a2 2 0 0 0 2 2h.44a2 2 0 0 0 2-2v-.18a2 2 0 0 1 1-1.73l.43-.25a2 2 0 0 1 2 0l.15.08a2 2 0 0 0 2.73-.73l.22-.39a2 2 0 0 0-.73-2.73l-.15-.08a2 2 0 0 1-1-1.74v-.5a2 2 0 0 1 1-1.74l.15-.09a2 2 0 0 0 .73-2.73l-.22-.38a2 2 0 0 0-2.73-.73l-.15.08a2 2 0 0 1-2 0l-.43-.25a2 2 0 0 1-1-1.73V4a2 2 0 0 0-2-2z"/><circle cx="12" cy="12" r="3"/></svg>',
    'rules': '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>',
    'logs': '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="9" y1="13" x2="15" y2="13"/><line x1="9" y1="17" x2="15" y2="17"/></svg>',
    'logout': '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg>',
    'menu': '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="3" y1="6" x2="21" y2="6"/><line x1="3" y1="12" x2="21" y2="12"/><line x1="3" y1="18" x2="21" y2="18"/></svg>',
    'copy': '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>',
    'open': '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/></svg>',
    'back': '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="19" y1="12" x2="5" y2="12"/><polyline points="12 19 5 12 12 5"/></svg>',
    'chart': '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="6" y1="20" x2="6" y2="14"/><line x1="12" y1="20" x2="12" y2="8"/><line x1="18" y1="20" x2="18" y2="11"/><line x1="3" y1="20" x2="21" y2="20"/></svg>',
    'pulse': '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>',
}


def icon(name):
    return _ICONS.get(name, '')


def render_nav(brand, badge):
    return (
        f'<div class="nav"><div class="brand">{html.escape(brand)}</div>'
        f'<span class="badge">{html.escape(badge)}</span></div>'
    )


def render_alert(msg, kind='flash'):
    if not msg:
        return ''
    return f'<div class="{kind}">{html.escape(msg)}</div>'


def render_prefixed_alert(flash, msg_map):
    """Resolve a flash code that may carry an 'err:' prefix and render the alert."""
    if not flash:
        return ''
    is_err = flash.startswith('err:')
    key = flash.removeprefix('err:')
    msg = msg_map.get(key, key)
    return render_alert(msg, 'err' if is_err else 'flash')


def back_to_admin(label='返回管理后台'):
    return f'<a class="btn secondary" href="/admin">{icon("back")}<span>{html.escape(label)}</span></a>'


_SIDEBAR_NAV = [
    ('dashboard', '/admin', '总览', 'dashboard'),
    ('daily', '/admin/daily', '每日流量', 'chart'),
    ('health', '/admin/health', '健康状态', 'pulse'),
    ('config', '/admin/config', '模板配置', 'config'),
    ('rules', '/admin/rules', '路由规则', 'rules'),
    ('logs', '/admin/logs', '清零日志', 'logs'),
]


def render_admin_shell(active, page_title, content, *, badge='', subtitle='', topbar_extra=''):
    """Wrap admin page content in the sidebar + topbar app shell."""
    nav_items = ''.join(
        f'<a href="{href}" class="sidebar-link {"active" if key == active else ""}">'
        f'{icon(icon_name)}<span>{html.escape(label)}</span></a>'
        for key, href, label, icon_name in _SIDEBAR_NAV
    )
    badge_html = f'<span class="badge">{html.escape(badge)}</span>' if badge else ''
    sub_html = f'<small>{html.escape(subtitle)}</small>' if subtitle else ''
    body = f'''<div class="app">
<aside class="sidebar" id="sidebar">
  <div class="sidebar-brand"><span class="logo">H</span><span>Hysteria</span></div>
  <nav class="sidebar-nav">
    <div class="sidebar-section">管理</div>
    {nav_items}
  </nav>
  <div class="sidebar-footer">
    <a href="/logout" class="sidebar-link">{icon("logout")}<span>退出登录</span></a>
  </div>
</aside>
<div class="scrim" id="scrim"></div>
<div class="main">
  <header class="topbar">
    <div class="topbar-inner">
      <div class="row gap-sm">
        <button class="sidebar-toggle" id="sidebar-toggle" type="button" aria-label="切换侧边栏">{icon("menu")}</button>
        <h1 class="page-title">{html.escape(page_title)}{sub_html}</h1>
      </div>
      <div class="topbar-actions">{topbar_extra}{badge_html}</div>
    </div>
  </header>
  <div class="content">{content}</div>
</div>
</div>
<script>
(function() {{
  var sb = document.getElementById('sidebar');
  var sc = document.getElementById('scrim');
  var bt = document.getElementById('sidebar-toggle');
  function close() {{ sb.classList.remove('open'); document.body.classList.remove('sidebar-open'); }}
  bt.addEventListener('click', function() {{ sb.classList.toggle('open'); document.body.classList.toggle('sidebar-open'); }});
  sc.addEventListener('click', close);
  window.addEventListener('resize', function() {{ if (window.innerWidth > 880) close(); }});
}})();
</script>'''
    return html_page(page_title, body, body_class='has-shell')


def flash_text(msg):
    if not msg:
        return ''
    if msg == 'login success':
        return '登录成功'
    if msg.startswith('updated '):
        return f'已更新用户：{msg.split(" ", 1)[1]}'
    if msg.startswith('created '):
        return f'已创建用户：{msg.split(" ", 1)[1]}'
    if msg.startswith('reset usage '):
        return f'已清除用户本月已用流量：{msg.split(" ", 2)[2]}'
    if msg == 'reset usage all':
        return '已清除全部用户本月已用流量'
    if msg.startswith('deleted '):
        return f'已删除用户：{msg.split(" ", 1)[1]}'
    maps = {
        'user not found': '用户不存在',
        'user empty': '用户名不能为空',
        'user_exists_use_reset_token': '用户已存在，请勾选”若用户已存在则重置订阅令牌”后再创建',
    }
    return maps.get(msg, msg)


def render_home(host):
    body = f'''<div class="wrap home-wrap">
<div class="card elev inline-form auth-card" style="text-align:center;">
  <div class="auth-head" style="justify-content:center;border-bottom:0;padding-bottom:6px;margin-bottom:8px;">
    <span class="app-logo lg">H</span>
    <div style="text-align:left;">
      <div class="title">Hysteria</div>
      <div class="sub">管理与订阅控制台</div>
    </div>
  </div>
  <a class="btn full mt-md" href="/login">{icon("logout")}<span>管理员登录</span></a>
</div></div>'''
    return html_page('Hysteria', body)


def render_login(host, msg=''):
    body = f'''<div class="wrap home-wrap">
{render_alert(msg, 'err')}
<div class="card elev inline-form auth-card">
  <div class="auth-head">
    <span class="app-logo">H</span>
    <div>
      <div class="title">管理员登录</div>
      <div class="sub">登录到 <code style="padding:2px 6px;font-size:11.5px;">{html.escape(host)}</code></div>
    </div>
  </div>
  <form method="post" action="/login">
    <label>用户名</label><input name="username" required autofocus autocomplete="username">
    <label class="mt-sm">密码</label><input name="password" type="password" required autocomplete="current-password">
    <div class="row mt-md">
      <button class="btn" type="submit" style="flex:1;justify-content:center;">登录</button>
      <a class="btn secondary" href="/">返回</a>
    </div>
  </form>
</div></div>'''
    return html_page('管理员登录', body)


def render_user_panel(host, base_url, user, token, cfg):
    tx, rx, used = scaled_usage_for_user(user)
    total = user_total_quota(cfg)
    remain = max(total - used, 0) if total > 0 else -1
    online = int(load_json(ONLINE_FILE, {}).get(user, 0))
    percent = pct(used, total)
    cls = 'danger' if percent >= 90 else ''
    sub_path = f'/sub/{user}?token={token}'
    panel_path = f'/panel/{user}?token={token}'
    sub_http = f'{base_url}{sub_path}'
    panel_http = f'{base_url}{panel_path}'
    max_devices_n = int(cfg.get('max_devices', 0) or 0)
    body = f'''<div class="wrap">
<div class="nav">
  <div class="row gap-sm">
    <span class="app-logo">H</span>
    <div>
      <div class="brand" style="font-size:16px;">用户面板</div>
      <div class="small">{html.escape(user)}</div>
    </div>
  </div>
  <span class="badge">{html.escape(host)}</span>
</div>
<div class="grid grid-4">
  <div class="card stat"><div class="k">本月已用</div><div class="v big">{fmt_bytes(used)}</div><div class="accent-bar"></div></div>
  <div class="card stat"><div class="k">总流量</div><div class="v">{fmt_bytes(total)}</div></div>
  <div class="card stat"><div class="k">剩余流量</div><div class="v">{fmt_bytes(remain)}</div></div>
  <div class="card stat"><div class="k">在线设备</div><div class="v">{online} <span class="faint" style="font-size:14px;font-weight:500;">/ {max_devices_n}</span></div></div>
</div>
<div class="card mt-md">
  <div class="row" style="justify-content:space-between;margin-bottom:10px;">
    <div class="k" style="margin:0;">流量进度</div>
    <div class="bold" style="font-variant-numeric:tabular-nums;">{percent:.2f}%</div>
  </div>
  <div class="bar"><div class="fill {cls}" style="width:{percent:.2f}%"></div></div>
  <div class="small mt-sm">上传 {fmt_bytes(tx)} · 下载 {fmt_bytes(rx)}</div>
</div>
<div class="grid grid-2 mt-md">
  <div class="card">
    <div class="k">订阅链接</div>
    <div class="copy-mono"><code id="sub">{html.escape(sub_http)}</code></div>
    <div class="row mt-md">
      <button class="btn" id="copy-sub-btn" type="button">{icon("copy")}<span>复制链接</span></button>
      <a class="btn secondary" href="{html.escape(sub_path)}">{icon("open")}<span>打开订阅</span></a>
    </div>
  </div>
  <div class="card">
    <div class="k">当前面板链接</div>
    <div class="copy-mono"><code>{html.escape(panel_http)}</code></div>
    <div class="row mt-md">
      <a class="btn secondary" href="/">{icon("back")}<span>返回首页</span></a>
    </div>
  </div>
</div>
</div>
<script>
document.getElementById('copy-sub-btn').addEventListener('click', function() {{
  var btn = this;
  var text = document.getElementById('sub').textContent;
  if (!navigator.clipboard) {{ alert('当前环境不支持自动复制，请手动选中链接复制'); return; }}
  navigator.clipboard.writeText(text).then(function() {{
    var label = btn.querySelector('span');
    var prev = label.textContent;
    label.textContent = '已复制 ✓';
    btn.disabled = true;
    setTimeout(function() {{ label.textContent = prev; btn.disabled = false; }}, 1400);
  }}).catch(function() {{ alert('复制失败，请手动复制'); }});
}});
</script>'''
    return html_page(f'{user} 用户面板', body)


def row_form(user, cfg, online, host, base_url, usage_month=None, daily=None):
    tx, rx, used = scaled_usage_for_user(user, usage_month)
    spark_cell = ''
    # NOTE: 30-day sparkline is rendered in 3 places — keep them in sync:
    # (1) here in row_form (initial page); (2) sparkline_svg() emits class="spark";
    # (3) /admin/usage.json sends spark_html, JS finds [data-role="spark"] and sets innerHTML.
    if daily is not None:
        spark_cell = f'<td class="spark-cell" data-role="spark">{sparkline_svg(daily_window_for_user(user, daily, days=30))}</td>'
    total = user_total_quota(cfg)
    max_devices = int(cfg.get('max_devices', 0) or 0)
    quota_gb = int(round(total / 1024 / 1024 / 1024)) if total > 0 else 0
    panel = f'{base_url}/panel/{user}?token={cfg.get("sub_token", "")}'
    sub_http = f'{base_url}/sub/{user}?token={cfg.get("sub_token", "")}'
    metered = user_compat.is_metered(cfg)
    guest_checked = 'checked' if metered else ''
    percent = pct(used, total)
    bar_cls = 'danger' if percent >= 90 else ''
    bar_w = f'{percent:.1f}'
    user_esc = html.escape(user)
    guest_badge = '<span class="badge badge-info">访客</span>' if metered else ''
    guest_preview = ' · 访客' if metered else ''
    summary_preview = f'<span class="summary-preview">{quota_gb or 150} GB · {max_devices or 2} 设备{guest_preview}</span>'
    return f'''<tr data-user="{user_esc}">
<td>
  <div class="row gap-sm" style="flex-wrap:nowrap;">
    <div class="user-avatar">{html.escape(user[:1].upper())}</div>
    <div style="min-width:0;">
      <div class="bold">{user_esc} {guest_badge}</div>
      <div class="small">在线 <span data-role="online">{online.get(user, 0)}</span> / {max_devices} 设备</div>
    </div>
  </div>
</td>
{spark_cell}
<td>
  <div class="row" style="justify-content:space-between;margin-bottom:4px;">
    <span class="bold" data-role="used">{fmt_bytes(used)}</span>
    <span class="small">/ {fmt_bytes(total)}</span>
  </div>
  <div class="mini-bar"><div class="mini-fill {bar_cls}" data-role="bar" style="width:{bar_w}%"></div></div>
  <div class="small mt-sm" data-role="detail">{percent:.1f}% · ↑{fmt_bytes(tx)} ↓{fmt_bytes(rx)}</div>
</td>
<td>
<details>
<summary>编辑套餐{summary_preview}</summary>
<form method="post" action="/admin/update" class="inline-form">
<input type="hidden" name="user" value="{user_esc}">
<label>兼容连接密码（可选）</label><input name="password" type="password" placeholder="留空则不修改">
<label class="mt-sm">设备数上限</label><input name="max_devices" type="number" min="1" value="{max_devices or 2}">
<label class="mt-sm">月流量上限 (GB)</label><input name="quota_gb" type="number" min="1" value="{quota_gb or 150}">
<label class="switch mt-sm"><input type="checkbox" name="guest" {guest_checked}>客人用户（仅做标记，不影响认证）</label>
<button class="btn mt-md" type="submit">保存</button>
</form>
</details>
<div class="row gap-sm mt-sm">
  <form method="post" action="/admin/reset-usage" class="inline-form-row">
    <input type="hidden" name="user" value="{user_esc}">
    <button class="btn ghost btn-sm" type="submit">清流量</button>
  </form>
  <form method="post" action="/admin/delete" class="inline-form-row" data-action="delete-user">
    <input type="hidden" name="user" value="{user_esc}">
    <button class="btn danger-btn btn-sm" type="submit">删除</button>
  </form>
</div>
</td>
<td class="link-cell">
  <div class="link-row">
    <a href="{html.escape(panel)}" target="_blank" rel="noopener">{icon("dashboard")}<span>面板</span></a>
    <button type="button" class="btn ghost btn-sm copy-link" data-copy="{html.escape(panel)}" title="复制面板链接">{icon("copy")}</button>
  </div>
  <div class="link-row">
    <a href="{html.escape(sub_http)}" target="_blank" rel="noopener">{icon("open")}<span>订阅</span></a>
    <button type="button" class="btn ghost btn-sm copy-link" data-copy="{html.escape(sub_http)}" title="复制订阅链接">{icon("copy")}</button>
  </div>
</td>
</tr>'''


def render_admin(host, base_url, flash=''):
    users = load_json(USERS_FILE, {})
    online = load_json(ONLINE_FILE, {})
    usage_month = load_json(USAGE_FILE, {}).get(month_key(), {})
    daily = load_json(USAGE_DAILY_FILE, {})
    total_used = sum(scaled_usage_for_user(u, usage_month)[2] for u in users)
    alert = render_alert(flash_text(flash))
    rows = ''.join(row_form(u, cfg, online, host, base_url, usage_month, daily) for u, cfg in users.items()) \
        or '<tr><td colspan="5" class="empty">暂无用户，使用下方表单创建第一个用户</td></tr>'
    content = f'''{alert}
<div class="grid grid-3">
  <div class="card stat"><div class="k">本月总流量</div><div class="v big" id="total-used">{fmt_bytes(total_used)}</div><div class="accent-bar"></div></div>
  <div class="card stat"><div class="k">统计月份</div><div class="v">{month_key()}</div></div>
  <div class="card stat">
    <div class="k">快速操作</div>
    <form method="post" action="/admin/reset-usage-all" data-action="reset-all" style="margin:6px 0 0;">
      <button class="btn secondary btn-sm" type="submit">一键清空本月已用</button>
    </form>
  </div>
</div>
<div class="card mt-md scroll-x" style="padding:0;overflow:hidden;">
  <div class="row" style="padding:14px 18px;justify-content:space-between;border-bottom:1px solid var(--line);">
    <div class="bold">用户列表</div>
    <div class="small">实时刷新 · 每 5 秒</div>
  </div>
  <table class="table"><thead><tr><th style="padding-left:18px;">用户</th><th>30 天趋势</th><th>本月用量</th><th>操作</th><th style="padding-right:18px;">链接</th></tr></thead><tbody>{rows}</tbody></table>
</div>
<div class="card mt-md">
  <details class="summary-muted">
    <summary>新增用户</summary>
    <form method="post" action="/admin/add" class="inline-form mt-md">
      <div class="grid grid-3">
        <div><label>用户名</label><input name="user" required></div>
        <div><label>兼容连接密码（可选）</label><input name="password" type="password" placeholder="默认仅用订阅 token 认证"></div>
        <div><label>月流量上限 (GB)</label><input name="quota_gb" type="number" value="150" min="1"></div>
      </div>
      <div class="row mt-md">
        <label class="switch"><input type="checkbox" name="guest" checked>客人用户</label>
        <label class="switch"><input type="checkbox" name="reset_token">已存在则重置订阅令牌</label>
      </div>
      <button class="btn mt-md" type="submit">创建用户</button>
    </form>
  </details>
</div>
<script>
<script src="/static/admin-poll.js" defer></script>
</script>'''
    return render_admin_shell('dashboard', '总览', content,
                              badge=f'{len(users)} 个用户',
                              subtitle=f'{host} · 计费月份 {month_key()}')


def _action_label(action):
    return {'reset_usage_user': '清除用户流量', 'reset_usage_all': '清空全部流量'}.get(action, action)


DAILY_RETENTION_DAYS = 30


def _scale_daily_entry(entry):
    """Scale a raw daily usage entry by DISPLAY_MULTIPLIER, returning (tx, rx, total)."""
    if not entry:
        return 0, 0, 0
    if isinstance(entry, dict):
        tx = int(entry.get('tx', 0))
        rx = int(entry.get('rx', 0))
        total = int(entry.get('total', tx + rx))
    else:
        total = int(entry or 0)
        tx, rx = 0, total
    m = DISPLAY_MULTIPLIER
    return int(tx * m), int(rx * m), int(total * m)


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
    Width/height come from the viewBox so the caller's CSS can size the SVG.

    Output contract (relied on by the admin dashboard's polling JS):
    - Outermost element is `<svg class="spark" ...>` — JS uses this class.
    - Each non-empty bar is `<rect class="spark-bar [today]" ...>` — CSS uses these.
    Changing these class names requires updating row_form's data-role="spark"
    cell and the tick() handler in render_admin's <script> block.
    """
    n = len(values)
    label = f'{n} 天趋势' if n else ''
    if n == 0:
        return f'<svg class="spark" viewBox="0 0 0 {height}" aria-hidden="true"></svg>'
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
    return (f'<svg class="spark" viewBox="0 0 {width} {height}" '
            f'aria-label="{html.escape(label)}">'
            f'{"".join(parts)}</svg>')


def render_daily_usage(host, days=14):
    days = max(1, min(DAILY_RETENTION_DAYS, int(days)))
    users = load_json(USERS_FILE, {})
    daily = load_json(USAGE_DAILY_FILE, {})

    today = datetime.now().date()
    today_key = today.strftime('%Y-%m-%d')
    window = [(today - timedelta(days=i)).strftime('%Y-%m-%d') for i in reversed(range(days))]
    weekday_labels = ['一', '二', '三', '四', '五', '六', '日']

    per_user = {}
    user_window_total = {}
    day_totals = {dk: 0 for dk in window}
    overall_total = 0
    for uid in users.keys():
        per_user[uid] = {}
        utot = 0
        for dk in window:
            tx, rx, tot = _scale_daily_entry((daily.get(dk) or {}).get(uid))
            per_user[uid][dk] = (tx, rx, tot)
            utot += tot
            day_totals[dk] += tot
            overall_total += tot
        user_window_total[uid] = utot

    sorted_uids = sorted(users.keys(), key=lambda u: user_window_total[u], reverse=True)

    col_headers = []
    for dk in window:
        wd = weekday_labels[datetime.strptime(dk, '%Y-%m-%d').weekday()]
        cls = ' day-today' if dk == today_key else ''
        col_headers.append(
            f'<th class="day-col{cls}" title="{dk}">'
            f'<div class="day-mmdd">{dk[5:]}</div>'
            f'<div class="day-weekday">周{wd}</div></th>'
        )

    rows = []
    for uid in sorted_uids:
        cells = []
        for dk in window:
            tx, rx, tot = per_user[uid][dk]
            today_cls = ' day-today' if dk == today_key else ''
            if tot <= 0:
                cells.append(f'<td class="day-cell empty-day{today_cls}">—</td>')
            else:
                title = f'{dk} · ↑ {fmt_bytes(tx)} · ↓ {fmt_bytes(rx)}'
                cells.append(
                    f'<td class="day-cell{today_cls}" title="{html.escape(title)}">{fmt_bytes(tot)}</td>'
                )
        utot = user_window_total[uid]
        utot_disp = fmt_bytes(utot) if utot > 0 else '—'
        rows.append(
            f'<tr><th class="user-col" scope="row">{html.escape(uid)}</th>'
            f'<td class="num user-total">{utot_disp}</td>'
            f'{"".join(cells)}</tr>'
        )

    if not rows:
        rows.append(f'<tr><td colspan="{2 + days}" class="empty">暂无用户</td></tr>')

    foot_cells = []
    peak_day = None
    peak_val = 0
    for dk in window:
        v = day_totals[dk]
        if v > peak_val:
            peak_val = v
            peak_day = dk
        today_cls = ' day-today' if dk == today_key else ''
        foot_cells.append(
            f'<td class="day-cell{today_cls}">{fmt_bytes(v) if v else "—"}</td>'
        )

    today_total = day_totals.get(today_key, 0)
    avg_per_day = int(overall_total / days) if days else 0

    switcher = ''.join(
        f'<a class="btn btn-sm {"primary" if d == days else "secondary"}" '
        f'href="/admin/daily?days={d}">{d} 天</a>'
        for d in (7, 14, 30)
    )

    earliest_recorded = min(daily.keys()) if daily else '—'

    content = f'''<div class="grid grid-4">
  <div class="card stat"><div class="k">{days} 天总流量</div><div class="v big">{fmt_bytes(overall_total)}</div><div class="accent-bar"></div></div>
  <div class="card stat"><div class="k">今日已用</div><div class="v">{fmt_bytes(today_total)}</div><div class="small">{today_key}</div></div>
  <div class="card stat"><div class="k">日均</div><div class="v">{fmt_bytes(avg_per_day)}</div></div>
  <div class="card stat"><div class="k">峰值日</div><div class="v">{fmt_bytes(peak_val) if peak_val else "—"}</div><div class="small">{peak_day or "—"}</div></div>
</div>
<div class="card mt-md" style="padding:14px 18px;">
  <div class="row" style="justify-content:space-between;flex-wrap:wrap;gap:10px;">
    <div>
      <div class="bold">每日流量明细 · 最近 {days} 天</div>
      <div class="small">最早数据：{earliest_recorded} · 保留 {DAILY_RETENTION_DAYS} 天</div>
    </div>
    <div class="row gap-sm">{switcher}</div>
  </div>
</div>
<div class="card mt-md scroll-x" style="padding:0;overflow:auto;">
  <table class="table daily-table">
    <thead><tr>
      <th class="user-col" style="padding-left:18px;">用户</th>
      <th class="num">{days} 天累计</th>
      {"".join(col_headers)}
    </tr></thead>
    <tbody>{"".join(rows)}</tbody>
    <tfoot><tr>
      <th class="user-col" style="padding-left:18px;">合计</th>
      <td class="num user-total">{fmt_bytes(overall_total) if overall_total else "—"}</td>
      {"".join(foot_cells)}
    </tr></tfoot>
  </table>
</div>'''
    return render_admin_shell('daily', '每日流量', content,
                              badge=f'最近 {days} 天',
                              subtitle=f'{host} · 滚动窗口 {DAILY_RETENTION_DAYS} 天')


def probe_cron_heartbeat():
    """How long since the cron tick last wrote usage.json. Stale if >120s."""
    try:
        mt = USAGE_FILE.stat().st_mtime
        age = int(time.time() - mt)
        return {'ok': age < 120, 'label': f'{age} 秒前'}
    except Exception:
        return {'ok': False, 'label': '未知'}


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
        # Force C locale so openssl emits English month names that strptime can parse.
        env = {**os.environ, 'LC_ALL': 'C'}
        out = subprocess.run(['openssl', 'x509', '-enddate', '-noout', '-in', str(p)],
                             capture_output=True, text=True, timeout=3, env=env)
        if out.returncode != 0 or '=' not in out.stdout:
            return {'ok': False, 'label': '未知'}
        end_str = out.stdout.split('=', 1)[1].strip()
        end_dt = datetime.strptime(end_str, '%b %d %H:%M:%S %Y %Z')
        days = (end_dt - datetime.utcnow()).days
        return {'ok': days > 14, 'label': f'{days} 天剩余'}
    except Exception:
        return {'ok': False, 'label': '未知'}


def probe_online():
    try:
        data = load_json(ONLINE_FILE, {})
        n = sum(int(v) for v in data.values())
        return {'ok': True, 'label': f'{n} 在线'}
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
    return render_admin_shell('health', '健康状态', content,
                              badge=host, subtitle='30 秒自动刷新')


def render_reset_logs(host, limit=300):
    from collections import deque
    rows = []
    try:
        with RESET_LOG_FILE.open('r', encoding='utf-8') as f:
            raw_lines = list(deque(f, maxlen=limit))
    except FileNotFoundError:
        raw_lines = []
    for line in reversed(raw_lines):
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
        except Exception:
            continue
        t = html.escape(str(entry.get('time', '')))
        actor = html.escape(str(entry.get('actor', '')))
        ip = html.escape(str(entry.get('ip', '')))
        action = html.escape(_action_label(str(entry.get('action', ''))))
        target = html.escape(str(entry.get('target', '')))
        month = html.escape(str(entry.get('month', '')))
        before = entry.get('before', {})
        after = entry.get('after', {})
        if isinstance(before, dict) and 'total' in before:
            detail = f'{fmt_bytes(before.get("total", 0))} → {fmt_bytes(after.get("total", 0))}'
        else:
            detail = ''
        rows.append(f'<tr><td class="small">{t}</td><td>{actor}</td><td class="small">{ip}</td>'
                    f'<td>{action}</td><td>{target}</td><td class="small">{month}</td>'
                    f'<td class="small">{html.escape(detail)}</td></tr>')
    table = ''.join(rows) if rows else f'<tr><td colspan="7" class="empty">暂无日志记录</td></tr>'
    content = f'''<div class="card scroll-x" style="padding:0;overflow:hidden;">
  <div class="row" style="padding:14px 18px;justify-content:space-between;border-bottom:1px solid var(--line);">
    <div class="bold">最近清零记录</div>
    <div class="small">最近 {limit} 条 · 最新在上</div>
  </div>
  <table class="table"><thead><tr><th style="padding-left:18px;">时间</th><th>操作人</th><th>IP</th><th>操作</th><th>目标</th><th>月份</th><th style="padding-right:18px;">流量变化</th></tr></thead>
  <tbody>{table}</tbody></table>
</div>'''
    return render_admin_shell('logs', '清零日志', content, badge=host)


def _load_yaml_file(path):
    import yaml
    text = path.read_text(encoding='utf-8')
    return yaml.safe_load(text) or {}


def _dump_yaml(data):
    import yaml
    return yaml.dump(data, allow_unicode=True, default_flow_style=False, sort_keys=False)


def load_template_config():
    """Load the subscription template as a dict. Returns {} if missing."""
    if not TEMPLATE_FILE.exists():
        return {}
    return _load_yaml_file(TEMPLATE_FILE)


def save_template_config(data):
    """Save dict to the subscription template."""
    TEMPLATE_FILE.write_text(_dump_yaml(data), encoding='utf-8')


_CONFIG_FLASH = {
    'saved': '模板已保存，所有用户下次拉订阅将使用新配置',
    'invalid_json': 'JSON 格式错误，请检查语法',
    'empty': '配置内容不能为空',
    'load_failed': '加载配置文件失败',
}


def render_config_editor(host, flash=''):
    alert = render_prefixed_alert(flash, _CONFIG_FLASH)

    try:
        data = load_template_config()
        config_json = json.dumps(data, ensure_ascii=False, indent=2)
    except Exception as e:
        config_json = '{}'
        if not flash:
            alert = render_alert(f'加载配置失败: {e}', 'err')

    content = f'''{alert}
<div class="card mb-md">
  <div class="small mb-sm">编辑订阅模板（JSON 格式）。保存后所有用户下次拉订阅即获得新配置，每个用户的密码和 UUID 由服务端从 users.json 自动注入。</div>
  <div class="small">模板文件：<code>{html.escape(str(TEMPLATE_FILE))}</code></div>
</div>
<div class="card">
  <form method="post" action="/admin/config/save" id="configForm">
    <div id="jsonError" class="json-error"></div>
    <textarea name="config_json" id="configEditor" class="code-area code-tall" spellcheck="false">{html.escape(config_json)}</textarea>
    <div class="row mt-md">
      <button class="btn" type="submit">保存模板</button>
      <button class="btn secondary" type="button" id="cfgFormat">格式化 JSON</button>
      <button class="btn ghost" type="button" id="cfgCollapse">折叠/展开</button>
    </div>
  </form>
</div>
<script>
(function(){{
  var editor = document.getElementById('configEditor');
  var errorDiv = document.getElementById('jsonError');
  function showError(msg) {{ errorDiv.textContent=msg; errorDiv.classList.add('visible'); editor.classList.add('invalid'); }}
  function clearError() {{ errorDiv.classList.remove('visible'); editor.classList.remove('invalid'); }}
  function validateJson() {{
    try {{ JSON.parse(editor.value); clearError(); return true; }}
    catch(e) {{ showError('JSON 语法错误: ' + e.message); return false; }}
  }}
  document.getElementById('cfgFormat').addEventListener('click', function() {{
    try {{ editor.value = JSON.stringify(JSON.parse(editor.value), null, 2); clearError(); }}
    catch(e) {{ showError('JSON 语法错误: ' + e.message); }}
  }});
  document.getElementById('cfgCollapse').addEventListener('click', function() {{
    try {{
      var obj = JSON.parse(editor.value);
      var isCompact = !editor.value.includes('\\n');
      editor.value = isCompact ? JSON.stringify(obj, null, 2) : JSON.stringify(obj);
    }} catch(e) {{}}
  }});
  editor.addEventListener('keydown', function(e) {{
    if (e.key !== 'Tab') return;
    e.preventDefault();
    var s=this.selectionStart, t=this.selectionEnd;
    this.value = this.value.substring(0,s) + '  ' + this.value.substring(t);
    this.selectionStart = this.selectionEnd = s + 2;
  }});
  var validateTimer;
  editor.addEventListener('input', function() {{
    clearTimeout(validateTimer);
    validateTimer = setTimeout(validateJson, 500);
  }});
  document.getElementById('configForm').addEventListener('submit', function(e) {{
    if (!validateJson()) {{ e.preventDefault(); alert('JSON 格式错误，请修正后再保存'); }}
  }});
}})();
</script>'''
    return render_admin_shell('config', '订阅模板配置', content, badge=host)


def load_template_rules():
    """Load rules list from the subscription template."""
    import yaml
    if not TEMPLATE_FILE.exists():
        return []
    text = TEMPLATE_FILE.read_text(encoding='utf-8')
    data = yaml.safe_load(text)
    return data.get('rules', [])


def save_template_rules(rules):
    """Replace the rules section in the subscription template."""
    text = TEMPLATE_FILE.read_text(encoding='utf-8')
    lines = text.split('\n')
    start = None
    end = len(lines)
    for i, line in enumerate(lines):
        if start is None and re.match(r'^rules\s*:', line):
            start = i
        elif start is not None and line and not line[0].isspace() and not line.startswith('#'):
            end = i
            break
    new_rule_lines = ['# 6. 规则', 'rules:']
    for r in rules:
        new_rule_lines.append(f"  - '{r}'")
    if start is None:
        result = lines + [''] + new_rule_lines
    else:
        cut = start - 1 if start > 0 and lines[start - 1].startswith('#') else start
        result = lines[:cut] + new_rule_lines + lines[end:]
    TEMPLATE_FILE.write_text('\n'.join(result) + ('\n' if not result[-1].endswith('\n') else ''), encoding='utf-8')


def _parse_clash_rule(rule_str):
    """Parse 'TYPE,value,action[,extra]' into display parts."""
    parts = rule_str.split(',', 2)
    if len(parts) < 2:
        return rule_str, '', '', ''
    rtype = parts[0]
    if rtype == 'MATCH':
        return 'MATCH', '全部', parts[1] if len(parts) > 1 else '', ''
    if len(parts) == 2:
        return rtype, parts[1], '', ''
    # parts[2] may be "action" or "action,no-resolve"
    rest = parts[2].split(',', 1)
    action = rest[0]
    extra = rest[1] if len(rest) > 1 else ''
    return rtype, parts[1], action, extra


_RULE_TYPE_LABELS = {
    'DOMAIN-SUFFIX': '域名后缀', 'DOMAIN-KEYWORD': '域名关键词', 'DOMAIN': '完整域名',
    'IP-CIDR': 'IP 段', 'IP-CIDR6': 'IPv6 段', 'GEOIP': 'GeoIP',
    'RULE-SET': '规则集', 'MATCH': '兜底',
}
_ACTION_LABELS = {'DIRECT': '直连', 'REJECT': '拦截'}


_RULES_FLASH = {
    'rule_added': '规则已添加，客户端更新订阅后生效',
    'rule_deleted': '规则已删除，客户端更新订阅后生效',
    'pattern_empty': '匹配值不能为空',
    'invalid_rule_type': '无效的规则类型',
    'invalid_index': '无效的规则序号',
    'index_out_of_range': '规则序号超出范围',
    'raw_saved': '全部规则已保存，客户端更新订阅后生效',
    'raw_empty': '规则不能为空',
}


def render_rules(host, flash=''):
    rules = load_template_rules()
    alert = render_prefixed_alert(flash, _RULES_FLASH)

    rows = ''
    for i, rule_str in enumerate(rules):
        rtype, val, action, extra = _parse_clash_rule(rule_str)
        type_label = _RULE_TYPE_LABELS.get(rtype, rtype)
        action_label = _ACTION_LABELS.get(action, action)
        extra_tag = f' <span class="small">({html.escape(extra)})</span>' if extra else ''
        is_system = rtype in ('RULE-SET', 'GEOIP', 'MATCH')
        del_btn = ''
        if not is_system:
            del_btn = (
                f'<form method="post" action="/admin/rules/delete" class="inline-form-row" data-action="delete-rule">'
                f'<input type="hidden" name="index" value="{i}">'
                f'<button class="btn danger-btn btn-sm" type="submit">删除</button>'
                f'</form>'
            )
        tr_class = ' class="system-row"' if is_system else ''
        rows += (
            f'<tr{tr_class}><td>{i + 1}</td><td>{html.escape(type_label)}</td>'
            f'<td class="break">{html.escape(val)}</td>'
            f'<td>{html.escape(action_label)}{extra_tag}</td>'
            f'<td>{del_btn}</td></tr>'
        )

    rules_text = html.escape('\n'.join(rules))

    content = f'''{alert}
<div class="card mb-md">
  <div class="small">自定义规则优先级高于规则集，从上到下依次匹配。灰色行为内置规则集，不可删除。</div>
</div>
<div class="card scroll-x" style="padding:0;overflow:hidden;">
  <table class="table"><thead><tr><th style="padding-left:18px;width:50px;">#</th><th>类型</th><th>匹配</th><th>动作</th><th style="padding-right:18px;width:90px;">操作</th></tr></thead>
  <tbody>{rows or '<tr><td colspan="5" class="empty">暂无规则</td></tr>'}</tbody></table>
</div>

<div class="card mt-md">
  <div class="bold mb-md">添加自定义规则</div>
  <form method="post" action="/admin/rules/add" class="inline-form">
    <div class="grid grid-2">
      <div><label>规则类型</label><select name="rule_type">
        <option value="DOMAIN-SUFFIX">DOMAIN-SUFFIX（域名后缀）</option>
        <option value="DOMAIN-KEYWORD">DOMAIN-KEYWORD（域名关键词）</option>
        <option value="DOMAIN">DOMAIN（完整域名）</option>
        <option value="IP-CIDR">IP-CIDR（IP 段）</option>
      </select></div>
      <div><label>匹配值</label><input name="pattern" required placeholder="example.com 或 10.0.0.0/8"></div>
      <div><label>动作</label><select name="action">
        <option value="DIRECT">直连 (DIRECT)</option>
        <option value="🚀 节点选择">代理 (🚀 节点选择)</option>
        <option value="REJECT">拦截 (REJECT)</option>
      </select></div>
      <div><label>附加选项</label><select name="extra">
        <option value="">无</option>
        <option value="no-resolve">no-resolve（IP 规则跳过 DNS 解析）</option>
      </select></div>
    </div>
    <div class="row mt-md">
      <button class="btn" type="submit">添加规则（插入到最前）</button>
    </div>
  </form>
</div>

<div class="card mt-md">
  <details>
    <summary>直接编辑全部规则</summary>
    <form method="post" action="/admin/rules/raw" class="inline-form mt-md">
      <div class="small mb-sm">每行一条规则，格式：<code>TYPE,匹配值,动作</code>。保存后同步到所有订阅模板。</div>
      <textarea name="rules_raw" class="code-area code-med">{rules_text}</textarea>
      <div class="row mt-md">
        <button class="btn" type="submit">保存全部规则</button>
      </div>
    </form>
  </details>
</div>
<script>
document.addEventListener('submit', function(ev){{
  var f = ev.target;
  if (f && f.tagName==='FORM' && f.dataset.action==='delete-rule') {{
    if (!confirm('确认删除此规则？')) ev.preventDefault();
  }}
}});
</script>'''
    return render_admin_shell('rules', '订阅路由规则', content, badge=f'{len(rules)} 条')


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        return

    def parse_form(self):
        length = int(self.headers.get('Content-Length', '0') or 0)
        body = self.rfile.read(length).decode('utf-8', errors='ignore')
        return parse_qs(body)

    def send_response_body(self, code, body, ctype='text/plain; charset=utf-8', send_body=True, extra_headers=None):
        data = body.encode('utf-8')
        self.send_response(code)
        self.send_header('Content-Type', ctype)
        self.send_header('Content-Length', str(len(data)))
        if 'text/html' in ctype:
            self.send_header('Cache-Control', 'no-store')
        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, v)
        self.end_headers()
        if send_body:
            self.wfile.write(data)

    def _serve_static(self, payload_bytes, etag, ctype, send_payload):
        """Serve a cacheable static asset with ETag-aware 304 handling."""
        if self.headers.get('If-None-Match') == etag:
            self.send_response(304)
            self.send_header('ETag', etag)
            self.send_header('Cache-Control', 'public, max-age=86400')
            self.end_headers()
            return
        self.send_response(200)
        self.send_header('Content-Type', ctype)
        self.send_header('Content-Length', str(len(payload_bytes)))
        self.send_header('Cache-Control', 'public, max-age=86400')
        self.send_header('ETag', etag)
        self.end_headers()
        if send_payload:
            self.wfile.write(payload_bytes)

    def redirect(self, to, cookie=None):
        self.send_response(302)
        self.send_header('Location', to)
        if cookie:
            self.send_header('Set-Cookie', cookie)
        self.end_headers()

    def get_admin_actor(self):
        q = parse_qs(urlparse(self.path).query)
        token = (q.get('token') or [''])[0]
        meta = ensure_meta()
        admin_token = str(meta.get('admin_token') or '')
        if token and hmac.compare_digest(token, admin_token):
            return 'token-admin'
        sid = parse_cookies(self).get('sid', '')
        sessions = get_sessions()
        if sid in sessions:
            return sessions[sid].get('user', 'admin')
        return 'unknown'

    def write_reset_log(self, actor, action, target, before, after):
        line = {
            'time': datetime.utcnow().isoformat(timespec='seconds') + 'Z',
            'actor': actor,
            'ip': self.client_address[0] if self.client_address else '',
            'action': action,
            'target': target,
            'month': month_key(),
            'before': before,
            'after': after,
        }
        RESET_LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        with RESET_LOG_FILE.open('a', encoding='utf-8') as f:
            f.write(json.dumps(line, ensure_ascii=True) + '\n')

    def handle_get(self, send_payload=True):
        parsed = urlparse(self.path)
        path = parsed.path
        q = parse_qs(parsed.query)
        host = sanitize_host(self.headers.get('Host', '127.0.0.1'))
        base_url = safe_base_url(host, self.headers.get('X-Forwarded-Proto', 'http'))

        if path == '/static/style.css':
            self._serve_static(BASE_CSS_BYTES, BASE_CSS_ETAG, 'text/css; charset=utf-8', send_payload)
            return

        if path == '/static/admin-poll.js':
            self._serve_static(ADMIN_POLL_JS_BYTES, ADMIN_POLL_JS_ETAG,
                               'application/javascript; charset=utf-8', send_payload)
            return

        if path == '/':
            self.send_response_body(200, render_home(host), 'text/html; charset=utf-8', send_payload)
            return

        if path == '/login':
            self.send_response_body(200, render_login(host), 'text/html; charset=utf-8', send_payload)
            return

        if path == '/logout':
            sid = parse_cookies(self).get('sid', '')
            delete_session(sid)
            self.redirect('/login', cookie='sid=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax')
            return

        if path.startswith('/sub/'):
            user = path.split('/', 2)[2]
            token = (q.get('token') or [''])[0]
            cfg = check_user_token(user, token)
            if not cfg:
                self.send_response_body(403, '无权限访问', send_body=send_payload)
                return
            yml = build_yaml(user, str(cfg.get('sub_token') or ''))
            tx, rx, used = scaled_usage_for_user(user)
            total = user_total_quota(cfg)
            payload = yml.encode('utf-8')
            self.send_response(200)
            self.send_header('Content-Type', 'text/yaml; charset=utf-8')
            self.send_header('Content-Disposition', f"attachment; filename*=UTF-8''{user}.yaml")
            self.send_header('profile-update-interval', '24')
            self.send_header('subscription-userinfo', f'upload={tx}; download={rx}; total={total}; expire=0')
            self.send_header('x-usage-total-bytes', str(used))
            self.send_header('Content-Length', str(len(payload)))
            self.end_headers()
            if send_payload:
                self.wfile.write(payload)
            return

        if path.startswith('/panel/'):
            user = path.split('/', 2)[2]
            token = (q.get('token') or [''])[0]
            cfg = check_user_token(user, token)
            if not cfg:
                self.send_response_body(403, '无权限访问', send_body=send_payload)
                return
            self.send_response_body(200, render_user_panel(host, base_url, user, token, cfg), 'text/html; charset=utf-8', send_payload)
            return

        if path == '/admin':
            if not is_logged_in(self):
                self.redirect('/login')
                return
            flash = (q.get('msg') or [''])[0]
            self.send_response_body(200, render_admin(host, base_url, flash=flash), 'text/html; charset=utf-8', send_payload)
            return

        if path == '/admin/usage.json':
            if not is_logged_in(self):
                self.send_response_body(403, '{"error":"unauthorized"}', 'application/json; charset=utf-8', send_payload)
                return
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
                    # NOTE: spark_html mirrors row_form's spark cell — see row_form for the 3-place coupling note.
                    'spark_html': sparkline_svg(daily_window_for_user(u, daily, days=30)),
                })
            payload = json.dumps({'total_used': total_used, 'users': user_list}, ensure_ascii=True)
            self.send_response_body(200, payload, 'application/json; charset=utf-8', send_payload)
            return

        if path == '/admin/logs':
            if not is_logged_in(self):
                self.redirect('/login')
                return
            self.send_response_body(200, render_reset_logs(host), 'text/html; charset=utf-8', send_payload)
            return

        if path == '/admin/daily':
            if not is_logged_in(self):
                self.redirect('/login')
                return
            try:
                days = int((q.get('days') or ['14'])[0])
            except ValueError:
                days = 14
            self.send_response_body(200, render_daily_usage(host, days=days), 'text/html; charset=utf-8', send_payload)
            return

        if path == '/admin/health':
            if not is_logged_in(self):
                self.redirect('/login')
                return
            self.send_response_body(200, render_health(host),
                                    'text/html; charset=utf-8', send_payload)
            return

        if path == '/admin/config':
            if not is_logged_in(self):
                self.redirect('/login')
                return
            flash = (q.get('msg') or [''])[0]
            self.send_response_body(200, render_config_editor(host, flash=flash), 'text/html; charset=utf-8', send_payload)
            return

        if path == '/admin/rules':
            if not is_logged_in(self):
                self.redirect('/login')
                return
            flash = (q.get('msg') or [''])[0]
            self.send_response_body(200, render_rules(host, flash=flash), 'text/html; charset=utf-8', send_payload)
            return

        self.send_response_body(404, '页面不存在', send_body=send_payload)

    def do_GET(self):
        self.handle_get(send_payload=True)

    def do_HEAD(self):
        self.handle_get(send_payload=False)

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path
        form = self.parse_form()
        meta = ensure_meta()

        if path == '/login':
            ip = self.client_address[0] if self.client_address else ''
            host = sanitize_host(self.headers.get('Host', '127.0.0.1'))
            if _is_rate_limited(ip):
                self.send_response_body(200, render_login(host, msg='登录尝试过于频繁，请 1 小时后再试'), 'text/html; charset=utf-8', True)
                return
            user = (form.get('username') or [''])[0].strip()
            passwd = (form.get('password') or [''])[0]
            stored_hash = str(meta.get('admin_pass_hash') or '')
            ok = (user == meta.get('admin_user') and stored_hash and verify_secret(passwd, stored_hash))
            if ok:
                _clear_failures(ip)
                sid = create_session('admin')
                self.redirect('/admin?msg=login+success', cookie=f'sid={sid}; Path=/; Max-Age={SESSION_TTL}; HttpOnly; SameSite=Lax')
                return
            _record_failure(ip)
            self.send_response_body(200, render_login(host, msg='用户名或密码错误'), 'text/html; charset=utf-8', True)
            return

        if path == '/admin/update':
            if not is_logged_in(self):
                self.redirect('/login')
                return
            username = (form.get('user') or [''])[0].strip()
            users = load_json(USERS_FILE, {})
            if username not in users:
                self.redirect('/admin?msg=user+not+found')
                return
            cfg = users[username]
            new_password = (form.get('password') or [''])[0].strip()
            max_devices = parse_int_field((form.get('max_devices') or ['2'])[0], 2, 1, 100)
            quota_gb = parse_int_field((form.get('quota_gb') or ['150'])[0], 150, 1, 10240)
            guest = 'guest' in form
            if new_password:
                cfg['password_hash'] = hash_secret(new_password)
            cfg.pop('password', None)
            cfg['max_devices'] = max(1, max_devices)
            cfg['monthly_quota_bytes'] = max(1, quota_gb) * 1024 * 1024 * 1024
            cfg['guest'] = guest
            if not cfg.get('sub_token'):
                cfg['sub_token'] = secrets.token_urlsafe(18)
            users[username] = cfg
            save_json(USERS_FILE, users)
            self.redirect('/admin?msg=updated+' + username)
            return

        if path == '/admin/add':
            if not is_logged_in(self):
                self.redirect('/login')
                return
            username = (form.get('user') or [''])[0].strip()
            password = (form.get('password') or [''])[0].strip()
            quota_gb = parse_int_field((form.get('quota_gb') or ['150'])[0], 150, 1, 10240)
            guest = 'guest' in form
            reset_token = 'reset_token' in form
            users = load_json(USERS_FILE, {})
            if not username:
                self.redirect('/admin?msg=user+empty')
                return
            if username in users and not reset_token:
                self.redirect('/admin?msg=user_exists_use_reset_token')
                return
            existing = users.get(username, {})
            existing_token = existing.get('sub_token')
            token = secrets.token_urlsafe(18) if (reset_token or not existing_token) else existing_token
            vless_uuid = str(existing.get('vless_uuid') or '').strip() or str(uuid.uuid4())
            entry = {
                'guest': guest,
                'max_devices': 2,
                'monthly_quota_bytes': max(1, quota_gb) * 1024 * 1024 * 1024,
                'sub_token': token,
                'vless_uuid': vless_uuid,
            }
            if password:
                entry['password_hash'] = hash_secret(password)
            elif existing.get('password_hash'):
                entry['password_hash'] = existing.get('password_hash')
            users[username] = entry
            save_json(USERS_FILE, users)
            if xray_config.sync_user(username, vless_uuid):
                xray_config.reload_async()
            self.redirect('/admin?msg=created+' + username)
            return

        if path == '/admin/reset-usage':
            if not is_logged_in(self):
                self.redirect('/login')
                return
            username = (form.get('user') or [''])[0].strip()
            users = load_json(USERS_FILE, {})
            if username not in users:
                self.redirect('/admin?msg=user+not+found')
                return
            with usage_lock():
                usage = load_json(USAGE_FILE, {})
                mk = month_key()
                usage.setdefault(mk, {})
                tx, rx, total = usage_for_user(username, usage[mk])
                before = {'tx': tx, 'rx': rx, 'total': total}
                usage[mk][username] = {'tx': 0, 'rx': 0, 'total': 0}
                after = {'tx': 0, 'rx': 0, 'total': 0}
                save_json(USAGE_FILE, usage)
                # Clear quota alert dedup so subsequent crossings re-fire (ADR-0001).
                alert_state = alerts.load_state()
                alerts.clear_quota_dedup_for(alert_state, [username])
                alerts.save_state(alert_state)
            self.write_reset_log(self.get_admin_actor(), 'reset_usage_user', username, before, after)
            self.redirect('/admin?msg=reset+usage+' + username)
            return

        if path == '/admin/reset-usage-all':
            if not is_logged_in(self):
                self.redirect('/login')
                return
            with usage_lock():
                usage = load_json(USAGE_FILE, {})
                mk = month_key()
                usage.setdefault(mk, {})
                before_all = {}
                users = load_json(USERS_FILE, {})
                for username in users.keys():
                    tx, rx, total = usage_for_user(username, usage[mk])
                    before_all[username] = {'tx': tx, 'rx': rx, 'total': total}
                    usage[mk][username] = {'tx': 0, 'rx': 0, 'total': 0}
                save_json(USAGE_FILE, usage)
                # Clear quota alert dedup for all users (ADR-0001).
                alert_state = alerts.load_state()
                alerts.clear_quota_dedup_for(alert_state, list(users.keys()))
                alerts.save_state(alert_state)
            self.write_reset_log(
                self.get_admin_actor(),
                'reset_usage_all',
                'all_users',
                before_all,
                {u: {'tx': 0, 'rx': 0, 'total': 0} for u in users.keys()},
            )
            self.redirect('/admin?msg=reset+usage+all')
            return

        if path == '/admin/delete':
            if not is_logged_in(self):
                self.redirect('/login')
                return
            username = (form.get('user') or [''])[0].strip()
            users = load_json(USERS_FILE, {})
            if username not in users:
                self.redirect('/admin?msg=user+not+found')
                return
            del users[username]
            save_json(USERS_FILE, users)
            hy_kick([username])
            if xray_config.remove_user(username):
                xray_config.reload_async()
            self.redirect('/admin?msg=deleted+' + username)
            return

        if path == '/admin/config/save':
            if not is_logged_in(self):
                self.redirect('/login')
                return
            raw = (form.get('config_json') or [''])[0].strip()
            if not raw:
                self.redirect('/admin/config?msg=err:empty')
                return
            try:
                data = json.loads(raw)
            except (json.JSONDecodeError, ValueError):
                self.redirect('/admin/config?msg=err:invalid_json')
                return
            save_template_config(data)
            self.redirect('/admin/config?msg=saved')
            return

        if path == '/admin/rules/add':
            if not is_logged_in(self):
                self.redirect('/login')
                return
            rule_type = (form.get('rule_type') or ['DOMAIN-SUFFIX'])[0]
            pattern = (form.get('pattern') or [''])[0].strip()
            action = (form.get('action') or ['DIRECT'])[0]
            extra = (form.get('extra') or [''])[0]
            if not pattern:
                self.redirect('/admin/rules?msg=err:pattern_empty')
                return
            if rule_type not in ('DOMAIN-SUFFIX', 'DOMAIN-KEYWORD', 'DOMAIN', 'IP-CIDR'):
                self.redirect('/admin/rules?msg=err:invalid_rule_type')
                return
            rule_str = f'{rule_type},{pattern},{action}'
            if extra:
                rule_str += f',{extra}'
            rules = load_template_rules()
            rules.insert(0, rule_str)
            save_template_rules(rules)
            self.redirect('/admin/rules?msg=rule_added')
            return

        if path == '/admin/rules/delete':
            if not is_logged_in(self):
                self.redirect('/login')
                return
            try:
                idx = int((form.get('index') or [''])[0])
            except (ValueError, IndexError):
                self.redirect('/admin/rules?msg=err:invalid_index')
                return
            rules = load_template_rules()
            if idx < 0 or idx >= len(rules):
                self.redirect('/admin/rules?msg=err:index_out_of_range')
                return
            rules.pop(idx)
            save_template_rules(rules)
            self.redirect('/admin/rules?msg=rule_deleted')
            return

        if path == '/admin/rules/raw':
            if not is_logged_in(self):
                self.redirect('/login')
                return
            raw = (form.get('rules_raw') or [''])[0]
            rules = [line.strip() for line in raw.splitlines() if line.strip()]
            if not rules:
                self.redirect('/admin/rules?msg=err:raw_empty')
                return
            save_template_rules(rules)
            self.redirect('/admin/rules?msg=raw_saved')
            return

        self.send_response_body(404, '页面不存在')


if __name__ == '__main__':
    ensure_meta()
    migrate_plaintext_passwords()
    migrate_admin_password()
    srv = ThreadingHTTPServer(LISTEN, Handler)
    srv.serve_forever()
