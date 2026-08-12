"""Subscription profile and Clash YAML rendering helpers."""
import hashlib
import logging
import os
import re
from dataclasses import dataclass
from datetime import datetime

import user_compat


log = logging.getLogger(__name__)

NODE_GROUP = '🚀 节点选择'
AUTO_GROUP = '🔄 自动选择'
GITHUB_GROUP = '⚡ GitHub 加速'
GPT_GROUP = '🤖 GPT 优化'
GOOGLE_GROUP = '🌐 Google 优化'
TELEGRAM_GROUP = '✈️ Telegram 优化'
HY2_UDP_PROXY = '🇺🇸 美国 UDP (端口跳跃)'
TUIC_UDP_PROXY = '🇺🇸 美国 UDP TUIC'
VLESS_TCP_PROXY = '🇺🇸 美国 TCP (VLESS+REALITY)'
VLESS_BACKUP_PROXY = '🇺🇸 美国 TCP 备用 (VLESS+REALITY)'
DIRECT_IP_RULE = 'IP-CIDR,47.245.53.96/32,DIRECT,no-resolve'
NOISY_TIMEOUT_IP_RULE = 'IP-CIDR,192.238.178.243/32,DIRECT,no-resolve'
DIRECT_IP_RULES = (DIRECT_IP_RULE, NOISY_TIMEOUT_IP_RULE)
USER_CLASH_RULES_KEY = 'clash_rules'
USER_FAKE_IP_FILTER_KEY = 'clash_fake_ip_filter'
USER_TUN_ROUTE_EXCLUDE_ADDRESS_KEY = 'clash_tun_route_exclude_address'
USER_TUIC_ENABLED_KEY = 'tuic_enabled'
USER_TEMPLATE_MODE_KEY = 'clash_template_mode'
USER_TEMPLATE_REVISION_KEY = 'clash_template_revision'
TEMPLATE_MODE_FOLLOW = 'follow'
TEMPLATE_MODE_PINNED = 'pinned'

RULE_PACKS = {
    'easyconnect': {
        'label': 'EasyConnect 直连',
        'desc': '深信服 EasyConnect / 西工大 VPN 进程、域名、IP 强制直连',
        'rules': [
            'PROCESS-NAME,EasyConnect.exe,DIRECT',
            'PROCESS-NAME,ECAgent.exe,DIRECT',
            'PROCESS-NAME,SangforCSClient.exe,DIRECT',
            'PROCESS-NAME,SangforServiceClient.exe,DIRECT',
            'DOMAIN,vpn.nwpu.edu.cn,DIRECT',
            'DOMAIN-SUFFIX,nwpu.edu.cn,DIRECT',
            'IP-CIDR,202.117.80.11/32,DIRECT,no-resolve',
            'IP-CIDR6,2001:250:1004:805:202:117:80:11/128,DIRECT,no-resolve',
        ],
        'fake_ip_filter': ['vpn.nwpu.edu.cn', '*.nwpu.edu.cn'],
        'tun_route_exclude_address': ['202.117.80.11/32'],
    },
    'overleaf': {
        'label': 'Overleaf 加速',
        'desc': 'Overleaf / ShareLaTeX 相关域名优先走节点选择',
        'rules': [
            f'DOMAIN-SUFFIX,overleaf.com,{NODE_GROUP}',
            f'DOMAIN-SUFFIX,overleafusercontent.com,{NODE_GROUP}',
            f'DOMAIN-SUFFIX,sharelatex.com,{NODE_GROUP}',
        ],
    },
    'ipv6_dead_end': {
        'label': 'IPv6 抑制',
        'desc': '拦截无 IPv6 出口时容易拖慢连接的 IPv6/NCSI 探测',
        'rules': [
            'DOMAIN,ipv6.msftconnecttest.com,REJECT',
            'DOMAIN,ipv6.msftncsi.com,REJECT',
            'IP-CIDR6,::/0,REJECT,no-resolve',
        ],
    },
}
RULE_PACK_ORDER = ('easyconnect', 'overleaf', 'ipv6_dead_end')

SUBSCRIPTION_PROFILES = {
    'default': {
        'label': '默认',
        'desc': '保持后台模板策略',
    },
    'game': {
        'label': '游戏',
        'desc': '优先 UDP，低延迟测试更激进',
    },
    'work': {
        'label': '办公',
        'desc': '优先 TCP/备用线路，稳定性优先',
    },
    'lowdata': {
        'label': '省流',
        'desc': '未知流量直连，只代理规则命中的域名',
    },
    'safe': {
        'label': '全代理',
        'desc': '除局域网/私有地址外尽量走代理',
    },
}
SUBSCRIPTION_PROFILE_ORDER = ('default', 'game', 'work', 'lowdata', 'safe')
_PROFILE_ALIASES = {
    '': 'default',
    'normal': 'default',
    'auto': 'default',
    'office': 'work',
    'stable': 'work',
    'low-data': 'lowdata',
    'low_data': 'lowdata',
    'save': 'lowdata',
    'global': 'safe',
    'proxy': 'safe',
    'full': 'safe',
}


@dataclass(frozen=True)
class SubscriptionProfileContext:
    template_file: object
    users_file: object
    load_json: object
    template_versions_file: object = None


@dataclass(frozen=True)
class SelectedTemplate:
    text: str
    mode: str
    revision: str
    mtime: str


@dataclass(frozen=True)
class RenderedSubscription:
    text: str
    template_mode: str
    template_revision: str
    template_mtime: str


class PinnedTemplateUnavailable(RuntimeError):
    """A user selected a pinned template revision that cannot be trusted."""


def normalize_user_template_mode(user_cfg):
    if not isinstance(user_cfg, dict):
        return TEMPLATE_MODE_FOLLOW
    if user_cfg.get(USER_TEMPLATE_MODE_KEY) == TEMPLATE_MODE_PINNED:
        return TEMPLATE_MODE_PINNED
    return TEMPLATE_MODE_FOLLOW


def template_revision(raw):
    if isinstance(raw, str):
        raw = raw.encode('utf-8')
    return hashlib.sha256(bytes(raw or b'')).hexdigest()


def _read_live_template(template_file):
    try:
        with template_file.open('rb') as source:
            raw = source.read()
            mtime = datetime.utcfromtimestamp(
                os.fstat(source.fileno()).st_mtime,
            ).isoformat(timespec='seconds') + 'Z'
    except FileNotFoundError:
        return b'', ''
    return raw, mtime


def _selected_template(ctx, user_cfg):
    mode = normalize_user_template_mode(user_cfg)
    if mode == TEMPLATE_MODE_FOLLOW:
        raw, mtime = _read_live_template(ctx.template_file)
        return SelectedTemplate(
            raw.decode('utf-8'),
            mode,
            template_revision(raw),
            mtime,
        )

    revision = str(user_cfg.get(USER_TEMPLATE_REVISION_KEY) or '').lower()
    if not re.fullmatch(r'[0-9a-f]{64}', revision):
        raise PinnedTemplateUnavailable('pinned template revision is invalid')
    if ctx.template_versions_file is None:
        raise PinnedTemplateUnavailable('template snapshot store is unavailable')
    state = ctx.load_json(ctx.template_versions_file, {})
    if not isinstance(state, dict) or state.get('version') != 1:
        raise PinnedTemplateUnavailable('template snapshot store is invalid')
    templates = state.get('templates')
    entry = templates.get(revision) if isinstance(templates, dict) else None
    text = entry.get('yaml') if isinstance(entry, dict) else None
    if not isinstance(text, str) or template_revision(text) != revision:
        raise PinnedTemplateUnavailable('pinned template snapshot is unavailable')
    template_mtime = entry.get('template_mtime')
    if not isinstance(template_mtime, str) or not re.fullmatch(
        r'[0-9TZ:.-]{0,40}', template_mtime,
    ):
        raise PinnedTemplateUnavailable('pinned template metadata is invalid')
    return SelectedTemplate(
        text,
        mode,
        revision,
        template_mtime,
    )


def normalize_subscription_profile(raw):
    key = str(raw or '').strip().lower()
    key = _PROFILE_ALIASES.get(key, key)
    if key not in SUBSCRIPTION_PROFILES:
        return 'default'
    return key


def _proxy_names(cfg):
    return {
        str(proxy.get('name'))
        for proxy in (cfg.get('proxies') or [])
        if isinstance(proxy, dict) and proxy.get('name')
    }


def _proxy_group_map(cfg):
    return {
        str(group.get('name')): group
        for group in (cfg.get('proxy-groups') or [])
        if isinstance(group, dict) and group.get('name')
    }


def _dedupe(seq):
    out = []
    seen = set()
    for item in seq:
        if item in seen:
            continue
        seen.add(item)
        out.append(item)
    return out


def _set_group_proxies(cfg, group_name, preferred, *,
                       allow_group_refs=False, allow_direct=False,
                       group_type=None, interval=None, timeout=None,
                       tolerance=None):
    groups = _proxy_group_map(cfg)
    group = groups.get(group_name)
    if not group:
        return
    allowed = set(_proxy_names(cfg))
    if allow_group_refs:
        allowed.update(name for name in groups if name != group_name)
    if allow_direct:
        allowed.add('DIRECT')

    current = [p for p in (group.get('proxies') or []) if p in allowed]
    ordered = [p for p in preferred if p in allowed and p != group_name]
    group['proxies'] = _dedupe(ordered + current)
    if group_type:
        group['type'] = group_type
    if interval is not None:
        group['interval'] = interval
    if timeout is not None:
        group['timeout'] = timeout
    if tolerance is not None:
        group['tolerance'] = tolerance


def _prepend_unique_rules(cfg, new_rules):
    rules = list(cfg.get('rules') or [])
    existing = [rule for rule in rules if rule not in new_rules]
    cfg['rules'] = new_rules + existing


def _string_list(value):
    if isinstance(value, str):
        items = value.splitlines()
    elif isinstance(value, (list, tuple)):
        items = value
    else:
        return []
    return [str(item).strip() for item in items if str(item).strip()]


def _prepend_unique_fake_ip_filters(cfg, new_filters):
    dns = cfg.get('dns')
    if not isinstance(dns, dict):
        dns = {}
        cfg['dns'] = dns
    current = _string_list(dns.get('fake-ip-filter') or [])
    dns['fake-ip-filter'] = _dedupe(list(new_filters) + current)


def _prepend_unique_tun_route_exclude_addresses(cfg, new_addresses):
    tun = cfg.get('tun')
    if not isinstance(tun, dict):
        tun = {}
        cfg['tun'] = tun
    current = _string_list(tun.get('route-exclude-address') or [])
    tun['route-exclude-address'] = _dedupe(list(new_addresses) + current)


def get_rule_pack(key):
    return RULE_PACKS.get(str(key or '').strip())


def apply_rule_pack_to_clash_config(cfg, pack_key):
    pack = get_rule_pack(pack_key)
    if not pack:
        return False
    rules = _string_list(pack.get('rules'))
    fake_ip_filters = _string_list(pack.get('fake_ip_filter'))
    route_exclude_addresses = _string_list(pack.get('tun_route_exclude_address'))
    if rules:
        _prepend_unique_rules(cfg, rules)
    if fake_ip_filters:
        _prepend_unique_fake_ip_filters(cfg, fake_ip_filters)
    if route_exclude_addresses:
        _prepend_unique_tun_route_exclude_addresses(cfg, route_exclude_addresses)
    return True


def apply_rule_pack_to_user_config(user_cfg, pack_key):
    pack = get_rule_pack(pack_key)
    if not pack or not isinstance(user_cfg, dict):
        return False
    merged = {
        USER_CLASH_RULES_KEY: _string_list(user_cfg.get(USER_CLASH_RULES_KEY)),
        USER_FAKE_IP_FILTER_KEY: _string_list(user_cfg.get(USER_FAKE_IP_FILTER_KEY)),
        USER_TUN_ROUTE_EXCLUDE_ADDRESS_KEY: _string_list(
            user_cfg.get(USER_TUN_ROUTE_EXCLUDE_ADDRESS_KEY)),
    }
    pack_map = {
        USER_CLASH_RULES_KEY: _string_list(pack.get('rules')),
        USER_FAKE_IP_FILTER_KEY: _string_list(pack.get('fake_ip_filter')),
        USER_TUN_ROUTE_EXCLUDE_ADDRESS_KEY: _string_list(
            pack.get('tun_route_exclude_address')),
    }
    for key, additions in pack_map.items():
        if additions:
            user_cfg[key] = _dedupe(additions + merged[key])
    return True


def _remove_proxy_everywhere(cfg, proxy_name):
    cfg['proxies'] = [
        proxy for proxy in (cfg.get('proxies') or [])
        if not (isinstance(proxy, dict) and proxy.get('name') == proxy_name)
    ]
    for group in (cfg.get('proxy-groups') or []):
        if isinstance(group, dict) and isinstance(group.get('proxies'), list):
            group['proxies'] = [p for p in group['proxies'] if p != proxy_name]


def apply_user_transport_policy(cfg, user_cfg):
    if not user_compat.tuic_enabled(user_cfg):
        _remove_proxy_everywhere(cfg, TUIC_UDP_PROXY)
    return cfg


def apply_user_clash_overrides(cfg, user_cfg):
    if not isinstance(user_cfg, dict):
        return cfg
    rules = _string_list(user_cfg.get(USER_CLASH_RULES_KEY))
    fake_ip_filters = _string_list(user_cfg.get(USER_FAKE_IP_FILTER_KEY))
    route_exclude_addresses = _string_list(
        user_cfg.get(USER_TUN_ROUTE_EXCLUDE_ADDRESS_KEY))
    if rules:
        _prepend_unique_rules(cfg, rules)
    if fake_ip_filters:
        _prepend_unique_fake_ip_filters(cfg, fake_ip_filters)
    if route_exclude_addresses:
        _prepend_unique_tun_route_exclude_addresses(
            cfg, route_exclude_addresses)
    return cfg


def render_user_transport_policy_yaml(text, user_cfg):
    if user_compat.tuic_enabled(user_cfg):
        return text
    try:
        import yaml
        data = yaml.safe_load(text) or {}
        apply_user_transport_policy(data, user_cfg)
        return _dump_yaml(data)
    except Exception:
        log.exception('failed to render user transport policy')
        return text


def _replace_match_rule(cfg, action):
    rules = []
    replaced = False
    for rule in (cfg.get('rules') or []):
        if isinstance(rule, str) and rule.startswith('MATCH,'):
            rules.append(f'MATCH,{action}')
            replaced = True
        else:
            rules.append(rule)
    if not replaced:
        rules.append(f'MATCH,{action}')
    cfg['rules'] = rules


def _rewrite_rule_action(rule, action):
    parts = str(rule).split(',')
    if not parts:
        return rule
    if parts[0] == 'MATCH':
        return f'MATCH,{action}'
    if len(parts) >= 3:
        parts[2] = action
        return ','.join(parts)
    return rule


def _apply_game_profile(cfg):
    _set_group_proxies(
        cfg, NODE_GROUP,
        [HY2_UDP_PROXY, TUIC_UDP_PROXY, GPT_GROUP, GOOGLE_GROUP,
         TELEGRAM_GROUP, AUTO_GROUP, VLESS_TCP_PROXY, VLESS_BACKUP_PROXY,
         GITHUB_GROUP, 'DIRECT'],
        allow_group_refs=True, allow_direct=True,
    )
    _set_group_proxies(
        cfg, AUTO_GROUP,
        [HY2_UDP_PROXY, TUIC_UDP_PROXY, VLESS_TCP_PROXY, VLESS_BACKUP_PROXY],
        group_type='url-test', interval=20, timeout=2500, tolerance=50,
    )
    _prepend_unique_rules(cfg, [
        f'DOMAIN-SUFFIX,steamcommunity.com,{NODE_GROUP}',
        f'DOMAIN-SUFFIX,epicgames.com,{NODE_GROUP}',
        f'DOMAIN-SUFFIX,epicgames.dev,{NODE_GROUP}',
        f'DOMAIN-SUFFIX,riotgames.com,{NODE_GROUP}',
        'DOMAIN-SUFFIX,steamcontent.com,DIRECT',
        'DOMAIN-SUFFIX,steamserver.net,DIRECT',
    ])


def _apply_work_profile(cfg):
    _set_group_proxies(
        cfg, NODE_GROUP,
        [GITHUB_GROUP, GPT_GROUP, GOOGLE_GROUP, TELEGRAM_GROUP, AUTO_GROUP,
         VLESS_TCP_PROXY, VLESS_BACKUP_PROXY, HY2_UDP_PROXY, TUIC_UDP_PROXY,
         'DIRECT'],
        allow_group_refs=True, allow_direct=True,
    )
    _set_group_proxies(
        cfg, AUTO_GROUP,
        [VLESS_TCP_PROXY, VLESS_BACKUP_PROXY, HY2_UDP_PROXY, TUIC_UDP_PROXY],
        group_type='fallback', interval=60, timeout=6000,
    )
    _prepend_unique_rules(cfg, [
        f'DOMAIN-SUFFIX,slack.com,{NODE_GROUP}',
        f'DOMAIN-SUFFIX,notion.so,{NODE_GROUP}',
        f'DOMAIN-SUFFIX,zoom.us,{NODE_GROUP}',
        f'DOMAIN-SUFFIX,linear.app,{NODE_GROUP}',
    ])


def _apply_lowdata_profile(cfg):
    cfg['log-level'] = 'warning'
    _set_group_proxies(
        cfg, NODE_GROUP,
        ['DIRECT', GPT_GROUP, GOOGLE_GROUP, TELEGRAM_GROUP, AUTO_GROUP,
         VLESS_TCP_PROXY, VLESS_BACKUP_PROXY, HY2_UDP_PROXY, TUIC_UDP_PROXY,
         GITHUB_GROUP],
        allow_group_refs=True, allow_direct=True,
    )
    _set_group_proxies(
        cfg, AUTO_GROUP,
        [VLESS_TCP_PROXY, VLESS_BACKUP_PROXY, HY2_UDP_PROXY, TUIC_UDP_PROXY],
        group_type='fallback', interval=90, timeout=6000,
    )
    _replace_match_rule(cfg, 'DIRECT')


def _apply_safe_profile(cfg):
    _set_group_proxies(
        cfg, NODE_GROUP,
        [GPT_GROUP, GOOGLE_GROUP, TELEGRAM_GROUP, AUTO_GROUP, VLESS_TCP_PROXY,
         VLESS_BACKUP_PROXY, HY2_UDP_PROXY, TUIC_UDP_PROXY, 'DIRECT'],
        allow_group_refs=True, allow_direct=True,
    )
    _set_group_proxies(
        cfg, AUTO_GROUP,
        [VLESS_TCP_PROXY, VLESS_BACKUP_PROXY, HY2_UDP_PROXY, TUIC_UDP_PROXY],
        group_type='fallback', interval=45, timeout=5000,
    )
    keep_direct = (
        *DIRECT_IP_RULES,
        'RULE-SET,private,DIRECT',
        'RULE-SET,lancidr,DIRECT',
        'GEOIP,LAN,DIRECT',
    )
    rewritten = []
    for rule in (cfg.get('rules') or []):
        if not isinstance(rule, str):
            rewritten.append(rule)
        elif rule.startswith('RULE-SET,reject,') or rule.startswith(keep_direct):
            rewritten.append(rule)
        elif rule.startswith('MATCH,'):
            rewritten.append(f'MATCH,{NODE_GROUP}')
        elif ',DIRECT' in rule:
            rewritten.append(_rewrite_rule_action(rule, NODE_GROUP))
        else:
            rewritten.append(rule)
    cfg['rules'] = rewritten
    _replace_match_rule(cfg, NODE_GROUP)


def apply_subscription_profile(cfg, profile):
    profile = normalize_subscription_profile(profile)
    if profile == 'default':
        return cfg
    appliers = {
        'game': _apply_game_profile,
        'work': _apply_work_profile,
        'lowdata': _apply_lowdata_profile,
        'safe': _apply_safe_profile,
    }
    appliers[profile](cfg)
    return cfg


def _dump_yaml(data):
    import yaml
    return yaml.dump(data, allow_unicode=True, default_flow_style=False, sort_keys=False)


def utc_now_iso():
    return datetime.utcnow().isoformat(timespec='seconds') + 'Z'


def template_mtime_iso(template_file):
    try:
        return datetime.utcfromtimestamp(template_file.stat().st_mtime).isoformat(timespec='seconds') + 'Z'
    except Exception:
        return ''


def prepend_subscription_header(
    text,
    username,
    profile,
    *,
    template_mtime='',
    template_mode=TEMPLATE_MODE_FOLLOW,
    template_revision_value='',
    generated_at=None,
):
    generated = generated_at or utc_now_iso()
    profile = normalize_subscription_profile(profile)
    header = [
        f'# hy2-generated-at: {generated}',
        f'# hy2-template-mtime: {template_mtime}',
        f'# hy2-template-mode: {template_mode}',
        f'# hy2-template-revision: {template_revision_value}',
        f'# hy2-user: {username}',
        f'# hy2-profile: {profile}',
        '# hy2-note: refresh the client subscription after route or rule changes',
    ]
    return '\n'.join(header) + '\n' + str(text or '').lstrip()


def render_profile_yaml(text, profile):
    profile = normalize_subscription_profile(profile)
    if profile == 'default':
        return text
    try:
        import yaml
        data = yaml.safe_load(text) or {}
        apply_subscription_profile(data, profile)
        return _dump_yaml(data)
    except Exception:
        log.exception('failed to render subscription profile %s', profile)
        return text


def render_user_clash_overrides_yaml(text, user_cfg):
    if not isinstance(user_cfg, dict):
        return text
    if not (_string_list(user_cfg.get(USER_CLASH_RULES_KEY)) or
            _string_list(user_cfg.get(USER_FAKE_IP_FILTER_KEY)) or
            _string_list(user_cfg.get(USER_TUN_ROUTE_EXCLUDE_ADDRESS_KEY))):
        return text
    try:
        import yaml
        data = yaml.safe_load(text) or {}
        apply_user_clash_overrides(data, user_cfg)
        return _dump_yaml(data)
    except Exception:
        log.exception('failed to render user Clash overrides')
        return text


def render_subscription(
    ctx,
    username,
    auth_secret,
    profile='default',
    *,
    generated_at=None,
):
    users = ctx.load_json(ctx.users_file, {})
    user_cfg = users.get(username) or {}
    selected = _selected_template(ctx, user_cfg)
    text = selected.text
    if not text:
        return RenderedSubscription(
            '', selected.mode, selected.revision, selected.mtime,
        )
    text = re.sub(
        r'(?m)^(\s*password:\s*).*$',
        lambda match: f'{match.group(1)}{username}:{auth_secret}',
        text,
        count=1,
    )
    vless_uuid = str(user_cfg.get('vless_uuid') or '').strip()
    if vless_uuid:
        text = re.sub(
            r'(?m)^(\s*uuid:\s*).*$',
            lambda match: f'{match.group(1)}{vless_uuid}',
            text,
        )
        text = re.sub(
            r'(?m)^(\s*password:\s*)TUIC_PASSWORD_PLACEHOLDER\s*$',
            lambda match: f'{match.group(1)}{username}:{auth_secret}',
            text,
        )
    text = render_profile_yaml(text, profile)
    text = render_user_transport_policy_yaml(text, user_cfg)
    text = render_user_clash_overrides_yaml(text, user_cfg)
    rendered = prepend_subscription_header(
        text,
        username,
        profile,
        template_mtime=selected.mtime,
        template_mode=selected.mode,
        template_revision_value=selected.revision,
        generated_at=generated_at,
    )
    return RenderedSubscription(
        rendered,
        selected.mode,
        selected.revision,
        selected.mtime,
    )


def build_yaml(ctx, username, auth_secret, profile='default', *, generated_at=None):
    return render_subscription(
        ctx,
        username,
        auth_secret,
        profile=profile,
        generated_at=generated_at,
    ).text
