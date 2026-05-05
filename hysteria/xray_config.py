"""xray VLESS Reality config helpers — owns ADR-0002.

Each user must exist as a `clients[]` entry in BOTH inbound ports (443 primary,
8443 backup) so that clients have transparent failover when the primary path is
blocked. Inside xray's config, the 8443 entry's email field carries a `-backup`
suffix; outside this module the suffix is invisible — usage aggregation strips
it via `strip_backup_suffix()`.

Maintenance rule: any code that mutates xray clients must go through `sync_user`
/ `remove_user`, never edit the config file directly. Forgetting one of the two
inbound ports leaves the user reachable on one and rejected on the other, with
no obvious error.
"""
import json
import subprocess
import time
from pathlib import Path

CONFIG_FILE = Path('/usr/local/etc/xray/config.json')
INBOUND_PORTS = (443, 8443)
PRIMARY_PORT = 443
BACKUP_SUFFIX = '-backup'


def email_for(port, username):
    """Return the xray client `email` field for `username` on `port`.

    The 8443 inbound carries the `-backup` suffix; 443 carries the bare username.
    """
    return username if port == PRIMARY_PORT else f'{username}{BACKUP_SUFFIX}'


def strip_backup_suffix(email):
    """Reduce a possibly-suffixed xray client email back to its canonical user id."""
    return email[: -len(BACKUP_SUFFIX)] if email.endswith(BACKUP_SUFFIX) else email


def _load_config(path):
    try:
        return json.loads(path.read_text(encoding='utf-8'))
    except Exception:
        return None


def _save_config(path, cfg):
    path.write_text(json.dumps(cfg, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')


def sync_user(username, vless_uuid, *, path=None):
    """Ensure `username` is present in every vless inbound under both ports
    with the given uuid. Returns True if the config file was modified.
    """
    p = Path(path) if path else CONFIG_FILE
    cfg = _load_config(p)
    if cfg is None:
        return False
    changed = False
    for ib in cfg.get('inbounds') or []:
        if ib.get('protocol') != 'vless':
            continue
        port = ib.get('port')
        if port not in INBOUND_PORTS:
            continue
        clients = ib.setdefault('settings', {}).setdefault('clients', [])
        email = email_for(port, username)
        existing = next((c for c in clients if c.get('email') == email), None)
        if existing is None:
            clients.append({'id': vless_uuid, 'email': email, 'flow': 'xtls-rprx-vision'})
            changed = True
        elif existing.get('id') != vless_uuid or existing.get('flow') != 'xtls-rprx-vision':
            existing['id'] = vless_uuid
            existing['flow'] = 'xtls-rprx-vision'
            changed = True
    if changed:
        _save_config(p, cfg)
    return changed


def remove_user(username, *, path=None):
    """Remove `username` from every vless inbound under both ports.
    Returns True if the config file was modified.
    """
    p = Path(path) if path else CONFIG_FILE
    cfg = _load_config(p)
    if cfg is None:
        return False
    targets = {email_for(port, username) for port in INBOUND_PORTS}
    changed = False
    for ib in cfg.get('inbounds') or []:
        if ib.get('protocol') != 'vless':
            continue
        clients = ib.get('settings', {}).get('clients') or []
        kept = [c for c in clients if c.get('email') not in targets]
        if len(kept) != len(clients):
            ib['settings']['clients'] = kept
            changed = True
    if changed:
        _save_config(p, cfg)
    return changed


def reload_async():
    """Restart xray asynchronously via systemd-run so the HTTP response is not
    held by the restart and the new xray inherits no SSH parent.
    """
    try:
        subprocess.Popen(
            ['systemd-run', '--no-block', '--unit', f'xray-reload-{int(time.time())}',
             'systemctl', 'restart', 'xray'],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
    except Exception:
        pass
