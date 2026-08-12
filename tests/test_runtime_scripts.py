import fcntl
import hashlib
import json
import os
import subprocess
import tarfile
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def isolated_backup_env(tmp_path, hy_dir):
    lock_dir = tmp_path / 'locks'
    lock_dir.mkdir(mode=0o700)
    lock_dir.chmod(0o700)
    env = os.environ.copy()
    for name in (
        'HY2_BACKUP_PASSPHRASE',
        'HY2_BACKUP_PASSPHRASE_FILE',
        'HY2_BACKUP_REMOTE',
        'HY2_BACKUP_GIT_REPO',
    ):
        env.pop(name, None)
    env.update({
        'HY2_HY_DIR': str(hy_dir),
        'HY2_BACKUP_DIR': str(tmp_path / 'backups'),
        'HY2_XRAY_CONFIG': str(tmp_path / 'xray' / 'config.json'),
        'HY2_TUIC_CONFIG': str(hy_dir / 'tuic.json'),
        'HY2_DEPLOY_LOCK': str(lock_dir / 'deploy.lock'),
        'HY2_USAGE_LOCK': str(lock_dir / 'usage.lock'),
        'HY2_META_LOCK': str(lock_dir / 'meta.lock'),
        'HY2_TEMPLATE_LOCK': str(lock_dir / 'template.lock'),
        'HY2_XRAY_LOCK': str(lock_dir / 'xray.lock'),
        'HY2_TUIC_LOCK': str(lock_dir / 'tuic.lock'),
    })
    return env


def write_checksum(archive, *, referenced_name=None, digest=None):
    archive = Path(archive)
    actual_digest = digest or hashlib.sha256(archive.read_bytes()).hexdigest()
    sidecar = archive.with_name(archive.name + '.sha256')
    sidecar.write_text(
        f'{actual_digest}  {referenced_name or archive.name}\n',
        encoding='ascii',
    )
    return sidecar


def test_backup_excludes_live_login_sessions(tmp_path):
    hy_dir = tmp_path / 'hysteria'
    state_dir = hy_dir / 'state'
    state_dir.mkdir(parents=True)
    (hy_dir / 'users.json').write_text('{}')
    (state_dir / 'usage.json').write_text('{}')
    (state_dir / 'panel_sessions.json').write_text('{"sid":{"exp":9999999999}}')
    (state_dir / 'user_panel_sessions.json').write_text('{"usid":{"exp":9999999999}}')
    (state_dir / 'credential_rotation_receipts.json').write_text(
        '{"receipt":{"new_token":"must-not-be-backed-up"}}',
    )
    (state_dir / 'credential_revocations.json').write_text(
        '{"task":{"user":"alice"}}',
    )
    (state_dir / 'template_versions.json').write_text(
        '{"version":1,"templates":{}}',
    )

    env = isolated_backup_env(tmp_path, hy_dir)
    result = subprocess.run(
        ['bash', str(ROOT / 'scripts/hy2-backup.sh')],
        check=True,
        capture_output=True,
        text=True,
        env=env,
    )

    archive = result.stdout.strip()
    with tarfile.open(archive, 'r:gz') as tf:
        names = tf.getnames()

    assert any(name.endswith('/users.json') for name in names)
    assert any(name.endswith('/state/usage.json') for name in names)
    assert any(name.endswith('/state/template_versions.json') for name in names)
    assert not any(name.endswith('/state/panel_sessions.json') for name in names)
    assert not any(name.endswith('/state/user_panel_sessions.json') for name in names)
    assert not any(
        name.endswith('/state/credential_rotation_receipts.json')
        for name in names
    )
    assert not any(
        name.endswith('/state/credential_revocations.json')
        for name in names
    )


def test_restore_check_accepts_plain_backup_archive(tmp_path):
    hy_dir = tmp_path / 'hysteria'
    state_dir = hy_dir / 'state'
    state_dir.mkdir(parents=True)
    (hy_dir / 'users.json').write_text('{}')
    (hy_dir / 'subscription_meta.json').write_text('{}')
    (hy_dir / 'template.yaml').write_text('proxies: []\nrules: []\n')
    (state_dir / 'usage.json').write_text('{}')
    snapshot_text = 'proxies: []\nproxy-groups: []\nrules: []\n'
    snapshot_revision = hashlib.sha256(snapshot_text.encode()).hexdigest()
    (state_dir / 'template_versions.json').write_text(json.dumps({
        'version': 1,
        'templates': {
            snapshot_revision: {
                'yaml': snapshot_text,
                'created_at': '2026-08-12T00:00:00Z',
                'template_mtime': '2026-08-12T00:00:00Z',
            },
        },
    }))

    env = isolated_backup_env(tmp_path, hy_dir)
    archive = subprocess.run(
        ['bash', str(ROOT / 'scripts/hy2-backup.sh')],
        check=True,
        capture_output=True,
        text=True,
        env=env,
    ).stdout.strip()

    result = subprocess.run(
        ['bash', str(ROOT / 'scripts/hy2-restore-check.sh'), archive],
        check=True,
        capture_output=True,
        text=True,
        env=env,
    )

    assert 'OK: hy2 backup dry-run passed' in result.stdout
    assert 'would_overwrite=' in result.stdout


def test_restore_check_rejects_corrupt_template_snapshot(tmp_path):
    hy_dir = tmp_path / 'hysteria'
    state_dir = hy_dir / 'state'
    state_dir.mkdir(parents=True)
    (hy_dir / 'users.json').write_text('{}')
    (hy_dir / 'subscription_meta.json').write_text('{}')
    (state_dir / 'template_versions.json').write_text(json.dumps({
        'version': 1,
        'templates': {
            'a' * 64: {
                'yaml': 'rules: []\n',
                'created_at': '2026-08-12T00:00:00Z',
                'template_mtime': '2026-08-12T00:00:00Z',
            },
        },
    }))
    env = isolated_backup_env(tmp_path, hy_dir)
    archive = subprocess.run(
        ['bash', str(ROOT / 'scripts/hy2-backup.sh')],
        check=True,
        capture_output=True,
        text=True,
        env=env,
    ).stdout.strip()

    result = subprocess.run(
        ['bash', str(ROOT / 'scripts/hy2-restore-check.sh'), archive],
        check=False,
        capture_output=True,
        text=True,
        env=env,
    )

    assert result.returncode != 0
    assert 'template_versions.json contains an invalid snapshot' in result.stderr


def test_backup_encryption_and_restore_check(tmp_path):
    hy_dir = tmp_path / 'hysteria'
    hy_dir.mkdir(parents=True)
    (hy_dir / 'users.json').write_text('{}')
    (hy_dir / 'subscription_meta.json').write_text('{}')

    env = isolated_backup_env(tmp_path, hy_dir)
    env['HY2_BACKUP_PASSPHRASE'] = 'test-passphrase'
    archive = subprocess.run(
        ['bash', str(ROOT / 'scripts/hy2-backup.sh')],
        check=True,
        capture_output=True,
        text=True,
        env=env,
    ).stdout.strip()

    assert archive.endswith('.tar.gz.enc')
    result = subprocess.run(
        ['bash', str(ROOT / 'scripts/hy2-restore-check.sh'), archive],
        check=True,
        capture_output=True,
        text=True,
        env=env,
    )
    assert 'OK: hy2 backup dry-run passed' in result.stdout


def test_backup_script_has_retention_guard():
    script = (ROOT / 'scripts/hy2-backup.sh').read_text(encoding='utf-8')

    assert 'BACKUP_KEEP="${HY2_BACKUP_KEEP:-14}"' in script
    assert 'prune_old_backups "$BACKUP_KEEP"' in script
    assert "hy2-backup-*.tar.gz.enc" in script


def test_backup_flushes_archive_sidecar_and_directory_before_publish():
    script = (ROOT / 'scripts/hy2-backup.sh').read_text(encoding='utf-8')

    flush = script.index('fsync_backup_pair "$out" "$out.sha256"')
    prune = script.index('prune_old_backups "$BACKUP_KEEP"', flush)
    remote = script.index('HY2_BACKUP_REMOTE', flush)
    git = script.index('HY2_BACKUP_GIT_REPO', flush)

    assert 'os.fsync(fd)' in script
    assert 'getattr(os, "O_DIRECTORY", 0)' in script
    assert flush < prune
    assert flush < remote
    assert flush < git


def test_backup_holds_all_snapshot_locks_until_tar_can_start(tmp_path):
    hy_dir = tmp_path / 'hysteria'
    hy_dir.mkdir(parents=True)
    (hy_dir / 'users.json').write_text('{}')
    env = isolated_backup_env(tmp_path, hy_dir)
    lock_names = (
        'HY2_DEPLOY_LOCK',
        'HY2_USAGE_LOCK',
        'HY2_META_LOCK',
        'HY2_TEMPLATE_LOCK',
        'HY2_XRAY_LOCK',
    )
    tuic_lock = Path(env['HY2_TUIC_LOCK'])
    tuic_lock.parent.mkdir(parents=True, exist_ok=True)

    with tuic_lock.open('a+') as blocker:
        fcntl.flock(blocker.fileno(), fcntl.LOCK_EX)
        proc = subprocess.Popen(
            ['bash', str(ROOT / 'scripts/hy2-backup.sh')],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=env,
        )
        all_held = False
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and proc.poll() is None:
            held = []
            for name in lock_names:
                path = Path(env[name])
                path.parent.mkdir(parents=True, exist_ok=True)
                with path.open('a+') as candidate:
                    try:
                        fcntl.flock(
                            candidate.fileno(),
                            fcntl.LOCK_EX | fcntl.LOCK_NB,
                        )
                    except BlockingIOError:
                        held.append(True)
                    else:
                        fcntl.flock(candidate.fileno(), fcntl.LOCK_UN)
                        held.append(False)
            if all(held):
                all_held = True
                break
            time.sleep(0.02)
        remained_blocked = proc.poll() is None
        fcntl.flock(blocker.fileno(), fcntl.LOCK_UN)

    stdout, stderr = proc.communicate(timeout=5)
    assert remained_blocked, stderr
    assert all_held, stderr
    assert proc.returncode == 0, stderr
    assert Path(stdout.strip()).is_file()


def test_backup_acquires_snapshot_locks_in_safe_fixed_order():
    script = (ROOT / 'scripts/hy2-backup.sh').read_text(encoding='utf-8')
    acquisitions = [
        script.index('flock -x 10'),
        script.index('flock -x 11'),
        script.index('flock -x 12'),
        script.index('flock -x 13'),
        script.index('flock -x 14'),
    ]

    assert acquisitions == sorted(acquisitions)
    deploy_lock = script.index(
        '--marker-env "$DEPLOY_LOCK_MARKER_ENV"',
    )
    tar_call = script.index(
        'tar -C / -czf "$tmp_tar" --files-from "$manifest"',
    )
    assert deploy_lock < acquisitions[0] < tar_call
    release_call = script.index(
        '\nrelease_snapshot_locks\n',
        acquisitions[-1],
    )
    assert tar_call < release_call
    assert release_call < script.index(
        'openssl enc -aes-256-cbc',
    )


def test_restore_check_rejects_invalid_json(tmp_path):
    root = tmp_path / 'payload'
    target = root / 'root/hysteria'
    target.mkdir(parents=True)
    (target / 'users.json').write_text('{bad json')
    archive = tmp_path / 'bad.tar.gz'
    with tarfile.open(archive, 'w:gz') as tf:
        tf.add(target / 'users.json', arcname='root/hysteria/users.json')
    write_checksum(archive)

    result = subprocess.run(
        ['bash', str(ROOT / 'scripts/hy2-restore-check.sh'), str(archive)],
        capture_output=True,
        text=True,
        env=isolated_backup_env(tmp_path, tmp_path / 'live'),
    )

    assert result.returncode != 0
    assert 'invalid JSON' in result.stderr


def test_restore_check_rejects_missing_checksum_before_unpack(tmp_path):
    archive = tmp_path / 'backup.tar.gz'
    archive.write_bytes(b'not a tar archive')

    result = subprocess.run(
        ['bash', str(ROOT / 'scripts/hy2-restore-check.sh'), str(archive)],
        capture_output=True,
        text=True,
        env=isolated_backup_env(tmp_path, tmp_path / 'live'),
    )

    assert result.returncode != 0
    assert 'Checksum sidecar not found' in result.stderr
    assert 'tar:' not in result.stderr


def test_restore_check_rejects_tampered_archive_before_decryption(tmp_path):
    archive = tmp_path / 'backup.tar.gz.enc'
    archive.write_bytes(b'original encrypted bytes')
    write_checksum(archive)
    archive.write_bytes(b'tampered encrypted bytes')

    result = subprocess.run(
        ['bash', str(ROOT / 'scripts/hy2-restore-check.sh'), str(archive)],
        capture_output=True,
        text=True,
        env=isolated_backup_env(tmp_path, tmp_path / 'live'),
    )

    assert result.returncode != 0
    assert 'Checksum mismatch for archive' in result.stderr
    assert 'requires HY2_RESTORE_PASSPHRASE' not in result.stderr


def test_restore_check_rejects_checksum_path_tricks(tmp_path):
    archive = tmp_path / 'backup.tar.gz'
    archive.write_bytes(b'archive bytes')
    write_checksum(archive, referenced_name=f'../{archive.name}')

    result = subprocess.run(
        ['bash', str(ROOT / 'scripts/hy2-restore-check.sh'), str(archive)],
        capture_output=True,
        text=True,
        env=isolated_backup_env(tmp_path, tmp_path / 'live'),
    )

    assert result.returncode != 0
    assert 'archive basename only' in result.stderr


def test_nginx_template_and_deploy_render_server_host():
    conf = (ROOT / 'nginx/hysteria-panel.conf').read_text(encoding='utf-8')
    deploy = (ROOT / 'deploy.sh').read_text(encoding='utf-8')

    assert 'server_name __HY_SERVER_HOST__;' in conf
    assert 'if ($host != "__HY_SERVER_HOST__") { return 421; }' in conf
    assert 'proxy_set_header Host __HY_SERVER_HOST__;' in conf
    assert 'render "$REPO_DIR/nginx/hysteria-panel.conf"' in deploy


def test_deploy_renders_display_multiplier():
    deploy = (ROOT / 'deploy.sh').read_text(encoding='utf-8')
    renderer = (
        ROOT / 'scripts/hy2-render-template.py'
    ).read_text(encoding='utf-8')
    env_example = (ROOT / '.env.example').read_text(encoding='utf-8')

    assert 'HY_DISPLAY_MULTIPLIER="${HY_DISPLAY_MULTIPLIER:-2.28}"' in deploy
    assert (
        '"__HY_DISPLAY_MULTIPLIER__": "HY_DISPLAY_MULTIPLIER"'
        in renderer
    )
    assert 'scripts/hy2-render-template.py' in deploy
    assert 'HY_DISPLAY_MULTIPLIER=2.28' in env_example


def test_deploy_installs_cost_calibrator_module():
    deploy = (ROOT / 'deploy.sh').read_text(encoding='utf-8')

    assert 'hysteria/cost_calibrator.py' in deploy
    assert '$HY_DIR/cost_calibrator.py' in deploy


def test_deploy_installs_incident_console_module():
    deploy = (ROOT / 'deploy.sh').read_text(encoding='utf-8')

    assert 'hysteria/incident_console.py' in deploy
    assert '$HY_DIR/incident_console.py' in deploy


def test_deploy_installs_online_snapshot_module():
    deploy = (ROOT / 'deploy.sh').read_text(encoding='utf-8')

    assert 'hysteria/online_snapshot.py' in deploy
    assert '$HY_DIR/online_snapshot.py' in deploy


def test_deploy_installs_health_widgets_module():
    deploy = (ROOT / 'deploy.sh').read_text(encoding='utf-8')

    assert 'hysteria/health_widgets.py' in deploy
    assert '$HY_DIR/health_widgets.py' in deploy


def test_deploy_installs_usage_dashboard_module():
    deploy = (ROOT / 'deploy.sh').read_text(encoding='utf-8')

    assert 'hysteria/usage_dashboard.py' in deploy
    assert '$HY_DIR/usage_dashboard.py' in deploy


def test_deploy_installs_subscription_profiles_module():
    deploy = (ROOT / 'deploy.sh').read_text(encoding='utf-8')

    assert 'hysteria/subscription_profiles.py' in deploy
    assert '$HY_DIR/subscription_profiles.py' in deploy


def test_deploy_installs_tuic_meter_module_and_nftables():
    deploy = (ROOT / 'deploy.sh').read_text(encoding='utf-8')

    assert ' nftables ' in deploy
    assert 'hysteria/tuic_meter.py' in deploy
    assert '$HY_DIR/tuic_meter.py' in deploy


def test_deploy_installs_and_enables_backup_timer():
    deploy = (ROOT / 'deploy.sh').read_text(encoding='utf-8')
    service = (ROOT / 'systemd/hy2-backup.service').read_text(encoding='utf-8')

    assert 'systemd/hy2-backup.service' in deploy
    assert 'systemd/hy2-backup.timer' in deploy
    assert 'systemctl enable --now hy2-backup.timer' in deploy
    read_write_paths = next(
        line for line in service.splitlines()
        if line.startswith('ReadWritePaths=')
    )
    assert read_write_paths.removeprefix('ReadWritePaths=').split() == [
        '/root/hysteria',
        '/usr/local/etc/xray/config.json.lock',
    ]


def test_deploy_installs_xray_logrotate_config():
    deploy = (ROOT / 'deploy.sh').read_text(encoding='utf-8')
    config = (ROOT / 'logrotate/xray').read_text(encoding='utf-8')

    assert ' logrotate ' in deploy
    assert 'logrotate/xray' in deploy
    assert '/etc/logrotate.d/xray' in deploy
    assert '/var/log/xray/*.log' in config
    assert 'maxsize 20M' in config
    assert 'copytruncate' in config


def test_traffic_limiter_unit_can_access_nftables():
    unit = (ROOT / 'systemd/hysteria-traffic-limiter.service').read_text(encoding='utf-8')

    assert 'AmbientCapabilities=CAP_NET_ADMIN' in unit
    assert 'CapabilityBoundingSet=CAP_NET_ADMIN' in unit
    assert 'AF_NETLINK' in unit
    assert 'Group=hy2-xray' in unit


def test_traffic_limiter_timer_runs_every_90_seconds():
    timer = (ROOT / 'systemd/hysteria-traffic-limiter.timer').read_text(encoding='utf-8')

    assert 'OnUnitActiveSec=90s' in timer
    assert 'AccuracySec=10s' in timer
    assert 'OnUnitActiveSec=30s' not in timer
    assert 'OnUnitActiveSec=15s' not in timer
    assert 'OnUnitActiveSec=5s' not in timer


def test_xray_template_uses_ipv4_outbound_strategy():
    cfg = (ROOT / 'xray/config.json.tpl').read_text(encoding='utf-8')

    assert '"domainStrategy": "UseIPv4"' in cfg


def test_deploy_installs_restore_check_script():
    deploy = (ROOT / 'deploy.sh').read_text(encoding='utf-8')

    assert 'hy2-restore-check.sh' in deploy
    assert '/usr/local/sbin/hy2-restore-check.sh' in deploy


def test_hysteria_service_restarts_and_waits_for_network_online():
    unit = (ROOT / 'systemd/hysteria-server.service').read_text(encoding='utf-8')

    assert 'Restart=on-failure' in unit
    assert 'After=network-online.target' in unit
    assert 'CapabilityBoundingSet=CAP_NET_BIND_SERVICE' in unit


def test_https_templates_preserve_acme_and_use_dedicated_port():
    plain = (ROOT / 'nginx/hysteria-panel.conf').read_text(encoding='utf-8')
    redirect = (ROOT / 'nginx/hysteria-panel-redirect.conf').read_text(encoding='utf-8')
    tls = (ROOT / 'nginx/hysteria-panel-https.conf').read_text(encoding='utf-8')

    assert '/.well-known/acme-challenge/' in plain
    assert '/.well-known/acme-challenge/' in redirect
    assert 'https://__HY_SERVER_HOST__:__HY_HTTPS_PORT__$request_uri' in redirect
    assert 'listen __HY_HTTPS_PORT__ ssl;' in tls
    assert 'proxy_set_header X-Forwarded-Proto https;' in tls
    assert 'proxy_set_header X-Forwarded-Port $server_port;' in tls
    assert 'Strict-Transport-Security "max-age=31536000" always;' in tls
    assert 'gzip on;' in plain
    assert 'gzip on;' in tls
    assert 'application/json' in tls


def test_deploy_installs_monitoring_fail2ban_and_journal_limits():
    deploy = (ROOT / 'deploy.sh').read_text(encoding='utf-8')

    assert 'hy2-health-check.timer' in deploy
    assert 'fail2ban/filter.d/tuic-auth.conf' in deploy
    assert 'journald/60-hy2-limits.conf' in deploy
    assert 'systemd/xray.service.d/20-hy2-hardening.conf' in deploy


def test_deploy_pins_proxy_binary_versions():
    deploy = (ROOT / 'deploy.sh').read_text(encoding='utf-8')

    assert 'readonly HYSTERIA_PINNED_VERSION=v2.9.3' in deploy
    assert (
        'HY_HYSTERIA_VERSION="${HY_HYSTERIA_VERSION:-'
        '$HYSTERIA_PINNED_VERSION}"'
    ) in deploy
    assert 'HY_HYSTERIA_VERSION is not in the checksum allowlist' in deploy
    assert (
        'HY_XRAY_VERSION="${HY_XRAY_VERSION:-$XRAY_PINNED_VERSION}"'
        in deploy
    )
    assert 'sha256sum -c -' in deploy


def test_backup_remote_requires_encryption():
    script = (ROOT / 'scripts/hy2-backup.sh').read_text(encoding='utf-8')

    assert 'Refusing off-host upload of an unencrypted backup' in script
    assert 'rclone copyto' in script
    assert 'Refusing Git upload of an unencrypted backup' in script
    assert 'git_backup.last' in script


def test_git_backup_uploader_force_pushes_one_rolling_snapshot(tmp_path):
    backups = tmp_path / 'backups'
    backups.mkdir()
    remote = tmp_path / 'remote.git'
    subprocess.run(['git', 'init', '--bare', '-q', str(remote)], check=True)

    for idx in range(3):
        archive = backups / f'hy2-backup-2026070{idx + 1}T000000Z.tar.gz.enc'
        archive.write_bytes(f'encrypted-{idx}'.encode())
        digest = hashlib.sha256(archive.read_bytes()).hexdigest()
        archive.with_name(archive.name + '.sha256').write_text(
            f'{digest}  {archive.name}\n', encoding='utf-8')

    env = os.environ.copy()
    env['HY2_BACKUP_GIT_REPO'] = str(remote)
    env['HY2_BACKUP_GIT_KEEP'] = '2'
    subprocess.run(
        ['bash', str(ROOT / 'scripts/hy2-backup-git.sh'), str(backups)],
        check=True, capture_output=True, text=True, env=env)

    checkout = tmp_path / 'checkout'
    subprocess.run(
        ['git', 'clone', '-q', '--branch', 'main', str(remote), str(checkout)],
        check=True)
    uploaded = sorted((checkout / 'backups').glob('*.tar.gz.enc'))
    assert [p.name for p in uploaded] == [
        'hy2-backup-20260702T000000Z.tar.gz.enc',
        'hy2-backup-20260703T000000Z.tar.gz.enc',
    ]
    assert not list((checkout / 'backups').glob('*.tar.gz'))
    checksum = uploaded[-1].with_name(uploaded[-1].name + '.sha256').read_text()
    assert '/root/' not in checksum
    commit_count = subprocess.run(
        ['git', '-C', str(checkout), 'rev-list', '--count', 'HEAD'],
        check=True, capture_output=True, text=True).stdout.strip()
    assert commit_count == '1'


def test_deploy_installs_git_backup_uploader():
    deploy = (ROOT / 'deploy.sh').read_text(encoding='utf-8')

    assert 'scripts/hy2-backup-git.sh' in deploy
    assert '/usr/local/sbin/hy2-backup-git.sh' in deploy
