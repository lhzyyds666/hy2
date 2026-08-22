#!/usr/bin/env bash
set -euo pipefail
umask 077

HY_DIR="${HY2_HY_DIR:-/root/hysteria}"
archive="${1:-}"
MAX_ARCHIVE_BYTES="${HY2_RESTORE_MAX_ARCHIVE_BYTES:-335544320}"
MAX_MEMBERS="${HY2_RESTORE_MAX_MEMBERS:-4096}"
MAX_FILE_BYTES="${HY2_RESTORE_MAX_FILE_BYTES:-67108864}"
MAX_TOTAL_BYTES="${HY2_RESTORE_MAX_TOTAL_BYTES:-268435456}"

if [[ "$HY_DIR" != /* || "$HY_DIR" == / || "/$HY_DIR/" == *'/../'* || "/$HY_DIR/" == *'/./'* ]]; then
  printf 'HY2_HY_DIR must be a canonical absolute non-root path\n' >&2
  exit 2
fi

if [[ -z "$archive" ]]; then
  printf 'Usage: %s /path/to/hy2-backup.tar.gz[.enc]\n' "$0" >&2
  exit 2
fi
if [[ ! -f "$archive" ]]; then
  printf 'Archive not found: %s\n' "$archive" >&2
  exit 2
fi

work="$(mktemp -d)"
staged_archive="$work/archive.input"
tarball="$staged_archive"
extract_root="$work/extracted"

cleanup() {
  rm -rf "$work"
}
trap cleanup EXIT

checksum_file="$archive.sha256"
if [[ ! -f "$checksum_file" ]]; then
  printf 'Checksum sidecar not found: %s\n' "$checksum_file" >&2
  exit 2
fi

# Validate the sidecar grammar and referenced name before calculating the
# digest. Never pass an untrusted sidecar directly to `sha256sum -c`: doing so
# would let it select a different local path.
#
# Hash and copy through the same source descriptor. The exact bytes covered by
# the checksum become the private snapshot used below, so replacing or
# modifying the source archive cannot create a validation/extraction
# time-of-check/time-of-use gap.
python3 - "$archive" "$staged_archive" "$checksum_file" \
  "$(basename -- "$archive")" "$MAX_ARCHIVE_BYTES" <<'PY'
import hashlib
import hmac
import os
import re
import stat
import sys
from pathlib import Path

archive = Path(sys.argv[1])
staged_archive = Path(sys.argv[2])
sidecar = Path(sys.argv[3])
archive_name = sys.argv[4]

try:
    max_archive_bytes = int(sys.argv[5])
except ValueError:
    print('HY2_RESTORE_MAX_ARCHIVE_BYTES must be a positive integer', file=sys.stderr)
    raise SystemExit(2)
if max_archive_bytes < 1:
    print('HY2_RESTORE_MAX_ARCHIVE_BYTES must be a positive integer', file=sys.stderr)
    raise SystemExit(2)

try:
    raw = sidecar.read_bytes()
except OSError as exc:
    print(f'Cannot read checksum sidecar: {sidecar} ({exc})', file=sys.stderr)
    raise SystemExit(2)

if len(raw) > 4096:
    print(f'Invalid checksum sidecar: {sidecar}', file=sys.stderr)
    raise SystemExit(2)
try:
    lines = raw.decode('ascii').splitlines()
except UnicodeDecodeError:
    print(f'Invalid checksum sidecar: {sidecar}', file=sys.stderr)
    raise SystemExit(2)
if len(lines) != 1:
    print(f'Invalid checksum sidecar: {sidecar}', file=sys.stderr)
    raise SystemExit(2)

match = re.fullmatch(r'([0-9a-fA-F]{64}) ([ *])(.+)', lines[0])
if match is None:
    print(f'Invalid checksum sidecar: {sidecar}', file=sys.stderr)
    raise SystemExit(2)

referenced_name = match.group(3)
if (
    referenced_name != archive_name
    or '/' in referenced_name
    or '\\' in referenced_name
    or referenced_name in {'.', '..'}
):
    print(
        'Checksum sidecar must reference the archive basename only',
        file=sys.stderr,
    )
    raise SystemExit(2)

digest = hashlib.sha256()
copied = 0
try:
    with archive.open('rb') as source:
        source_stat = os.fstat(source.fileno())
        if not stat.S_ISREG(source_stat.st_mode):
            print(f'Archive is not a regular file: {archive}', file=sys.stderr)
            raise SystemExit(2)
        if source_stat.st_size > max_archive_bytes:
            print(
                f'Archive exceeds the '
                f'{max_archive_bytes}-byte compressed-size limit',
                file=sys.stderr,
            )
            raise SystemExit(1)
        with staged_archive.open('xb') as output:
            for chunk in iter(lambda: source.read(1024 * 1024), b''):
                copied += len(chunk)
                if copied > max_archive_bytes:
                    print(
                        f'Archive exceeds the '
                        f'{max_archive_bytes}-byte compressed-size limit',
                        file=sys.stderr,
                    )
                    raise SystemExit(1)
                digest.update(chunk)
                output.write(chunk)
            output.flush()
            os.fsync(output.fileno())
except OSError as exc:
    print(f'Cannot stage archive: {archive} ({exc})', file=sys.stderr)
    raise SystemExit(2)

if not hmac.compare_digest(digest.hexdigest().lower(), match.group(1).lower()):
    print(f'Checksum mismatch for archive: {archive}', file=sys.stderr)
    raise SystemExit(1)
PY

pass_arg=()
if [[ "$archive" == *.enc ]]; then
  if [[ -n "${HY2_RESTORE_PASSPHRASE_FILE:-}" ]]; then
    pass_arg=(-pass "file:$HY2_RESTORE_PASSPHRASE_FILE")
  elif [[ -n "${HY2_BACKUP_PASSPHRASE_FILE:-}" ]]; then
    pass_arg=(-pass "file:$HY2_BACKUP_PASSPHRASE_FILE")
  elif [[ -n "${HY2_RESTORE_PASSPHRASE:-}" ]]; then
    pass_arg=(-pass env:HY2_RESTORE_PASSPHRASE)
  elif [[ -n "${HY2_BACKUP_PASSPHRASE:-}" ]]; then
    pass_arg=(-pass env:HY2_BACKUP_PASSPHRASE)
  else
    printf 'Encrypted archive requires HY2_RESTORE_PASSPHRASE_FILE or HY2_RESTORE_PASSPHRASE\n' >&2
    exit 2
  fi
  tarball="$work/archive.tar.gz"
  openssl enc -d -aes-256-cbc -pbkdf2 -iter 200000 -md sha256 \
    -in "$staged_archive" -out "$tarball" "${pass_arg[@]}"
fi

python3 - "$tarball" "$extract_root" \
  "$MAX_ARCHIVE_BYTES" "$MAX_MEMBERS" "$MAX_FILE_BYTES" "$MAX_TOTAL_BYTES" <<'PY'
import os
import re
import sys
import tarfile
from pathlib import Path

archive_path = Path(sys.argv[1])
destination = Path(sys.argv[2])
limit_names = (
    'HY2_RESTORE_MAX_ARCHIVE_BYTES',
    'HY2_RESTORE_MAX_MEMBERS',
    'HY2_RESTORE_MAX_FILE_BYTES',
    'HY2_RESTORE_MAX_TOTAL_BYTES',
)
limits = []
for name, raw in zip(limit_names, sys.argv[3:]):
    try:
        value = int(raw)
    except ValueError:
        print(f'{name} must be a positive integer', file=sys.stderr)
        raise SystemExit(2)
    if value < 1:
        print(f'{name} must be a positive integer', file=sys.stderr)
        raise SystemExit(2)
    limits.append(value)

max_archive_bytes, max_members, max_file_bytes, max_total_bytes = limits


def reject(reason):
    print(f'Unsafe archive: {reason}', file=sys.stderr)
    raise SystemExit(1)


def checked_parts(name):
    if not name:
        reject('member name is empty')
    if len(name.encode('utf-8', errors='surrogateescape')) > 4096:
        reject('member path exceeds 4096 bytes')
    if name.startswith('/') or '\\' in name or re.match(r'^[A-Za-z]:', name):
        reject(f'absolute or platform-ambiguous path: {name!r}')
    candidate = name.rstrip('/')
    parts = candidate.split('/')
    if not candidate or any(part in {'', '.', '..'} for part in parts):
        reject(f'path traversal or non-canonical path: {name!r}')
    if any(
        len(part.encode('utf-8', errors='surrogateescape')) > 255
        for part in parts
    ):
        reject(f'path component exceeds 255 bytes: {name!r}')
    return tuple(parts)


try:
    compressed_size = archive_path.stat().st_size
except OSError as exc:
    reject(f'cannot stat archive ({exc})')
if compressed_size > max_archive_bytes:
    reject(
        f'archive exceeds the {max_archive_bytes}-byte compressed-size limit'
    )

members = []
paths = {}
total_size = 0
try:
    with tarfile.open(archive_path, mode='r:gz') as archive_handle:
        for member_count, member in enumerate(archive_handle, start=1):
            if member_count > max_members:
                reject(f'member count exceeds the {max_members}-member limit')

            parts = checked_parts(member.name)
            if parts in paths:
                reject(f'duplicate member path: {member.name!r}')

            if member.isdir():
                if member.size != 0:
                    reject(f'directory has a non-zero payload: {member.name!r}')
                kind = 'directory'
            elif member.isfile():
                kind = 'file'
                if member.size < 0:
                    reject(f'file has a negative size: {member.name!r}')
                if member.size > max_file_bytes:
                    reject(
                        f'file exceeds the {max_file_bytes}-byte limit: '
                        f'{member.name!r}'
                    )
                total_size += member.size
                if total_size > max_total_bytes:
                    reject(
                        f'total file size exceeds the '
                        f'{max_total_bytes}-byte limit'
                    )
            else:
                # This rejects symlinks, hardlinks, character/block devices,
                # FIFOs, sockets, and unknown/vendor-specific entry types.
                reject(f'unsupported member type: {member.name!r}')

            paths[parts] = kind
            members.append((member, parts, kind))

        if not members:
            reject('archive has no members')

        file_paths = {parts for parts, kind in paths.items() if kind == 'file'}
        for parts in paths:
            for depth in range(1, len(parts)):
                if parts[:depth] in file_paths:
                    reject(
                        'regular file is also the parent of another member: '
                        f'{"/".join(parts[:depth])!r}'
                    )

        # Extraction starts only after the complete member table has passed
        # type, path, count, and expanded-size validation.
        destination.mkdir(mode=0o700)
        for _member, parts, kind in sorted(
            members, key=lambda item: len(item[1])
        ):
            if kind == 'directory':
                destination.joinpath(*parts).mkdir(
                    mode=0o700,
                    parents=True,
                    exist_ok=True,
                )

        for member, parts, kind in members:
            if kind != 'file':
                continue
            target = destination.joinpath(*parts)
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            source = archive_handle.extractfile(member)
            if source is None:
                reject(f'cannot read regular file payload: {member.name!r}')
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
            if hasattr(os, 'O_NOFOLLOW'):
                flags |= os.O_NOFOLLOW
            fd = os.open(target, flags, 0o600)
            remaining = member.size
            try:
                with source, os.fdopen(fd, 'wb', closefd=True) as output:
                    while remaining:
                        chunk = source.read(min(1024 * 1024, remaining))
                        if not chunk:
                            reject(
                                f'truncated regular file payload: '
                                f'{member.name!r}'
                            )
                        output.write(chunk)
                        remaining -= len(chunk)
            except BaseException:
                try:
                    os.close(fd)
                except OSError:
                    pass
                raise
except (tarfile.TarError, OSError, EOFError) as exc:
    reject(f'cannot safely read or extract tar archive ({exc})')
PY

python3 - "$extract_root" "$HY_DIR" <<'PY'
import hashlib
import json
import re
import sys
from pathlib import Path

try:
    import yaml
except Exception:  # pragma: no cover - deploy installs python3-yaml
    yaml = None

root = Path(sys.argv[1])
hy_dir = Path(sys.argv[2])
archive_hy_rel = Path(*hy_dir.parts[1:]) if hy_dir.is_absolute() else hy_dir
errors = []
warnings = []

json_files = []
for p in root.rglob('*.json'):
    json_files.append(p)
    try:
        data = json.loads(p.read_text(encoding='utf-8'))
    except Exception as exc:
        errors.append(f'invalid JSON: {p.relative_to(root)} ({exc})')
        continue
    rel = str(p.relative_to(root))
    if Path(rel) == archive_hy_rel / 'users.json' and not isinstance(data, dict):
        errors.append('users.json must be a JSON object')
    if (
        Path(rel) == archive_hy_rel / 'subscription_meta.json'
        and not isinstance(data, dict)
    ):
        errors.append('subscription_meta.json must be a JSON object')
    if Path(rel) == archive_hy_rel / 'state/template_versions.json':
        templates = data.get('templates') if isinstance(data, dict) else None
        if (
            not isinstance(data, dict)
            or data.get('version') != 1
            or not isinstance(templates, dict)
        ):
            errors.append('template_versions.json has an unsupported structure')
            continue
        for revision, entry in templates.items():
            text = entry.get('yaml') if isinstance(entry, dict) else None
            template_mtime = (
                entry.get('template_mtime')
                if isinstance(entry, dict)
                else None
            )
            if (
                not isinstance(revision, str)
                or not re.fullmatch(r'[0-9a-f]{64}', revision)
                or not isinstance(text, str)
                or hashlib.sha256(text.encode('utf-8')).hexdigest() != revision
                or not isinstance(template_mtime, str)
                or not re.fullmatch(r'[0-9TZ:.-]{0,40}', template_mtime)
            ):
                errors.append(
                    f'template_versions.json contains an invalid snapshot: '
                    f'{revision!r}'
                )

template = root / archive_hy_rel / 'template.yaml'
if template.exists() and yaml is not None:
    try:
        parsed = yaml.safe_load(template.read_text(encoding='utf-8')) or {}
        if not isinstance(parsed, dict):
            errors.append('template.yaml must parse to a mapping')
    except Exception as exc:
        errors.append(f'invalid YAML: {archive_hy_rel}/template.yaml ({exc})')

users = root / archive_hy_rel / 'users.json'
meta = root / archive_hy_rel / 'subscription_meta.json'
if not users.exists():
    warnings.append('users.json not present in archive')
if not meta.exists():
    warnings.append('subscription_meta.json not present in archive')

archive_files = [p for p in root.rglob('*') if p.is_file()]
overwrites = []
for p in archive_files:
    rel = p.relative_to(root)
    parts = rel.parts
    prefix_parts = archive_hy_rel.parts
    if parts[:len(prefix_parts)] == prefix_parts:
        live = hy_dir.joinpath(*parts[len(prefix_parts):])
        if live.exists():
            overwrites.append(str(live))

if errors:
    for err in errors:
        print(f'ERROR: {err}', file=sys.stderr)
    raise SystemExit(1)

print('OK: hy2 backup dry-run passed')
print(f'files={len(archive_files)}')
print(f'json_files={len(json_files)}')
print(f'would_overwrite={len(overwrites)}')
if warnings:
    for warning in warnings:
        print(f'WARN: {warning}')
if overwrites:
    print('overwrite_examples=' + ', '.join(overwrites[:5]))
PY
