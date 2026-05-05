"""Z-score anomaly detection — math runs on raw bytes, no I/O."""
from datetime import date, timedelta

from anomaly import detect

GiB = 1 << 30


def _hist(uid, today, values):
    """Build a `daily` dict where index 0 of `values` is today, 1 is yesterday, ..."""
    out = {}
    for i, v in enumerate(values):
        dk = (today - timedelta(days=i)).strftime('%Y-%m-%d')
        out[dk] = {uid: {'tx': 0, 'rx': v, 'total': v}}
    return out


def test_returns_none_when_today_below_min_bytes():
    today = date(2026, 5, 5)
    daily = _hist('alice', today, [500_000_000, 1, 1, 1])  # 500 MB today
    assert detect('alice', daily, today) is None


def test_returns_none_when_history_too_short():
    today = date(2026, 5, 5)
    # only 2 prior non-zero days
    daily = _hist('alice', today, [10 * GiB, 100, 100])
    assert detect('alice', daily, today) is None


def test_flags_when_zscore_over_threshold():
    today = date(2026, 5, 5)
    # baseline ~ 1 GiB, today 20 GiB → very high z
    daily = _hist('alice', today, [20 * GiB, GiB, GiB, GiB, GiB, GiB, GiB, GiB])
    out = detect('alice', daily, today, z_threshold=3.0)
    assert out is not None
    assert out['user'] == 'alice'
    assert out['today'] == 20 * GiB
    assert out['z'] > 3.0


def test_does_not_flag_when_zscore_below_threshold():
    today = date(2026, 5, 5)
    # noisy baseline matching today
    daily = _hist('alice', today, [10 * GiB, 8 * GiB, 12 * GiB, 9 * GiB, 11 * GiB,
                                    10 * GiB, 9 * GiB, 11 * GiB])
    assert detect('alice', daily, today, z_threshold=3.0) is None


def test_zero_stdev_requires_double_mean():
    today = date(2026, 5, 5)
    daily = _hist('alice', today, [3 * GiB, GiB, GiB, GiB])  # stdev=0, today=3*mean
    out = detect('alice', daily, today)
    assert out is not None and out['stdev'] == 0.0


def test_zero_stdev_skipped_if_only_slightly_above():
    today = date(2026, 5, 5)
    daily = _hist('alice', today, [int(1.5 * GiB), GiB, GiB, GiB])
    assert detect('alice', daily, today) is None


def test_returns_none_for_unknown_user():
    today = date(2026, 5, 5)
    daily = _hist('alice', today, [10 * GiB] * 8)
    assert detect('bob', daily, today) is None


def test_handles_int_only_legacy_entries():
    today = date(2026, 5, 5)
    daily = {}
    for i in range(8):
        dk = (today - timedelta(days=i)).strftime('%Y-%m-%d')
        daily[dk] = {'alice': (20 * GiB if i == 0 else GiB)}  # int legacy form
    out = detect('alice', daily, today)
    assert out is not None and out['today'] == 20 * GiB
