"""Z-score anomaly detection for daily traffic totals.

All math operates on raw bytes (pre-DISPLAY_MULTIPLIER). Scaling is a
display concern handled in the alert formatter, not here.
"""
from datetime import timedelta
from statistics import mean, pstdev

DEFAULT_Z_THRESHOLD = 3.0
DEFAULT_MIN_BYTES = 1 << 30  # 1 GiB


def detect(uid, daily, today, *, z_threshold=DEFAULT_Z_THRESHOLD,
           min_bytes=DEFAULT_MIN_BYTES):
    """Return an anomaly record for `uid` on `today`, or None.

    Args:
        uid:          user id (string)
        daily:        {YYYY-MM-DD: {uid: int | {'tx','rx','total'}}}
        today:        a `datetime.date`
        z_threshold:  flag if z > this
        min_bytes:    floor below which today's traffic is ignored

    Returns: {"user", "today", "mean", "stdev", "z"} or None
    """
    today_total = _entry_total((daily.get(today.strftime('%Y-%m-%d')) or {}).get(uid))
    if today_total < min_bytes:
        return None

    history = []
    for i in range(1, 8):
        dk = (today - timedelta(days=i)).strftime('%Y-%m-%d')
        v = _entry_total((daily.get(dk) or {}).get(uid))
        if v > 0:
            history.append(v)
    if len(history) < 3:
        return None

    h_mean = mean(history)
    h_stdev = pstdev(history)

    if h_stdev == 0:
        if today_total > 2 * h_mean:
            return {'user': uid, 'today': today_total, 'mean': h_mean,
                    'stdev': 0.0, 'z': float('inf')}
        return None

    z = (today_total - h_mean) / h_stdev
    if z > z_threshold:
        return {'user': uid, 'today': today_total, 'mean': h_mean,
                'stdev': h_stdev, 'z': z}
    return None


def _entry_total(entry):
    if not entry:
        return 0
    if isinstance(entry, dict):
        return int(entry.get('total', int(entry.get('tx', 0)) + int(entry.get('rx', 0))))
    return int(entry or 0)
