"""User-config field accessors with backward-compat for legacy field names.

Centralizes the `metered` / `guest` alias mapping so callers don't hardcode the
fallback chain. See CONTEXT.md `### User types` for the canonical vocabulary.
"""


def is_metered(cfg):
    """Return True if this user is **metered** — quota-enforced, kicked over
    quota, eligible for quota alerts. Reads canonical `metered`, falls back
    to legacy `guest`. Missing/unknown both → False.
    """
    if not isinstance(cfg, dict):
        return False
    if 'metered' in cfg:
        return bool(cfg['metered'])
    return bool(cfg.get('guest', False))
