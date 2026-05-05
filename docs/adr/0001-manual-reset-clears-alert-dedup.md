# Manual reset clears alert dedup state for the affected users

When an admin performs a **manual reset** on a user (or all users), the matching entries in `alert_state.json` (`quota_80`, `quota_100`) for those users **must be cleared** for the current cycle, so that subsequent quota crossings within the same cycle re-fire the alerts. Cycle rollover does not need this — `mark_alerted` is keyed by `cycle_key`, so a new cycle key automatically re-arms every alert without state cleanup.

The alternative — keeping dedup state across a manual reset — was rejected because manual resets are rare, deliberate operator actions ("this user gets a fresh start"); silently suppressing the next over-quota alert after a reset would be a worse failure mode than re-firing one alert the operator already knew about. The cost of accidentally spamming an operator who reset 50 users at once is bounded (one alert per user across the rest of the cycle); the cost of silently missing a real over-quota event is not.

**Status:** accepted — policy decided 2026-05-05 during grill-with-docs. Current code does **not** yet implement this behavior; `reset_usage_user` and `reset_usage_all` in `subscription_service.py` need to drop matching entries from `alert_state.json` and re-save it. Anomaly dedup (`anomaly` key, day-scoped) does not need touching — it self-resets each calendar day.
