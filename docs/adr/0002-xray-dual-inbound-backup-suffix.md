# Per-user xray clients are duplicated across inbound ports with a -backup suffix

xray runs two VLESS Reality inbounds on the same server — port **443** and port **8443** — so that clients have a fallback path when the primary port is blocked by a network operator. Each user must exist as a `clients[]` entry in *both* inbounds, so the same `username` is registered twice in xray configuration: once as `username` (port 443) and once as `username-backup` (port 8443). When traffic is collected via `xray statsquery`, the `-backup` suffix is stripped before aggregation, so the two ports contribute to a single per-user usage figure that is invisible to the rest of the system.

The alternative — issuing each user two distinct usernames or two distinct UUIDs — was rejected because it would have leaked the dual-port topology into the user panel, the subscription YAML, and the alert payloads, all of which want a single canonical identity per user. The `-backup` suffix keeps the duplication contained inside `xray_sync_user` / `xray_remove_user` / `get_xray_traffic`.

**Status:** accepted. Maintenance rule: any code that mutates xray clients must iterate over `XRAY_INBOUND_PORTS` and call `_xray_email_for(port, username)` for each one. Forgetting a port leaves the user reachable on one inbound and rejected on the other, with no obvious error.
