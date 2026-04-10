#!/usr/bin/env bash
set -euo pipefail

PORT_RANGE="20000:40000"
TARGET_PORT="443"

iptables -t nat -C PREROUTING -p udp --dport "$PORT_RANGE" -j REDIRECT --to-ports "$TARGET_PORT" 2>/dev/null \
  || iptables -t nat -A PREROUTING -p udp --dport "$PORT_RANGE" -j REDIRECT --to-ports "$TARGET_PORT"

if command -v ip6tables >/dev/null 2>&1; then
  ip6tables -t nat -C PREROUTING -p udp --dport "$PORT_RANGE" -j REDIRECT --to-ports "$TARGET_PORT" 2>/dev/null \
    || ip6tables -t nat -A PREROUTING -p udp --dport "$PORT_RANGE" -j REDIRECT --to-ports "$TARGET_PORT" || true
fi
