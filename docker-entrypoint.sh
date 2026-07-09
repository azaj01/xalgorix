#!/usr/bin/env bash
# Container entrypoint for the Xalgorix image.
#
# The image binds 0.0.0.0 (so the published port works), but the engine refuses
# to bind a non-loopback address without dashboard auth. Rather than fail a
# plain `docker run`, we generate a random admin password when none is supplied,
# print it once, and start. Operators can override by passing their own
# XALGORIX_USERNAME + XALGORIX_PASSWORD (or XALGORIX_PASSWORD_HASH).
set -euo pipefail

bind="${XALGORIX_BIND:-0.0.0.0}"

# Is the bind address loopback (no auth required by the engine)?
is_loopback=false
case "$bind" in
  127.0.0.1 | localhost | ::1 | "") is_loopback=true ;;
esac

# Is dashboard auth already configured?
has_auth=false
if [ -n "${XALGORIX_USERNAME:-}" ] && { [ -n "${XALGORIX_PASSWORD:-}" ] || [ -n "${XALGORIX_PASSWORD_HASH:-}" ]; }; then
  has_auth=true
fi

if [ "$is_loopback" = false ] && [ "$has_auth" = false ]; then
  export XALGORIX_USERNAME="${XALGORIX_USERNAME:-admin}"
  export XALGORIX_PASSWORD="$(openssl rand -base64 24 | tr -dc 'A-Za-z0-9' | head -c 20)"
  echo "============================================================"
  echo "  Xalgorix — no dashboard auth was provided."
  echo "  Generated one-time credentials so the container can start:"
  echo ""
  echo "      username: ${XALGORIX_USERNAME}"
  echo "      password: ${XALGORIX_PASSWORD}"
  echo ""
  echo "  Override by setting XALGORIX_USERNAME + XALGORIX_PASSWORD"
  echo "  (or XALGORIX_PASSWORD_HASH). Rotate these before exposing"
  echo "  the dashboard on an untrusted network."
  echo "============================================================"
fi

exec xalgorix "$@"
