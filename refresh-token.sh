#!/bin/bash
# refresh-token.sh — Auto-refresh Claude OAuth token for the billing proxy
#
# Problem:
#   Claude Code stores refreshed OAuth tokens in macOS Keychain, but the proxy
#   reads from ~/.claude/.credentials.json. The file goes stale after ~8h when
#   the token expires, causing the proxy to 401 on every request.
#
# Solution:
#   1. Run `claude --print "."` to trigger Claude Code's internal token refresh
#   2. Read the fresh token from macOS Keychain
#   3. Write it to the credentials JSON file
#   4. Restart the proxy via launchctl
#
# Usage:
#   ./refresh-token.sh              # manual run
#   crontab: 0 */6 * * * /path/to/refresh-token.sh   # every 6h
#
# Requirements:
#   - Claude Code CLI installed and authenticated (`claude auth login`)
#   - macOS (uses `security` CLI for Keychain access)
#   - Proxy running as launchd service (com.openclaw.billing-proxy)

set -euo pipefail

CREDS_FILE="${CLAUDE_CREDENTIALS_PATH:-$HOME/.claude/.credentials.json}"
KEYCHAIN_SERVICE="Claude Code-credentials"
LAUNCHD_LABEL="com.openclaw.billing-proxy"
PROXY_PORT="${PROXY_PORT:-18801}"

log() { echo "[refresh-token] $(date '+%Y-%m-%d %H:%M:%S') $*"; }

# Step 1: Trigger Claude Code token refresh
log "Triggering Claude Code token refresh..."
if ! claude --print "." >/dev/null 2>&1; then
    log "ERROR: claude --print failed. Is Claude Code CLI installed and authenticated?"
    exit 1
fi

sleep 2

# Step 2: Read fresh token from Keychain and sync to credentials file
log "Syncing token from Keychain..."
python3 -c "
import json, time, subprocess, sys, os

result = subprocess.run(
    ['security', 'find-generic-password', '-s', '$KEYCHAIN_SERVICE', '-w'],
    capture_output=True, text=True
)
if result.returncode != 0:
    print('ERROR: Cannot read Keychain entry \"$KEYCHAIN_SERVICE\"', file=sys.stderr)
    sys.exit(1)

parsed = json.loads(result.stdout.strip())
oauth = parsed.get('claudeAiOauth', {})
exp = oauth.get('expiresAt', 0)
now = int(time.time() * 1000)
remaining_h = (exp - now) / 3600000

if remaining_h <= 0:
    print(f'ERROR: Token still expired after refresh ({remaining_h:.1f}h)', file=sys.stderr)
    sys.exit(1)

creds_path = os.path.expanduser('$CREDS_FILE')
os.makedirs(os.path.dirname(creds_path), exist_ok=True)
with open(creds_path, 'w') as f:
    json.dump(parsed, f, indent=2)

print(f'OK: Token synced ({remaining_h:.1f}h remaining)')
"
if [ $? -ne 0 ]; then
    log "ERROR: Token sync failed"
    exit 1
fi

# Step 3: Restart the proxy
log "Restarting proxy..."
if launchctl list "$LAUNCHD_LABEL" >/dev/null 2>&1; then
    launchctl kickstart -k "gui/$(id -u)/$LAUNCHD_LABEL" 2>/dev/null
    sleep 2

    # Verify proxy is listening
    if lsof -i ":$PROXY_PORT" >/dev/null 2>&1; then
        log "OK: Proxy restarted and listening on port $PROXY_PORT"
    else
        log "WARN: Proxy restarted but not yet listening on port $PROXY_PORT"
    fi
else
    log "WARN: launchd service $LAUNCHD_LABEL not found — proxy not restarted"
    log "Start the proxy manually: node proxy.js"
fi

log "Done."
