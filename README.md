# Claude Proxy

> A standalone fork of [openclaw-billing-proxy](https://github.com/zacdcook/openclaw-billing-proxy) — original work credited under the MIT License. See [LICENSE](LICENSE).

Route your OpenClaw API requests through your Claude Max/Pro subscription instead of Extra Usage billing.

## What This Does

After Anthropic revoked subscription billing for third-party tools (April 4, 2026), OpenClaw requests are billed to Extra Usage. This proxy sits between OpenClaw and the Anthropic API, transforming requests to be indistinguishable from real Claude Code at every level — billing, headers, body structure, and tool signatures.

**Zero cost increase. Full OpenClaw functionality. No code changes to OpenClaw.**

## Detection Bypass Layers

The proxy applies 8 layers of transformation plus additional hardening:

| Layer | Name | What It Does |
|-------|------|-------------|
| 1 | **Billing Fingerprint** | Dynamic SHA256-based 3-char hash from message content + salt + CC version. Injected as system prompt block. |
| 2 | **String Sanitization** | 30 pattern replacements: `OpenClaw` → `OCPlatform`, `sessions_spawn` → `create_task`, `HEARTBEAT` → `HB_SIGNAL`, etc. |
| 3 | **Tool Name Bypass** | 29 tool renames using `"name":"X"` prefix to avoid content type collision (e.g., `exec` → `Bash`, `message` → `SendMessage`). |
| 4 | **System Prompt Strip** | Removes ~35K chars of OpenClaw config template, replaces with brief paraphrase. |
| 5 | **Description Strip** | Empties verbose tool descriptions that fingerprint OpenClaw. |
| 6 | **Property Renames** | 8 OC-specific schema properties renamed (`session_id` → `thread_id`, etc.). |
| 7 | **Reverse Mapping** | Bidirectional SSE + JSON response processing with chunk-boundary-safe streaming. |
| 8 | **CC Signature Emulation** | Full Claude Code HTTP signature: Stainless SDK headers, user-agent, metadata, temperature normalization, context management, `?beta=true` URL transform. |

**Additional hardening:**
- **Prompt caching** — 1h ephemeral TTL on identity block
- **Assistant prefill stripping** — Removes trailing assistant messages for Opus 4.6 compatibility
- **Escaped JSON reverse mapping** — Handles `\"name\"` in SSE `input_json_delta` deltas
- **CC tool stubs** — 5 fake Claude Code tools injected (Glob, Grep, Agent, NotebookEdit, TodoRead)
- **CC identity string** — "You are Claude Code, Anthropic's official CLI for Claude."

## Requirements

- **Node.js** 18+
- **Claude Max or Pro subscription**
- **Claude Code CLI** installed and authenticated (`npm install -g @anthropic-ai/claude-code && claude auth login`)

## Quick Start

### Native (macOS / Linux)

```bash
git clone https://github.com/sioakim/claude-proxy.git
cd claude-proxy
node setup.js    # finds credentials, creates config.json
node proxy.js    # starts on port 18801
```

### Docker

```bash
git clone https://github.com/sioakim/claude-proxy.git
cd claude-proxy
cp .env.example .env
# Edit .env: set OAUTH_TOKEN=sk-ant-... (from `claude auth status`)
docker compose up -d
```

### OpenClaw Configuration

Point OpenClaw at the proxy in `openclaw.json`:

```json
{
  "models": {
    "providers": {
      "anthropic": {
        "baseUrl": "http://127.0.0.1:18801"
      }
    }
  }
}
```

## Docker Deployment

The included `docker-compose.yml` provides:

- **Localhost-only binding** (`127.0.0.1`) — proxy never exposed externally
- **Built-in health check** (30s interval, 3 retries)
- **Log rotation** (10MB max, 3 files)
- **Credential volume mount** (`~/.claude:/root/.claude:ro`)

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `OAUTH_TOKEN` | *(none)* | OAuth token — overrides file-based credentials |
| `PROXY_PORT` | `18801` | Proxy listen port |
| `PROXY_HOST` | `127.0.0.1` | Bind address (Docker sets `0.0.0.0` automatically) |
| `CLAUDE_CODE_ACCOUNT_UUID` | *(none)* | Account UUID for request metadata |

Two auth modes:
1. **Environment variable** — Set `OAUTH_TOKEN` in `.env` (no volume mount needed)
2. **Credential file** — Mount `~/.claude` as read-only volume (default in docker-compose.yml)

## Configuration

Optional `config.json` for custom rules:

```json
{
  "port": 18801,
  "credentialsPath": "~/.claude/.credentials.json",
  "stripSystemConfig": true,
  "stripToolDescriptions": true,
  "injectCCStubs": true,
  "stripTrailingAssistantPrefill": true,
  "replacements": [],
  "reverseMap": [],
  "toolRenames": [],
  "propRenames": []
}
```

| Option | Default | Description |
|--------|---------|-------------|
| `stripSystemConfig` | `true` | Remove ~35K OpenClaw config from system prompt |
| `stripToolDescriptions` | `true` | Empty verbose tool descriptions |
| `injectCCStubs` | `true` | Add 5 fake Claude Code tools |
| `stripTrailingAssistantPrefill` | `true` | Strip trailing assistant messages (Opus 4.6 fix) |
| `replacements` | 30 patterns | Custom string sanitization rules `[["find", "replace"], ...]` |
| `toolRenames` | 29 renames | Custom tool name mappings |
| `propRenames` | 8 renames | Custom property name mappings |

## Running as a Service

### macOS (launchd)

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>com.openclaw.billing-proxy</string>
  <key>ProgramArguments</key>
  <array>
    <string>/usr/local/bin/node</string>
    <string>/path/to/claude-proxy/proxy.js</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>StandardOutPath</key>
  <string>/tmp/openclaw-billing-proxy.log</string>
  <key>StandardErrorPath</key>
  <string>/tmp/openclaw-billing-proxy.log</string>
</dict>
</plist>
```

```bash
cp com.openclaw.billing-proxy.plist ~/Library/LaunchAgents/
launchctl load ~/Library/LaunchAgents/com.openclaw.billing-proxy.plist
```

### Linux (systemd)

```ini
[Unit]
Description=Claude Billing Proxy
After=network.target

[Service]
ExecStart=/usr/bin/node /path/to/claude-proxy/proxy.js
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

### PM2

```bash
pm2 start proxy.js --name claude-proxy
pm2 save
pm2 startup
```

## Dashboard

The proxy includes a real-time terminal dashboard (when running in a TTY):

- Request log with model tags (O=Opus, S=Sonnet, H=Haiku)
- Token usage per request (input ↑ / output ↓)
- Rate limit status bar
- Daily/monthly usage tracking

**Keyboard shortcuts:** `q` quit, `c` clear log, `r` refresh display

Usage data persists to `~/.claude-proxy-usage.json`.

## Token Refresh

Claude Code OAuth tokens expire every ~8 hours.

### Manual

```bash
claude --print "." && launchctl kickstart -k gui/$(id -u)/com.openclaw.billing-proxy
```

### Automated (cron)

```bash
# Every 6 hours
0 */6 * * * /path/to/claude-proxy/refresh-token.sh >> /tmp/claude-proxy-refresh.log 2>&1
```

The included `refresh-token.sh` script:
1. Runs `claude --print "."` to trigger token refresh
2. Syncs Keychain → credentials file
3. Restarts the proxy via launchctl

## Health Check

```bash
curl http://127.0.0.1:18801/health
```

Returns:
```json
{
  "status": "ok",
  "proxy": "claude-proxy",
  "version": "2.1.0",
  "requestsServed": 42,
  "tokenExpiresInHours": "5.2",
  "subscriptionType": "max",
  "ccEmulation": {
    "ccVersion": "2.1.97",
    "deviceId": "f4da7011...",
    "sessionId": "56a49b90..."
  },
  "layers": {
    "stringReplacements": 30,
    "toolNameRenames": 29,
    "propertyRenames": 8,
    "ccToolStubs": 5,
    "systemStripEnabled": true,
    "descriptionStripEnabled": true
  }
}
```

## Security

- **File permissions** — Credentials written with `0o600` (owner-only read/write)
- **Localhost binding** — Default `127.0.0.1`, never exposed externally
- **Sanitized errors** — No credential data in error responses
- **Body size limit** — `MAX_BODY_SIZE` prevents memory exhaustion
- **Keychain integration** — macOS Keychain for credential storage with proactive sync

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| `400 "out of extra usage"` | Detection triggered | Check proxy logs for `[STRIP]` messages — config template may have changed |
| `400 "assistant message prefill"` | Opus 4.6 prefill rejection | Ensure `stripTrailingAssistantPrefill` is enabled (default) |
| `400 "Input tag ImageGen"` | Content type collision | Already fixed in v2.1 — tool renames use `"name":"X"` prefix |
| `400 "Extra inputs are not permitted"` | Metadata field rejected | Only `metadata.user_id` is allowed by the API |
| `400 "maximum of 4 blocks with cache_control"` | Too many cache breakpoints | Reduce to identity block only |
| Token expired | 8h OAuth expiry | Run `refresh-token.sh` or set up cron |
| Empty responses | SSE reverse-map leak | Stream reverser with holdback handles chunk boundaries |

Run diagnostics:
```bash
node troubleshoot.js
```

## Disclaimer

This proxy is provided as-is for personal use. It modifies API requests to use your existing Claude subscription for billing. Use at your own risk. The authors are not responsible for any account actions taken by Anthropic.

## License

MIT — see [LICENSE](LICENSE).

Based on [openclaw-billing-proxy](https://github.com/zacdcook/openclaw-billing-proxy) by [@zacdcook](https://github.com/zacdcook).
