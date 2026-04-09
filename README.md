# Claude Proxy

> A standalone fork of [openclaw-billing-proxy](https://github.com/zacdcook/openclaw-billing-proxy) — original work credited under the MIT License. See [LICENSE](LICENSE).

Route your OpenClaw API requests through your Claude Max/Pro subscription instead of Extra Usage billing.

## What This Does

After Anthropic revoked subscription billing for third-party tools (April 4, 2026), OpenClaw requests are billed to Extra Usage. This proxy sits between OpenClaw and the Anthropic API, making requests indistinguishable from native Claude Code sessions so they use your existing subscription.

Anthropic's detection evolved beyond simple string matching into tool-name fingerprinting, schema-property fingerprinting, system-prompt template detection, and SDK-header validation. v2.1.0 addresses all of these across 8 coordinated layers.

**Zero cost increase. Full OpenClaw functionality. No code changes to OpenClaw. Real-time usage dashboard.**

## Features

### Detection Layers

| Layer | Name | What it does |
|-------|------|--------------|
| 1 | **Dynamic billing fingerprint** | SHA256-derived hash of first user message + CC version, injected as `x-anthropic-billing-header` in the system prompt. Varies per request like real Claude Code — not a static 84-char blob. |
| 2 | **String trigger sanitization** | 30 find/replace patterns wipe OpenClaw-specific trigger phrases (`OpenClaw`, `openclaw`, `sessions_*`, `HEARTBEAT_OK`, `running inside`, `clawhub`, `billing proxy`, etc.) from the outbound body. |
| 3 | **Tool name fingerprint bypass** | 29 tool renames (`exec`→`Bash`, `sessions_spawn`→`TaskCreate`, `lcm_grep`→`ContextGrep`, …) using `"name":"X"` prefix matching to avoid colliding with the same word appearing in content blocks. |
| 4 | **System prompt template stripping** | Detects OpenClaw's ~35K-char system config section and replaces it with a neutral paraphrase. Template-based detection cannot match what isn't there. |
| 5 | **Tool description stripping** | Empties verbose OpenClaw tool descriptions in the schema — these carry heavy fingerprint signal. Injects 5 Claude Code tool stubs (`Glob`, `Grep`, `Agent`, `NotebookEdit`, `TodoRead`) to further blend the toolset. |
| 6 | **Property name renaming** | 8 schema property renames (`session_id`→`thread_id`, `agent_id`→`worker_id`, `wake_at`→`trigger_at`, etc.) to neutralize per-property fingerprinting. |
| 7 | **Bidirectional reverse mapping** | Every rename and replacement has a matching reverse rule applied to responses. Handles SSE chunk boundary splits, escaped JSON inside `input_json_delta` deltas, and both plain and `\"escaped\"` quote styles so tool-use arguments land back in OpenClaw's original vocabulary intact. |
| 8 | **Full Claude Code signature emulation** | Stainless SDK headers (`x-stainless-lang`, `x-stainless-os`, `x-stainless-arch`, `x-stainless-package-version`, `x-stainless-runtime`, `x-stainless-runtime-version`, `x-stainless-retry-count`, `x-stainless-timeout`), `claude-cli/<ver>` user-agent, `x-app: cli`, session ID header, request metadata (`user_id` with device/account/session UUIDs), temperature normalization, `context_management` injection for thinking requests, stale `betas` body field stripping, `anthropic-beta` header merging, and URL normalization (`?beta=true` append). |

### Additional Features

| Feature | Description |
|---------|-------------|
| **Prompt caching** | `cache_control: { type: 'ephemeral', ttl: '1h' }` injected on system blocks. Slashes repeat-context cost. Disable with `--no-cache`. |
| **Assistant prefill stripping** | Removes trailing assistant prefill messages that Opus 4.6 rejects with 400. |
| **Escaped JSON reverse mapping** | SSE `input_json_delta` chunks are unescaped, reverse-mapped, and re-escaped correctly across streaming chunk boundaries. |
| **Stream-safe reverse mapping** | Stateful reverser holds back up to `maxPatternLen - 1` bytes between SSE chunks so keywords split across boundaries are still caught. |
| **Real-time terminal dashboard** | Live 5h/7d rate limit bars, daily token usage table (7 days), recent request log with model tag (S/H/O), uptime, CC emulation info. Falls back to plain text when stdout is not a TTY. |
| **Usage persistence** | Token counts saved to `./data/usage.json` (2s debounce, flushed on shutdown). Survives restarts. |
| **Keychain auto-sync** | On macOS, proactively syncs tokens from Keychain → credentials file every 5 minutes. |

## Requirements

- **Node.js** 18+
- **Claude Max or Pro subscription**
- **Claude Code CLI** installed and authenticated (`npm install -g @anthropic-ai/claude-code && claude auth login`)
- **OpenClaw** installed and running

## Quick Start

### Native

```bash
git clone https://github.com/sioakim/claude-proxy
cd claude-proxy

node setup.js     # auto-detect OpenClaw config, write config.json
node proxy.js     # start on 127.0.0.1:18801
```

Then point OpenClaw at the proxy — in `~/.openclaw/openclaw.json`:

```json
{ "baseUrl": "http://127.0.0.1:18801" }
```

Restart the OpenClaw gateway.

### Docker

```bash
cp .env.example .env    # edit: set OAUTH_TOKEN (or rely on ~/.claude mount)
docker compose up -d
```

## Docker Deployment

The `docker-compose.yml` builds from the local `Dockerfile` (Node 18 Alpine), exposes the proxy on `127.0.0.1:18801`, mounts `~/.claude` read-only for credentials, and includes a built-in health check.

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `OAUTH_TOKEN` | *(unset)* | OAuth token string. Overrides all file-based credential lookup. Skip the `~/.claude` mount if set. |
| `PROXY_PORT` | `18801` | Listen port (container + host mapping). |
| `PROXY_HOST` | `127.0.0.1` | Bind address. Compose overrides to `0.0.0.0` inside the container; the host-side port mapping is still `127.0.0.1`. |

### Health Check

Compose probes `/health` every 30 s. You can also call it directly:

```bash
curl http://127.0.0.1:18801/health
```

Returns JSON with token status, version, request count, uptime, subscription type, CC emulation details, and per-layer configuration.

### Volumes

| Mount | Purpose |
|-------|---------|
| `~/.claude:/root/.claude:ro` | Credentials (drop if `OAUTH_TOKEN` is set) |
| `./config.json:/app/config.json:ro` | Custom rules (uncomment in `docker-compose.yml`) |

## Configuration

`config.json` (generated by `node setup.js` or created manually):

```json
{
  "port": 18801,
  "credentialsPath": "~/.claude/.credentials.json",
  "stripSystemConfig": true,
  "stripToolDescriptions": true,
  "injectCCStubs": true,
  "stripTrailingAssistantPrefill": true,
  "replacements": [
    ["OpenClaw", "OCPlatform"],
    ["openclaw", "ocplatform"],
    ...
  ],
  "reverseMap": [
    ["OCPlatform", "OpenClaw"],
    ["ocplatform", "openclaw"],
    ...
  ],
  "toolRenames": [
    ["exec", "Bash"],
    ["sessions_spawn", "TaskCreate"],
    ...
  ],
  "propRenames": [
    ["session_id", "thread_id"],
    ["agent_id", "worker_id"],
    ...
  ]
}
```

### Options

| Option | Default | Description |
|--------|---------|-------------|
| `port` | `18801` | Listen port. CLI `--port` and `PROXY_PORT` env override. |
| `credentialsPath` | `~/.claude/.credentials.json` | OAuth credential file. `OAUTH_TOKEN` env takes precedence. |
| `stripSystemConfig` | `true` | Layer 4 — strip ~35K-char OpenClaw system template. |
| `stripToolDescriptions` | `true` | Layer 5 — empty OC tool descriptions. |
| `injectCCStubs` | `true` | Inject 5 Claude Code tool stubs into the tools array. |
| `stripTrailingAssistantPrefill` | `true` | Drop trailing assistant messages (Opus 4.6 compatibility). |
| `replacements` | built-in (11 pairs) | Layer 2 string trigger sanitization rules. |
| `reverseMap` | built-in (10 pairs) | Inverse of `replacements`, applied to responses. |
| `toolRenames` | built-in (29 pairs) | Layer 3 tool name renames. |
| `propRenames` | built-in (8 pairs) | Layer 6 schema property renames. |

**Important:** Every entry in `replacements`, `toolRenames`, or `propRenames` **must** have a corresponding `reverseMap` entry, or OpenClaw will see sanitized names in responses and tool calls will fail.

**Path safety:** Use space-free replacements for lowercase `openclaw` (e.g., `ocplatform`, not `assistant platform`) to avoid breaking filesystem paths like `.openclaw/`.

### CLI Flags

```bash
node proxy.js --port 9000 --config custom.json --no-cache
```

| Flag | Description |
|------|-------------|
| `--port N` | Override listen port |
| `--config path` | Use custom config file |
| `--no-cache` | Disable prompt caching |

## Running as a Service

### macOS (launchd)

```xml
<!-- ~/Library/LaunchAgents/com.openclaw.billing-proxy.plist -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.openclaw.billing-proxy</string>
    <key>ProgramArguments</key>
    <array>
        <string>/opt/homebrew/bin/node</string>
        <string>/path/to/proxy.js</string>
    </array>
    <key>WorkingDirectory</key>
    <string>/path/to/claude-proxy</string>
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
launchctl load ~/Library/LaunchAgents/com.openclaw.billing-proxy.plist
launchctl kickstart -k gui/$(id -u)/com.openclaw.billing-proxy   # restart
```

### Linux (systemd)

```ini
[Unit]
Description=Claude Proxy
After=network.target

[Service]
ExecStart=/usr/bin/node /path/to/proxy.js
Restart=always
User=YOUR_USER

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable --now claude-proxy
```

### PM2

```bash
pm2 start proxy.js --name claude-proxy
pm2 save
```

## Dashboard

When stdout is a TTY, the proxy draws a live dashboard:

```
  Claude Proxy v2.1.0               Port: 18801   Uptime: 2h 14m
  Sub: max            Token: 7.7h remaining
  CC Emulation: v2.1.97  Device: a3f8c1d2...  Session: 9b7e4f01...
  5h [██████░░░░░░░░░] 40% 1h30m    7d [███░░░░░░░░░░░░] 20% 4d12h
  ──────────────────────────────────────────────────────────────────
                                       Input        Output
  Today (2026-04-09)                     100         8,220   (46)
  Yesterday                          283,094       211,779   (880)
  ──────────────────────────────────────────────────────────────────
  Total (2d)                         283,194       219,999   (926)

  RECENT ACTIVITY
  S [14:32:07] #37 POST /v1/messages 200   ↑1,204    ↓389
  O [14:31:55] #36 POST /v1/messages 200     ↑980    ↓201

  [i] info  [q] quit
```

### Keyboard Shortcuts

| Key | Action |
|-----|--------|
| `i` | Toggle info overlay (explains every element) |
| `q` / `Ctrl-C` | Quit |

When stdout is not a TTY (piped, service, Docker), falls back to plain text logging.

### Usage Data

Persisted to `./data/usage.json` with 2-second debounce and shutdown flush.

## Token Refresh

Claude Code's OAuth token expires every 8–24 hours. The proxy reads `~/.claude/.credentials.json` on each request.

### macOS Keychain Quirk

Claude Code stores refreshed tokens in the macOS Keychain (`Claude Code-credentials`) but doesn't always write them back to the JSON file. The proxy handles this with:

1. **Startup sync** — checks Keychain vs file, writes newer token to file
2. **Periodic sync** — every 5 minutes, compares Keychain expiry to file; updates if Keychain is newer
3. **On-demand refresh** — when the file token has < 5 minutes left, probes Keychain before returning a stale token

### Manual Refresh

```bash
claude --print "."                                                    # trigger CLI refresh
security find-generic-password -s "Claude Code-credentials" -w > ~/.claude/.credentials.json  # sync
```

### Automated Refresh

The included `refresh-token.sh` handles the full cycle (trigger refresh → read Keychain → write file → restart proxy):

```bash
./refresh-token.sh

# Schedule with cron (every 6 hours)
0 */6 * * * /path/to/claude-proxy/refresh-token.sh >> /tmp/refresh-token.log 2>&1
```

**Environment overrides:** `CLAUDE_CREDENTIALS_PATH`, `PROXY_PORT`.

### Non-macOS

On Linux/Windows, Claude Code writes tokens directly to the JSON file. A cron running `claude -p "ping" --max-turns 1 --no-session-persistence` is sufficient.

## How Detection Works

Anthropic checks multiple signals in combination:

1. **Billing header** — `x-anthropic-billing-header` must be present in the system prompt with a valid, per-request-varying fingerprint.
2. **String classifier** — scans the body for trigger phrases (`OpenClaw`, `sessions_*`, `HEARTBEAT_OK`, `running inside`, etc.).
3. **Tool-name fingerprint** — the *set* of tool names in the `tools` array is matched against known OpenClaw tool inventories.
4. **Schema property fingerprint** — specific property names (`session_id`, `agent_id`, `wake_at`, etc.) leak OpenClaw origin.
5. **System-prompt template** — the structure, length, and phrasing of OpenClaw's ~35K system config is itself a fingerprint.
6. **SDK/UA fingerprint** — headers and user-agent must match `claude-cli` + Stainless SDK, not a generic HTTP client.

Each layer (1–8) targets one or more of these. No single layer is sufficient — they're checked in combination.

## Troubleshooting

```bash
node troubleshoot.js
```

Tests 8 independent checks: credentials, token validity, API connectivity, billing header, trigger detection, proxy health, reverse mapping, and end-to-end flow.

### Common Issues

| Symptom | Cause | Fix |
|---------|-------|-----|
| `Could not find credentials file` | Not logged in | `claude auth login`; on macOS check both `~/.claude/.credentials.json` and `~/.claude/credentials.json` |
| Proxy returns 400 | Unsanitized trigger term | Run `node setup.js` to auto-detect tools; add missing `sessions_*` entries |
| "Third-party apps draw from extra usage" | Detection tripped | Restart OpenClaw gateway (clear session); verify `stripSystemConfig: true` |
| 429 Rate Limit | Shared bucket with active Claude Code | Wait; not a proxy issue |
| 401 Token Expired | OAuth expired | Run `./refresh-token.sh` or `claude --print "."` |
| Model uses `.ocplatform/` paths | Missing `reverseMap` entries | Ensure every `replacements` entry has a matching inverse |
| "Model does not support assistant message prefill" | Opus 4.6 rejecting prefill | Enable `stripTrailingAssistantPrefill: true` (default) |
| Empty credentials file (macOS) | Keychain not synced to file | Run `./refresh-token.sh` or set up the cron |

## Security

- **File permissions** — credentials written with `0o600` (owner-only read/write).
- **Localhost-only binding** — defaults to `127.0.0.1`. Docker binds `0.0.0.0` inside the container but maps only to `127.0.0.1` on the host.
- **Sanitized errors** — upstream error bodies are reverse-mapped before being returned so trigger phrases can't leak into OpenClaw logs.
- **`MAX_BODY_SIZE`** — 10 MB hard cap on request bodies; oversized requests rejected with 413.
- **`OAUTH_TOKEN` env var** — Docker deployments can skip mounting `~/.claude` entirely.
- **No dependencies** — single-file `proxy.js`, zero npm packages, reduced supply-chain risk.

## Rollback

```bash
# In openclaw.json, change baseUrl back:
"baseUrl": "https://api.anthropic.com"
# Restart the gateway. Enable Extra Usage in Claude settings if needed.
```

## Disclaimer

This is an unofficial workaround. Anthropic may change their detection at any time. Use at your own risk. This proxy does not modify OpenClaw or Claude Code — it's a transparent HTTP middleman.

## License

MIT
