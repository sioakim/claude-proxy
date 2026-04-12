# Claude Proxy v2.2.6

> A standalone fork of [openclaw-billing-proxy](https://github.com/zacdcook/openclaw-billing-proxy) — original work credited under the MIT License. See [LICENSE](LICENSE).

Route your OpenClaw API requests through your Claude Max/Pro subscription instead of Extra Usage billing.

## What This Does

After Anthropic revoked subscription billing for third-party tools (April 4, 2026), OpenClaw requests are billed to Extra Usage. This proxy sits between OpenClaw and the Anthropic API, making requests indistinguishable from native Claude Code sessions so they use your existing subscription.

Anthropic's detection evolved beyond simple string matching into tool-name fingerprinting, schema-property fingerprinting, system-prompt template detection, and SDK-header validation. v2.x addresses all of these across 8 coordinated layers.

**Zero cost increase. Full OpenClaw functionality. No code changes to OpenClaw. Real-time usage dashboard.**

## Features

### Detection Layers

| Layer | Name | What it does |
|-------|------|--------------|
| 1 | **Dynamic billing fingerprint** | SHA256-derived hash of first user message + CC version, injected as `x-anthropic-billing-header` in the system prompt. Varies per request like real Claude Code — not a static blob. |
| 2 | **String trigger sanitization** | Find/replace patterns wipe OpenClaw-specific trigger phrases (`OpenClaw`, `openclaw`, `sessions_*`, `HEARTBEAT_OK`, `running inside`, etc.) from the outbound body. |
| 3 | **Tool name fingerprint bypass** | Tool renames (`exec`→`Bash`, `sessions_spawn`→`TaskCreate`, `lcm_grep`→`ContextGrep`, …) using `"name":"X"` prefix matching to avoid colliding with the same word in content blocks. |
| 4 | **System prompt template stripping** | Detects OpenClaw's ~35K-char system config section and replaces it with a neutral paraphrase. Template-based detection cannot match what isn't there. |
| 5 | **Tool description stripping** | Empties verbose OpenClaw tool descriptions in the schema — these carry heavy fingerprint signal. Injects 5 Claude Code tool stubs (`Glob`, `Grep`, `Agent`, `NotebookEdit`, `TodoRead`) to further blend the toolset. |
| 6 | **Property name renaming** | Schema property renames (`session_id`→`thread_id`, `agent_id`→`worker_id`, `wake_at`→`trigger_at`, etc.) to neutralize per-property fingerprinting. |
| 7 | **Bidirectional reverse mapping** | Every rename and replacement has a matching reverse rule applied to responses. Handles SSE chunk boundary splits with newline-aligned slicing, escaped JSON inside `input_json_delta` deltas, and both plain and `\"escaped\"` quote styles so tool-use arguments land back in OpenClaw's original vocabulary intact. |
| 8 | **Full Claude Code signature emulation** | Stainless SDK headers (`x-stainless-lang`, `x-stainless-os`, `x-stainless-arch`, etc.), `claude-cli/<ver>` user-agent, `x-app: cli`, session ID header, request metadata (`user_id` with device/session UUIDs), temperature normalization, `context_management` injection for thinking requests, stale `betas` body field stripping, `anthropic-beta` header merging, and URL normalization (`?beta=true` append). |

### Additional Features

| Feature | Description |
|---------|-------------|
| **Prompt caching** | `cache_control: { type: 'ephemeral', ttl: '1h' }` injected on system blocks. Slashes repeat-context cost. Disable with `--no-cache`. |
| **Thinking block preservation** | Masks `thinking` and `redacted_thinking` content blocks before transforms, restores them after — Anthropic enforces byte-equality on these. Works in both SSE streaming and JSON response paths. |
| **Assistant prefill stripping** | Removes trailing assistant prefill messages that Opus 4.6 rejects with 400. |
| **Non-SSE keep-alive forwarding** | When upstream proxies inject blank-line heartbeat bytes during long inference, forwards leading whitespace immediately so clients don't time out. |
| **Automatic token refresh** | Monitors token expiry and triggers `claude -p "ping"` + Keychain re-extraction before it expires. Configurable threshold and retry. |
| **Stream-safe reverse mapping** | Stateful reverser holds back up to `maxPatternLen - 1` bytes between SSE chunks with newline-aligned slicing, so keywords split across chunk boundaries are still caught. |
| **Real-time terminal dashboard** | Live 5h/7d rate limit bars, daily token usage table (7 days), recent request log with model tag (S/H/O), uptime, CC emulation info. Falls back to plain text when stdout is not a TTY. |
| **Usage persistence** | Token counts saved to `./data/usage.json` (2s debounce, flushed on shutdown). Survives restarts. |
| **Keychain auto-sync** | On macOS, proactively syncs tokens from Keychain → credentials file every 5 minutes (separate from the CLI-based token refresh). |
| **UTF-8 safe streaming** | Uses `StringDecoder` to handle multi-byte UTF-8 characters split across TCP chunks in SSE streams. |

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

The `docker-compose.yml` builds from the local `Dockerfile` (Node 18 Alpine), exposes the proxy on `127.0.0.1:18801`, mounts `~/.claude` read-only for credentials, and includes a built-in health check.

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `OAUTH_TOKEN` | *(unset)* | OAuth token string. Overrides all file-based credential lookup. Skip the `~/.claude` mount if set. Disables auto token refresh. |
| `PROXY_PORT` | `18801` | Listen port. |
| `PROXY_HOST` | `127.0.0.1` | Bind address. Compose overrides to `0.0.0.0` inside the container; the host-side port mapping is still `127.0.0.1`. |

### Health Check

```bash
curl http://127.0.0.1:18801/health
```

Returns JSON with token status, version, request count, uptime, subscription type, CC emulation details, and per-layer configuration.

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
  "mergeDefaults": true,
  "refreshEnabled": true,
  "refreshThresholdMinutes": 2,
  "refreshRetrySeconds": 15,
  "replacements": [],
  "reverseMap": [],
  "toolRenames": [],
  "propRenames": []
}
```

### Config Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `port` | number | `18801` | Listen port. CLI `--port` and `PROXY_PORT` env override (in that order). |
| `credentialsPath` | string | auto-detect | Path to OAuth credential file. Searched in order: this value, `~/.claude/.credentials.json`, `~/.claude/credentials.json`. `OAUTH_TOKEN` env takes precedence over all files. |
| `stripSystemConfig` | bool | `true` | Layer 4 — strip ~35K-char OpenClaw system template and replace with neutral paraphrase. |
| `stripToolDescriptions` | bool | `true` | Layer 5 — empty OC tool descriptions from schemas. |
| `injectCCStubs` | bool | `true` | Inject 5 Claude Code tool stubs (`Glob`, `Grep`, `Agent`, `NotebookEdit`, `TodoRead`) into the tools array. |
| `stripTrailingAssistantPrefill` | bool | `true` | Drop trailing assistant messages that Opus 4.6 rejects with "does not support assistant message prefill". |
| `mergeDefaults` | bool | `true` | When `true`, config arrays (replacements, toolRenames, etc.) are **merged** with built-in defaults — your entries override by first-element match, extras are appended. When `false`, config arrays replace defaults entirely. |
| `refreshEnabled` | bool | `true` | Enable automatic token refresh. When the token is within `refreshThresholdMinutes` of expiry, runs `claude -p "ping" --max-turns 1 --no-session-persistence` to trigger a CLI refresh, then re-extracts from macOS Keychain into the credentials file. Disabled automatically when using `OAUTH_TOKEN` env var. |
| `refreshThresholdMinutes` | number | `2` | How close to expiry (in minutes) before triggering a refresh. Claude CLI only rotates tokens when < ~2 minutes remain, so lower values work better than high ones. |
| `refreshRetrySeconds` | number | `15` | How quickly to retry if a refresh attempt was a no-op (Claude CLI declined to rotate the token). The proxy doesn't poll on a fixed cadence — it schedules the next check based on the actual token expiry time, and only switches to this fast-retry interval when a refresh didn't advance the expiry. |
| `replacements` | array | 11 built-in pairs | Layer 2 string trigger sanitization rules. Each entry is `[find, replace]`. |
| `reverseMap` | array | 10 built-in pairs | Inverse of `replacements`, applied to responses. Each entry is `[sanitized, original]`. |
| `toolRenames` | array | 32 built-in pairs | Layer 3 tool name renames. Each entry is `[ocName, ccName]`. |
| `propRenames` | array | 8 built-in pairs | Layer 6 schema property renames. Each entry is `[ocName, ccName]`. |

**Important:** Every entry in `replacements`, `toolRenames`, or `propRenames` **must** have a corresponding `reverseMap` entry (for replacements) or be listed in the same array (tool/prop renames are reversed automatically). Otherwise OpenClaw will see sanitized names in responses and tool calls will fail.

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

## Token Management

Claude Code's OAuth token expires every 8–24 hours. The proxy has multiple layers of token management:

### Automatic Token Refresh (new in v2.2.6)

The proxy monitors the token's actual expiry time and schedules a refresh to fire when it drops below the threshold (default: 2 minutes remaining). The refresh process:

1. Runs `claude -p "ping" --max-turns 1 --no-session-persistence` (30s timeout) to trigger the Claude CLI's own token rotation
2. On macOS, re-extracts the refreshed token from Keychain into the credentials file
3. Verifies the new token has a later expiry than the old one
4. If the refresh was a no-op (CLI declined to rotate), retries every 15 seconds until it takes

This is **not** fixed-interval polling — the scheduler computes the exact delay until the threshold is reached, so it's quiet for hours and only activates when needed.

**Note:** Claude CLI only rotates tokens when they have less than ~2 minutes remaining. Setting `refreshThresholdMinutes` higher than 2 will cause repeated no-op retries until the token is actually close to expiry. The default of 2 minutes is optimal based on community testing.

Configure or disable in `config.json`:
```json
{
  "refreshEnabled": true,
  "refreshThresholdMinutes": 2,
  "refreshRetrySeconds": 15
}
```

### macOS Keychain Sync (proactive)

Separate from the CLI-based refresh above, the proxy also does a lighter-weight Keychain sync every 5 minutes:

1. **Startup sync** — compares Keychain vs file, writes the newer token to file
2. **Periodic sync** — every 5 minutes, checks if Keychain has a newer token than the file (skipped if file token has > 30 minutes remaining)
3. **On-demand refresh** — when the file token has < 5 minutes left, probes Keychain before returning a stale token to the caller

This catches tokens that were refreshed by Claude Code running in another terminal without needing to invoke the CLI.

### Manual Refresh

```bash
claude -p "ping" --max-turns 1 --no-session-persistence   # trigger CLI refresh
```

On macOS, the proxy will automatically pick up the new token from Keychain within 5 minutes (or immediately if the old token was nearly expired).

### Non-macOS

On Linux/Windows, Claude Code writes tokens directly to the JSON file. The automatic refresh (`refreshEnabled: true`) handles this — no Keychain involved.

## Non-SSE Keep-Alive Forwarding (v2.2.6)

When chained behind upstream proxies that inject blank-line heartbeat bytes during long non-streaming inference (e.g., CLIProxyAPI's `nonstream-keepalive-interval`), the proxy now forwards those bytes immediately instead of absorbing them into the response buffer.

**Before:** Client receives first byte only when the full response is ready — inference taking >15s causes timeout disconnects.

**After:** Leading whitespace bytes are forwarded as they arrive, keeping the client connection alive. Once non-whitespace (actual JSON) appears, the proxy switches to the normal buffer-and-transform path for `reverseMap` and thinking-block masking.

This is transparent — no configuration needed. Short responses (<15s) are unaffected.

## Reverse Mapping

The proxy transforms request bodies on the way out (sanitization) and response bodies on the way back (reverse mapping). The reverse mapping has several important design details:

### SSE Streaming

For streaming (SSE) responses, a stateful `StreamReverser` holds back up to `maxPatternLen - 1` bytes between chunks. This ensures that a renamed keyword split across two TCP chunks is still caught and reversed.

**Newline-aligned slicing** (v2.2.6): When computing where to slice the pending buffer, the reverser backs up to the last newline boundary if one exists. Since SSE data is line-oriented (`data: {...}\n\n`), this prevents splitting a keyword at an unlucky position relative to the holdback window. This is defense-in-depth on top of the existing dynamic holdback.

### Thinking Blocks

Thinking and redacted_thinking content blocks are masked with unique placeholders before any transforms run, then restored afterward. Anthropic enforces byte-equality on these blocks — mutating them causes API rejection on subsequent turns.

### Escaped JSON

SSE `input_json_delta` chunks contain nested JSON inside a string field with escaped quotes (`\"name\":\"Bash\"`). The reverse mapper handles both plain (`"name":"Bash"`) and escaped (`\"name\":\"Bash\"`) variants to ensure tool-use arguments are correctly reverted.

## Dashboard

When stdout is a TTY, the proxy draws a live dashboard:

```
  Claude Proxy v2.2.6               Port: 18801   Uptime: 2h 14m
  Sub: max            Token: 7.7h remaining
  CC Emulation: v2.1.97  Device: a3f8c1d2...  Session: 9b7e4f01...
  Token refresh:     when <2m remaining (retry 15s on no-op)
  5h [██████░░░░░░░░░] 40% 1h30m    7d [███░░░░░░░░░░░░] 20% 4d12h
  ──────────────────────────────────────────────────────────────────
                                       Input        Output
  Today (2026-04-12)                     100         8,220   (46)
  Yesterday                          283,094       211,779   (880)
  ──────────────────────────────────────────────────────────────────
  Total (2d)                         283,194       219,999   (926)

  RECENT ACTIVITY
  S [14:32:07] #37 POST /v1/messages 200   ↑1,204    ↓389
  O [14:31:55] #36 POST /v1/messages 200     ↑980    ↓201

  [i] info  [q] quit
```

| Key | Action |
|-----|--------|
| `i` | Toggle info overlay (explains every element) |
| `q` / `Ctrl-C` | Quit |

When stdout is not a TTY (piped, service, Docker), falls back to plain text logging. Usage data persisted to `./data/usage.json`.

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

## Troubleshooting

```bash
node troubleshoot.js
```

Tests 8 independent checks: credentials, token validity, API connectivity, billing header, trigger detection, proxy health, reverse mapping, and end-to-end flow.

### Common Issues

| Symptom | Cause | Fix |
|---------|-------|-----|
| `Could not find credentials file` | Not logged in | `claude auth login`; on macOS check both `~/.claude/.credentials.json` and `~/.claude/credentials.json` |
| Proxy returns 400 | Unsanitized trigger term | Run `node setup.js` to auto-detect tools; add missing entries to config |
| "Third-party apps draw from extra usage" | Detection tripped | Restart OpenClaw gateway (clear session); verify `stripSystemConfig: true` |
| 429 Rate Limit | Shared bucket with active Claude Code | Wait; not a proxy issue |
| 401 Token Expired | OAuth expired, auto-refresh didn't fire | Check `refreshEnabled: true` in config; verify `claude` CLI is on PATH; run `claude auth login` manually |
| Model uses `.ocplatform/` paths | Missing reverse map entries | Ensure every `replacements` entry has a matching `reverseMap` inverse |
| "Model does not support assistant message prefill" | Opus 4.6 rejecting prefill | Enable `stripTrailingAssistantPrefill: true` (default) |
| Client timeout on long non-streaming requests | Heartbeat bytes being absorbed | Update to v2.2.6+ (automatic — no config needed) |
| Token refresh logs "no-op" repeatedly | Token not close enough to expiry | Normal — Claude CLI only rotates at <2m remaining. The proxy retries every 15s until it takes. |
| `[PROXY] claude CLI refresh failed` | `claude` not on PATH or not installed | Install Claude Code CLI: `npm install -g @anthropic-ai/claude-code` |
| Empty credentials file (macOS) | Keychain not synced to file | Proxy auto-syncs; if stuck, run `claude -p "ping" --max-turns 1 --no-session-persistence` |
| `Token expired Xm ago` | Auto-refresh couldn't reach Claude CLI | Check network; run `claude auth login` manually |

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

## Changelog

### v2.2.6 (2026-04-12)
- **Automatic token refresh** — monitors expiry and triggers `claude -p "ping"` + Keychain re-extraction before token expires. Smart scheduling based on actual expiry time, not fixed polling. Configurable via `refreshEnabled`, `refreshThresholdMinutes`, `refreshRetrySeconds`. (Upstream PR #32, credit: mvrska)
- **Non-SSE keep-alive forwarding** — forwards upstream heartbeat whitespace bytes immediately during long non-streaming inference, preventing client idle timeouts. (Upstream PR #40, credit: kongkong7777)
- **Newline-aligned SSE slicing** — `createStreamReverser` now slices at newline boundaries when possible, preventing keyword splits at unlucky positions in SSE data. Defense-in-depth improvement. (Issue #35)

### v2.2.5
- UTF-8 safe streaming via `StringDecoder` for multi-byte character handling
- Transfer-encoding header fix for SSE responses

### v2.2.4
- Thinking block preservation (forward + reverse passes)
- Config strip boundary uses filesystem path patterns

### v2.2.3
- Dynamic `maxPatternLen` holdback for stream-safe reverse mapping
- Escaped JSON reverse mapping for SSE `input_json_delta`

## Disclaimer

This is an unofficial workaround. Anthropic may change their detection at any time. Use at your own risk. This proxy does not modify OpenClaw or Claude Code — it's a transparent HTTP middleman.

## License

MIT
