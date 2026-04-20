#!/usr/bin/env node
/**
 * Claude Proxy v2.0
 *
 * Routes OpenClaw API requests through Claude Code's subscription billing
 * instead of Extra Usage. Defeats Anthropic's multi-layer detection:
 *
 *   Layer 1: Billing header injection (84-char Claude Code identifier)
 *   Layer 2: String trigger sanitization (OCPlatform, sessions_*, running on, etc.)
 *   Layer 3: Tool name fingerprint bypass (rename OC tools to CC PascalCase convention)
 *   Layer 4: System prompt template bypass (strip config section, replace with paraphrase)
 *   Layer 5: Tool description stripping (reduce fingerprint signal in tool schemas)
 *   Layer 6: Property name renaming (eliminate OC-specific schema property names)
 *   Layer 7: Full bidirectional reverse mapping (SSE + JSON responses)
 *
 * v1.x string-only sanitization stopped working April 8, 2026 when Anthropic
 * upgraded from string matching to tool-name fingerprinting and template detection.
 * v2.0 defeats the new detection by transforming the entire request body.
 *
 * Fork enhancements: Dashboard, prompt caching (1h TTL), security hardening,
 * Keychain auto-sync, usage tracking.
 *
 * Zero dependencies. Works on Windows, Linux, Mac.
 *
 * Usage:
 *   node proxy.js [--port 18801] [--config config.json]
 *
 * Quick start:
 *   1. Authenticate Claude Code: claude auth login
 *   2. Run: node proxy.js
 *   3. Set openclaw.json baseUrl to http://127.0.0.1:18801
 *   4. Restart OpenClaw gateway
 */

const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');
const { StringDecoder } = require('string_decoder');

// ─── Defaults ───────────────────────────────────────────────────────────────
const DEFAULT_PORT = 18801;
const UPSTREAM_HOST = 'api.anthropic.com';
const VERSION = '2.4.1';
const USAGE_FILE = path.join(__dirname, 'data', 'usage.json');

// ─── Layer 8: Claude Code Identity & Billing ───────────────────────
// [dario] CC version updated to match dario v3.30 live fingerprint capture
const CC_VERSION = '2.1.114';
const BILLING_HASH_SALT = '59cf53e54c78';
const BILLING_HASH_INDICES = [4, 7, 20];
const DEVICE_ID = crypto.randomBytes(32).toString('hex');

// ─── Layer 9: Session ID Rotation (ported from dario/session-rotation.ts) ───
// Real CC rotates session ID after idle gaps (~15min), not per-request or never.
// A static session ID is a fingerprint; per-request rotation is also a fingerprint.
// This module rotates after idle gaps with optional jitter to match CC's behavior.
const SESSION_ROTATION_IDLE_MS = 15 * 60 * 1000; // 15 minutes idle threshold
const SESSION_ROTATION_JITTER_MS = 3 * 60 * 1000; // 0-3 minutes random jitter
let SESSION_ID = crypto.randomUUID();
let sessionCreatedAt = Date.now();
let sessionLastUsedAt = Date.now();
let sessionIdleJitterMs = Math.floor(Math.random() * SESSION_ROTATION_JITTER_MS);

function getOrRotateSessionId() {
  const now = Date.now();
  const idleThreshold = SESSION_ROTATION_IDLE_MS + sessionIdleJitterMs;
  if (now - sessionLastUsedAt > idleThreshold) {
    // Idle gap exceeded — rotate like a new CC conversation
    SESSION_ID = crypto.randomUUID();
    sessionCreatedAt = now;
    sessionIdleJitterMs = Math.floor(Math.random() * SESSION_ROTATION_JITTER_MS);
    console.log(`[SESSION] Rotated after ${((now - sessionLastUsedAt) / 60000).toFixed(1)}m idle`);
  }
  sessionLastUsedAt = now;
  return SESSION_ID;
}

// ─── Layer 10: Inter-Request Pacing (ported from dario/pacing.ts) ───────────
// Real CC has human-paced gaps between requests. Machine-speed firing is
// a trivial fingerprint. Add minimum gap + jitter between outbound requests.
const PACING_MIN_GAP_MS = 500;  // minimum ms between requests
const PACING_JITTER_MS = 200;   // additional random jitter ms
let lastRequestTime = 0;

function computePacingDelay() {
  if (lastRequestTime <= 0) return 0;
  const now = Date.now();
  const jitterAdd = PACING_JITTER_MS > 0 ? Math.floor(Math.random() * PACING_JITTER_MS) : 0;
  const effectiveGap = PACING_MIN_GAP_MS + jitterAdd;
  const elapsed = now - lastRequestTime;
  if (elapsed >= effectiveGap) return 0;
  return effectiveGap - elapsed;
}

function sleep(ms) { return new Promise(resolve => setTimeout(resolve, ms)); }

// Claude Code identity string — injected as system prompt block
const CLAUDE_CODE_IDENTITY_STRING = 'You are Claude Code, Anthropic\'s official CLI for Claude.';

// Dynamic billing fingerprint — replaces static BILLING_BLOCK
function computeBillingFingerprint(firstUserMessage, version) {
  const chars = BILLING_HASH_INDICES.map(i => (firstUserMessage || '')[i] || '0').join('');
  const input = `${BILLING_HASH_SALT}${chars}${version}`;
  return crypto.createHash('sha256').update(input).digest('hex').slice(0, 3);
}

function extractFirstUserMessageText(bodyStr) {
  const msgMatch = bodyStr.match(/"role"\s*:\s*"user"[\s\S]*?"text"\s*:\s*"([^"]*?)"/);;
  return msgMatch ? msgMatch[1] : '';
}

// [dario] CCH is random 5-char hex per request, NOT a hash of user message.
// Real CC uses randomBytes, not a deterministic hash. Previous SHA256-based
// computation was a fingerprint since it was deterministic for same input.
function computeCch() {
  return crypto.randomBytes(3).toString('hex').slice(0, 5);
}

function buildBillingBlock(firstUserMessage) {
  const fp = computeBillingFingerprint(firstUserMessage, CC_VERSION);
  const cch = computeCch();
  return {
    type: 'text',
    text: `x-anthropic-billing-header: cc_version=${CC_VERSION}.${fp}; cc_entrypoint=cli; cch=${cch};`
  };
}

// Stainless SDK helpers
function getStainlessOs() {
  const p = process.platform;
  if (p === 'darwin') return 'macOS';
  if (p === 'win32') return 'Windows';
  if (p === 'linux') return 'Linux';
  return p;
}

function getStainlessArch() {
  const a = process.arch;
  if (a === 'arm64') return 'arm64';
  if (a === 'x64') return 'x64';
  return a;
}

function buildUserAgent() {
  return `claude-cli/${CC_VERSION} (external, cli)`;
}

// ─── Layer 11: Orchestration Tag Stripping (ported from dario/proxy.ts) ─────
// Agent frameworks inject XML-style orchestration tags into messages that
// Claude Code would never send. Strip them before forwarding upstream.
const ORCHESTRATION_TAG_NAMES = [
  'system-reminder', 'env', 'system_information', 'current_working_directory',
  'operating_system', 'default_shell', 'home_directory', 'task_metadata',
  'directories', 'thinking',
  'agent_persona', 'agent_context', 'tool_context', 'persona', 'tool_call',
];
const ORCHESTRATION_PATTERNS = [];
for (const tag of ORCHESTRATION_TAG_NAMES) {
  ORCHESTRATION_PATTERNS.push(new RegExp(`<${tag}\\b[^>]*>[\\s\\S]*?<\\/${tag}>`, 'gi'));
  ORCHESTRATION_PATTERNS.push(new RegExp(`<${tag}\\b[^>]*\\/>`, 'gi'));
}

function stripOrchestrationTags(text) {
  let result = text;
  for (const pattern of ORCHESTRATION_PATTERNS) {
    pattern.lastIndex = 0;
    result = result.replace(pattern, '');
  }
  return result.replace(/\n{3,}/g, '\n\n').trim();
}

function sanitizeMessageOrchestration(bodyStr) {
  // Quick check — if no angle brackets, skip the expensive regex work
  if (!bodyStr.includes('<system-reminder') && !bodyStr.includes('<env') &&
      !bodyStr.includes('<current_working_directory') && !bodyStr.includes('<agent_')) {
    return bodyStr;
  }
  try {
    const parsed = JSON.parse(bodyStr);
    if (Array.isArray(parsed.messages)) {
      let changed = false;
      for (const msg of parsed.messages) {
        if (typeof msg.content === 'string') {
          const cleaned = stripOrchestrationTags(msg.content);
          if (cleaned !== msg.content) { msg.content = cleaned; changed = true; }
        } else if (Array.isArray(msg.content)) {
          for (const block of msg.content) {
            if (block && block.type === 'text' && typeof block.text === 'string') {
              const cleaned = stripOrchestrationTags(block.text);
              if (cleaned !== block.text) { block.text = cleaned; changed = true; }
            }
          }
          // Drop text blocks that became empty after orchestration-tag scrubbing.
          // CC v2.1.112 splits per-reminder system-reminders into separate content
          // blocks; scrubbing leaves each as {type:'text',text:''} which Anthropic
          // rejects with "text content blocks must be non-empty" (upstream #54).
          // Non-text blocks (tool_result, tool_use, image) pass through intact.
          const beforeLen = msg.content.length;
          msg.content = msg.content.filter(b =>
            !(b && b.type === 'text' && b.text === '')
          );
          if (msg.content.length !== beforeLen) changed = true;
        }
      }
      if (changed) {
        console.log('[ORCH-STRIP] Removed orchestration tags from messages');
        return JSON.stringify(parsed);
      }
    }
  } catch (e) { /* not valid JSON at this stage, skip */ }
  return bodyStr;
}

// ─── Layer 12: Billable Beta Filtering (ported from dario/proxy.ts) ─────────
// extended-cache-ttl-* betas require Extra Usage to be enabled on the account.
// Filter them out to avoid 400 errors on subscription-only accounts.
const BILLABLE_BETA_PREFIXES = ['extended-cache-ttl-'];

function filterBillableBetas(betaStr) {
  return betaStr.split(',').map(b => b.trim()).filter(b =>
    b.length > 0 && !BILLABLE_BETA_PREFIXES.some(p => b.startsWith(p))
  ).join(',');
}

// ─── Layer 13: Header Ordering (ported from dario/cc-template.ts) ───────────
// CC sends headers in a specific order. Node's http module uses insertion order.
// Reproduce CC's exact header order to avoid server-side fingerprinting.
const CC_HEADER_ORDER = [
  'accept', 'content-type', 'user-agent', 'x-claude-code-session-id',
  'x-stainless-arch', 'x-stainless-lang', 'x-stainless-os',
  'x-stainless-package-version', 'x-stainless-retry-count',
  'x-stainless-runtime', 'x-stainless-runtime-version',
  'x-stainless-timeout', 'anthropic-beta',
  'anthropic-dangerous-direct-browser-access', 'anthropic-version',
  'authorization', 'x-app', 'content-length',
];

function orderHeadersForOutbound(headers) {
  const lowerToValue = new Map();
  const lowerToOrigKey = new Map();
  for (const [k, v] of Object.entries(headers)) {
    const lk = k.toLowerCase();
    lowerToValue.set(lk, v);
    lowerToOrigKey.set(lk, k);
  }
  const ordered = {};
  const seen = new Set();
  for (const name of CC_HEADER_ORDER) {
    const key = name.toLowerCase();
    if (seen.has(key)) continue;
    const value = lowerToValue.get(key);
    if (value !== undefined) {
      ordered[name] = value;
      seen.add(key);
    }
  }
  // Append any headers not in the CC order (e.g. custom headers)
  for (const [k, v] of Object.entries(headers)) {
    const lk = k.toLowerCase();
    if (!seen.has(lk)) {
      ordered[k] = v;
    }
  }
  return ordered;
}

// ─── Layer 14: Body Field Ordering (ported from dario/cc-template.ts) ───────
// JSON key order is observable on the wire. CC sends fields in a specific order.
const CC_BODY_FIELD_ORDER = [
  'model', 'messages', 'system', 'tools', 'metadata', 'max_tokens',
  'thinking', 'context_management', 'output_config', 'stream',
  'temperature', 'top_k', 'top_p', 'stop_sequences', 'tool_choice',
];

function orderBodyForOutbound(body) {
  const ordered = {};
  const seen = new Set();
  for (const name of CC_BODY_FIELD_ORDER) {
    if (seen.has(name)) continue;
    if (Object.prototype.hasOwnProperty.call(body, name)) {
      ordered[name] = body[name];
      seen.add(name);
    }
  }
  // Append any fields not in the CC order
  for (const k of Object.keys(body)) {
    if (!seen.has(k)) {
      ordered[k] = body[k];
    }
  }
  return ordered;
}



// Beta flags required for OAuth + Claude Code features
// [dario] Updated to match CC v2.1.114 captured beta set from dario v3.30
const REQUIRED_BETAS = [
  'claude-code-20250219',
  'oauth-2025-04-20',
  'interleaved-thinking-2025-05-14',
  'context-management-2025-06-27',
  'prompt-caching-scope-2026-01-05',
  'advisor-tool-2026-03-01',
  'afk-mode-2026-01-31'
];

// Model-aware beta selection:
// - Haiku cannot handle interleaved-thinking (returns 400)
// - effort-2025-11-24 only applies to 4.6 models (Sonnet/Opus 4-6)
function getModelBetas(modelId) {
  const m = (modelId || '').toLowerCase();
  const betas = [...REQUIRED_BETAS];
  // Haiku rejects interleaved-thinking with 400
  if (m.includes('haiku')) {
    const idx = betas.indexOf('interleaved-thinking-2025-05-14');
    if (idx !== -1) betas.splice(idx, 1);
  }
  // effort beta only for 4.6 models
  if (m.includes('4-6') || m.includes('4_6')) {
    if (!betas.includes('effort-2025-11-24')) betas.push('effort-2025-11-24');
  }
  return betas;
}

// ─── CC Tool Stubs ──────────────────────────────────────────────────────────
// Injected into tools array to make the tool set look more like a Claude Code
// session. The model won't call these (schemas are minimal).
// CC tool stubs disabled by default — bare PascalCase names without mcp_ prefix cause
// 'tool not found' loops (upstream issue #43). Only enable for detection testing.
const CC_TOOL_STUBS = [
  '{"name":"mcp_Glob","description":"Find files by pattern","input_schema":{"type":"object","properties":{"pattern":{"type":"string","description":"Glob pattern"}},"required":["pattern"]}}',
  '{"name":"mcp_Grep","description":"Search file contents","input_schema":{"type":"object","properties":{"pattern":{"type":"string","description":"Regex pattern"},"path":{"type":"string","description":"Search path"}},"required":["pattern"]}}',
  '{"name":"mcp_Agent","description":"Launch a subagent for complex tasks","input_schema":{"type":"object","properties":{"prompt":{"type":"string","description":"Task description"}},"required":["prompt"]}}',
  '{"name":"mcp_NotebookEdit","description":"Edit notebook cells","input_schema":{"type":"object","properties":{"notebook_path":{"type":"string"},"cell_index":{"type":"integer"}},"required":["notebook_path"]}}',
  '{"name":"mcp_TodoRead","description":"Read current task list","input_schema":{"type":"object","properties":{}}}'
];

// ─── Layer 3: Tool Name Renames ─────────────────────────────────────────────
// Applied as "quoted" replacements ("name" -> "Name") throughout the ENTIRE body.
// This defeats Anthropic's tool-name fingerprinting which identifies the request
// as OpenClaw based on the combination of tool names in the tools array.
// ORDERING: lcm_expand_query MUST come before lcm_expand to avoid partial match.
// Tool renames use mcp_ prefix — Anthropic's billing validator rejects bare PascalCase names
// NOTE: 'image' → 'mcp_ImageGen' removed — collides with Anthropic content block type "image"
// (image content blocks would have their type renamed, causing 400 errors — upstream issue #14)
const DEFAULT_TOOL_RENAMES = [
  ['exec', 'mcp_Bash'],
  ['process', 'mcp_BashSession'],
  ['browser', 'mcp_BrowserControl'],
  ['canvas', 'mcp_CanvasView'],
  ['nodes', 'mcp_DeviceControl'],
  ['cron', 'mcp_Scheduler'],
  ['message', 'mcp_SendMessage'],
  ['tts', 'mcp_Speech'],
  ['gateway', 'mcp_SystemCtl'],
  ['agents_list', 'mcp_AgentList'],
  ['sessions_list', 'mcp_TaskList'],
  ['sessions_history', 'mcp_TaskHistory'],
  ['sessions_send', 'mcp_TaskSend'],
  ['sessions_spawn', 'mcp_TaskCreate'],
  ['subagents', 'mcp_AgentControl'],
  ['session_status', 'mcp_StatusCheck'],
  ['read', 'mcp_Read'],
  ['write', 'mcp_Write'],
  ['edit', 'mcp_Edit'],
  ['grep', 'mcp_Grep'],
  ['glob', 'mcp_Glob'],
  ['ls', 'mcp_LS'],
  ['web_search', 'mcp_WebSearch'],
  ['web_fetch', 'mcp_WebFetch'],
  ['pdf', 'mcp_PdfParse'],
  ['memory_search', 'mcp_KnowledgeSearch'],
  ['memory_get', 'mcp_KnowledgeGet'],
  ['lcm_expand_query', 'mcp_ContextQuery'],
  ['lcm_grep', 'mcp_ContextGrep'],
  ['lcm_describe', 'mcp_ContextDescribe'],
  ['lcm_expand', 'mcp_ContextExpand'],
  ['sessions_yield', 'mcp_TaskYield'],
  ['sessions_store', 'mcp_TaskStore'],
  ['sessions_yield_interrupt', 'mcp_TaskYieldInterrupt'],
  ['image_generate', 'mcp_ImageCreate'],
  ['music_generate', 'mcp_MusicCreate'],
  ['video_generate', 'mcp_VideoCreate'],
  ['ollama_web_search', 'mcp_OllamaSearch'],
  ['ollama_web_fetch', 'mcp_OllamaFetch']
];

// ─── Layer 6: Property Name Renames ─────────────────────────────────────────
// OC-specific schema property names that contribute to fingerprinting.
const DEFAULT_PROP_RENAMES = [
  ['session_id', 'thread_id'],
  ['conversation_id', 'thread_ref'],
  ['summaryIds', 'chunk_ids'],
  ['summary_id', 'chunk_id'],
  ['system_event', 'event_text'],
  ['agent_id', 'worker_id'],
  ['wake_at', 'trigger_at'],
  ['wake_event', 'trigger_event']
];

// ─── Layer 2: String Trigger Replacements ─────────────────────────────────────────────
// Layer 2: String trigger sanitization.
// Applied globally via split/join on the entire request body.
// IMPORTANT: Use space-free replacements for lowercase 'openclaw' to avoid
// breaking filesystem paths.
// [dario] Framework pattern scrubbing improvements ported from dario/cc-template.ts
// Added: sessions_* pattern, gateway, powered by, and additional framework names
const DEFAULT_REPLACEMENTS = [
  ['OpenClaw', 'OCPlatform'],
  ['openclaw', 'ocplatform'],
  ['sessions_spawn', 'create_task'],
  ['sessions_list', 'list_tasks'],
  ['sessions_history', 'get_history'],
  ['sessions_send', 'send_to_task'],
  ['sessions_yield_interrupt', 'task_yield_interrupt'],
  ['sessions_yield', 'yield_task'],
  ['sessions_store', 'task_store'],
  ['HEARTBEAT_OK', 'HB_ACK'],
  ['running inside', 'running on'],
  ['Hermes', 'Assistant'],
  ['LibreChat', 'Assistant'],
  ['TypingMind', 'Assistant']
];

// Reverse mapping: applied to API responses before returning to OpenClaw.
// This ensures OpenClaw sees original tool names, file paths, and identifiers.
const DEFAULT_REVERSE_MAP = [
  ['OCPlatform', 'OpenClaw'],
  ['ocplatform', 'openclaw'],
  ['create_task', 'sessions_spawn'],
  ['list_tasks', 'sessions_list'],
  ['get_history', 'sessions_history'],
  ['send_to_task', 'sessions_send'],
  ['task_yield_interrupt', 'sessions_yield_interrupt'],
  ['yield_task', 'sessions_yield'],
  ['task_store', 'sessions_store'],
  ['HB_ACK', 'HEARTBEAT_OK']
];

// ─── Configuration ──────────────────────────────────────────────────────────
function loadConfig() {
  const args = process.argv.slice(2);
  let configPath = null;
  let cliPort = null;
  let cacheEnabled = true;

  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--port' && args[i + 1]) {
      port = parseInt(args[i + 1], 10);
      if (isNaN(port) || port < 1 || port > 65535) {
        console.error('[ERROR] Invalid port: ' + args[i + 1] + '. Must be 1-65535.');
        process.exit(1);
      }
    }
    if (args[i] === '--config' && args[i + 1]) configPath = args[i + 1];
    if (args[i] === '--no-cache') cacheEnabled = false;
  }

  const envPort = process.env.PROXY_PORT ? parseInt(process.env.PROXY_PORT) : null;

  let config = {};
  if (configPath && fs.existsSync(configPath)) {
    try { config = JSON.parse(fs.readFileSync(configPath, 'utf8')); } catch(e) {
      console.error('[ERROR] Failed to parse config: ' + configPath + ' (' + e.message + ')');
      process.exit(1);
    }
  } else if (fs.existsSync('config.json')) {
    try { config = JSON.parse(fs.readFileSync('config.json', 'utf8')); } catch(e) {
      console.error('[PROXY] Warning: config.json is invalid, using defaults. (' + e.message + ')');
    }
  }

  // Find Claude Code credentials
  const homeDir = os.homedir();
  // OAUTH_TOKEN env var takes precedence over all file-based credentials
  if (process.env.OAUTH_TOKEN) {
    credsPath = 'env';
    console.log('[PROXY] Using OAUTH_TOKEN from environment variable.');
  }

  const credsPaths = [
    config.credentialsPath,
    path.join(homeDir, '.claude', '.credentials.json'),
    path.join(homeDir, '.claude', 'credentials.json')
  ].filter(Boolean);

  let credsPath = null;

  if (!credsPath) {
  for (const p of credsPaths) {
    const resolved = p.startsWith('~') ? path.join(homeDir, p.slice(1)) : p;
    if (fs.existsSync(resolved) && fs.statSync(resolved).size > 0) {
      credsPath = resolved;
      break;
    }
  }
  }

  // macOS Keychain fallback: extract token and write to file
  if (!credsPath && process.platform === 'darwin') {
    const creds = readKeychainToken();
    if (creds) {
      credsPath = path.join(homeDir, '.claude', '.credentials.json');
      fs.mkdirSync(path.join(homeDir, '.claude'), { recursive: true, mode: 0o700 });
      fs.writeFileSync(credsPath, JSON.stringify(creds), { mode: 0o600 });
      console.log('[PROXY] Extracted credentials from macOS Keychain to ' + credsPath);
    }
  }

  if (!credsPath) {
    console.error('[ERROR] Claude Code credentials not found.');
    console.error('Run "claude auth login" first to authenticate.');
    console.error('On macOS, try: claude -p "test" --max-turns 1 --no-session-persistence');
    console.error('Then run this proxy again.');
    console.error('Searched:', credsPaths.join(', '));
    if (process.platform === 'darwin') {
      console.error('Also checked macOS Keychain (Claude Code-credentials, claude-code, claude, com.anthropic.claude-code)');
    }
    process.exit(1);
  }

  // Merge config arrays with defaults (config entries override by first element match).
  // Set config.mergeDefaults = false to use config arrays as-is (old behavior).
  const shouldMerge = config.mergeDefaults !== false;

  function mergeArrayPairs(defaults, overrides) {
    if (!overrides) return defaults;
    if (!shouldMerge) return overrides;
    const merged = [...defaults];
    for (const entry of overrides) {
      const idx = merged.findIndex(d => d[0] === entry[0]);
      if (idx !== -1) merged[idx] = entry;
      else merged.push(entry);
    }
    return merged;
  }

  return {
    port: envPort || cliPort || config.port || DEFAULT_PORT,
    credsPath,
    cacheEnabled,
    replacements: mergeArrayPairs(DEFAULT_REPLACEMENTS, config.replacements),
    reverseMap: mergeArrayPairs(DEFAULT_REVERSE_MAP, config.reverseMap),
    toolRenames: mergeArrayPairs(DEFAULT_TOOL_RENAMES, config.toolRenames),
    propRenames: mergeArrayPairs(DEFAULT_PROP_RENAMES, config.propRenames),
    stripSystemConfig: config.stripSystemConfig !== false,
    stripToolDescriptions: config.stripToolDescriptions !== false,
    // CC tool stubs disabled by default — causes 'tool not found' loops (upstream issue #43)
    injectCCStubs: config.injectCCStubs === true,
    stripTrailingAssistantPrefill: config.stripTrailingAssistantPrefill !== false,
    refreshEnabled: config.refreshEnabled !== false,
    refreshThresholdMs: (config.refreshThresholdMinutes || DEFAULT_REFRESH_THRESHOLD_MINUTES) * 60 * 1000,
    refreshRetryMs: (config.refreshRetrySeconds || DEFAULT_REFRESH_RETRY_SECONDS) * 1000
  };
}

// ─── Token Management ───────────────────────────────────────────────────────
const KEYCHAIN_SERVICE_NAMES = ['Claude Code-credentials', 'claude-code', 'claude', 'com.anthropic.claude-code'];
const TOKEN_REFRESH_BUFFER_MS = 5 * 60 * 1000;        // refresh when token has < 5 min left
const PROACTIVE_SYNC_TRIGGER_MS = 30 * 60 * 1000;     // skip Keychain probe if > 30 min remaining

// Periodic credential refresh defaults (overridable via config.json)
const DEFAULT_REFRESH_THRESHOLD_MINUTES = 2;
const DEFAULT_REFRESH_RETRY_SECONDS = 15;
const CLAUDE_CLI_REFRESH_TIMEOUT_MS = 30000;

let _cachedKeychainServiceName = null; // remember which service name worked

function readKeychainToken() {
  if (process.platform !== 'darwin') return null;
  const { execFileSync } = require('child_process');
  const namesToTry = _cachedKeychainServiceName
    ? [_cachedKeychainServiceName, ...KEYCHAIN_SERVICE_NAMES.filter(n => n !== _cachedKeychainServiceName)]
    : KEYCHAIN_SERVICE_NAMES;
  for (const svc of namesToTry) {
    try {
      const token = execFileSync('security', ['find-generic-password', '-s', svc, '-w'], { encoding: 'utf8', stdio: ['pipe', 'pipe', 'ignore'] }).trim();
      if (!token) continue;
      let creds;
      try { creds = JSON.parse(token); } catch(e) {
        if (token.startsWith('sk-ant-')) {
          creds = { claudeAiOauth: { accessToken: token, expiresAt: Date.now() + 86400000, subscriptionType: 'unknown' } };
        }
      }
      if (creds && creds.claudeAiOauth && creds.claudeAiOauth.accessToken) {
        _cachedKeychainServiceName = svc;
        return creds;
      }
    } catch(e) { /* not found or access denied */ }
  }
  return null;
}

// Mtime-keyed cache of the parsed credentials file. Avoids re-reading and
// re-parsing JSON on every proxied request. Invalidated automatically when
// the file changes on disk (refreshFromKeychain writes update mtime).
let _credsCache = { path: null, mtimeMs: 0, parsed: null };

function readCredsFile(credsPath) {
  const st = fs.statSync(credsPath);
  if (_credsCache.path === credsPath && _credsCache.mtimeMs === st.mtimeMs) {
    return _credsCache.parsed;
  }
  const parsed = JSON.parse(fs.readFileSync(credsPath, 'utf8'));
  _credsCache = { path: credsPath, mtimeMs: st.mtimeMs, parsed };
  return parsed;
}

function refreshFromKeychain(credsPath) {
  const creds = readKeychainToken();
  if (!creds || creds.claudeAiOauth.expiresAt <= Date.now()) return null;
  fs.writeFileSync(credsPath, JSON.stringify(creds), { mode: 0o600 });
  return creds.claudeAiOauth;
}

// Compares Keychain against file; if Keychain has a strictly newer token,
// updates the file. Returns { updated, newExpiresAt? }.
function proactiveKeychainSync(credsPath) {
  // Skip the subprocess when the file token still has plenty of life — the
  // 5-minute periodic timer would otherwise spawn `security` for nothing.
  let fileExp = 0;
  try {
    const fileCreds = readCredsFile(credsPath);
    fileExp = (fileCreds.claudeAiOauth && fileCreds.claudeAiOauth.expiresAt) || 0;
  } catch(e) { /* file missing or corrupt — treat as stale, force probe */ }

  if (fileExp > Date.now() + PROACTIVE_SYNC_TRIGGER_MS) {
    return { updated: false };
  }

  const kc = readKeychainToken();
  if (!kc) return { updated: false };
  const kcExp = kc.claudeAiOauth.expiresAt || 0;
  if (kcExp <= Date.now() || kcExp <= fileExp) return { updated: false };

  fs.writeFileSync(credsPath, JSON.stringify(kc), { mode: 0o600 });
  return { updated: true, newExpiresAt: kcExp };
}

function getToken(credsPath) {
  const creds = readCredsFile(credsPath);
  const oauth = creds.claudeAiOauth;
  if (!oauth || !oauth.accessToken) {
    throw new Error('No OAuth token in credentials file. Run "claude auth login".');
  }
  if (oauth.expiresAt && oauth.expiresAt < Date.now() + TOKEN_REFRESH_BUFFER_MS) {
    const refreshed = refreshFromKeychain(credsPath);
    if (refreshed) return refreshed;
    // Stale token returned so caller gets a clear 401 from upstream rather
    // than a cryptic local error.
    const expiredAgo = ((Date.now() - oauth.expiresAt) / 60000).toFixed(0);
    console.error(`[PROXY] Token expired ${expiredAgo}m ago. Run "claude auth login" to refresh.`);
  }
  return oauth;
}

// ─── Periodic Credential Refresh ────────────────────────────────────────────
// Checks token expiry and refreshes via Claude CLI + Keychain re-extraction.
// See: https://github.com/zacdcook/openclaw-billing-proxy/pull/32
function refreshCredentials(credsPath) {
  if (credsPath === 'env') return false;
  const { execSync } = require('child_process');

  // Step 1: Trigger Claude CLI to refresh the underlying credential store
  try {
    execSync('claude -p "ping" --max-turns 1 --no-session-persistence', {
      timeout: CLAUDE_CLI_REFRESH_TIMEOUT_MS,
      stdio: 'pipe'
    });
  } catch(e) {
    console.error('[PROXY] claude CLI refresh failed: ' + (e.message || 'unknown'));
    // Continue anyway — Keychain may still have a fresh token from elsewhere
  }

  // Step 2: On macOS, re-extract from Keychain into the snapshot file
  if (process.platform === 'darwin') {
    const creds = readKeychainToken();
    if (creds && creds.claudeAiOauth && creds.claudeAiOauth.accessToken) {
      fs.mkdirSync(path.dirname(credsPath), { recursive: true });
      fs.writeFileSync(credsPath, JSON.stringify(creds), { mode: 0o600 });
      return true;
    }
  }

  // Step 3: Verify file is readable and fresh
  try { getToken(credsPath); return true; } catch(e) { return false; }
}

// Returns 'retry' if the caller should re-check quickly (e.g. refresh was a
// no-op because the Claude CLI declined to rotate), 'ok' otherwise.
function maybeRefreshCredentials(config) {
  if (!config.refreshEnabled || config.credsPath === 'env') return 'ok';
  try {
    const oauth = getToken(config.credsPath);
    const remainingMs = oauth.expiresAt - Date.now();
    if (remainingMs > config.refreshThresholdMs) return 'ok';
    const remainingMin = (remainingMs / 60000).toFixed(1);
    console.log('[PROXY] Token expires in ' + remainingMin + 'm, refreshing...');
    if (!refreshCredentials(config.credsPath)) {
      console.error('[PROXY] Token refresh failed — run `claude auth login` manually');
      return 'retry';
    }
    const newOauth = getToken(config.credsPath);
    if (newOauth.expiresAt <= oauth.expiresAt) {
      const newMin = ((newOauth.expiresAt - Date.now()) / 60000).toFixed(1);
      console.log('[PROXY] Token refresh was a no-op (still ' + newMin + 'm), retrying shortly');
      return 'retry';
    }
    const newHours = ((newOauth.expiresAt - Date.now()) / 3600000).toFixed(1);
    console.log('[PROXY] Token refreshed, now expires in ' + newHours + 'h');
    return 'ok';
  } catch(e) {
    console.error('[PROXY] Refresh check error: ' + e.message);
    return 'ok';
  }
}

// ─── Helper ─────────────────────────────────────────────────────────────────
function findMatchingBracket(str, start) {
  let d = 0;
  let inString = false;
  for (let i = start; i < str.length; i++) {
    const ch = str[i];
    if (inString) {
      // Skip escaped characters inside strings (including \")
      if (ch === '\\') { i++; continue; }
      if (ch === '"') inString = false;
      continue;
    }
    if (ch === '"') { inString = true; continue; }
    if (ch === '[') d++;
    else if (ch === ']') { d--; if (d === 0) return i; }
  }
  return -1;
}

// ─── Thinking Block Preservation ────────────────────────────────────────────
// When extended thinking is enabled, Anthropic requires thinking blocks to be
// returned verbatim on subsequent turns. String replacements/renames that mutate
// thinking block content cause rejection. These helpers replace thinking and
// redacted_thinking content blocks with unique placeholders before transforms,
// then restore them afterwards.

function maskThinkingBlocks(bodyStr) {
  const store = [];
  // Match "type":"thinking" and "type":"redacted_thinking" content blocks
  // These appear in messages[].content arrays from prior assistant turns
  const pattern = /\{"type":"(?:thinking|redacted_thinking)"[^}]*?"(?:thinking|data)":"(?:[^"\\]|\\.)*"[^}]*?\}/g;
  const masked = bodyStr.replace(pattern, (match) => {
    const id = `__THINKING_PLACEHOLDER_${store.length}__`;
    store.push({ id, original: match });
    return `"${id}"`;
  });
  return { masked, store };
}

function unmaskThinkingBlocks(bodyStr, store) {
  let result = bodyStr;
  for (const { id, original } of store) {
    result = result.split(`"${id}"`).join(original);
  }
  return result;
}

// Check if a request body has thinking enabled
function hasThinkingEnabled(bodyStr) {
  return /"type"\s*:\s*"(?:adaptive|enabled)"/.test(bodyStr) &&
         /"thinking"\s*:\s*\{/.test(bodyStr);
}

// ─── SSE Thinking Event Detection ──────────────────────────────────────────
// Detects thinking_delta and content_block_start/stop for thinking blocks
// in SSE streams, passing them through unchanged.
function isThinkingSSEEvent(eventStr) {
  // thinking content_block_delta events
  if (eventStr.includes('"thinking_delta"') || eventStr.includes('"thinking"')) {
    if (eventStr.includes('content_block_delta') || eventStr.includes('content_block_start') || eventStr.includes('content_block_stop')) {
      return true;
    }
  }
  // redacted_thinking blocks
  if (eventStr.includes('"redacted_thinking"')) return true;
  return false;
}

// ─── Tool Pair Repair ───────────────────────────────────────────────────────
// Removes orphaned tool_use/tool_result blocks that would cause API 400 errors.
// Must run before any transforms since it needs valid JSON to parse.
function repairToolPairs(bodyStr) {
  const msgArrayMatch = /"messages"\s*:\s*(\[)/.exec(bodyStr);
  if (!msgArrayMatch) return bodyStr;
  const arrayOpenIdx = msgArrayMatch.index + msgArrayMatch[0].length - 1;
  const arrayCloseIdx = findMatchingBracket(bodyStr, arrayOpenIdx);
  if (arrayCloseIdx === -1) return bodyStr;

  let messages;
  try {
    messages = JSON.parse(bodyStr.slice(arrayOpenIdx, arrayCloseIdx + 1));
  } catch (e) {
    return bodyStr; // if parse fails, leave untouched
  }
  if (!Array.isArray(messages)) return bodyStr;

  const toolUseIds = new Set();
  const toolResultIds = new Set();
  for (const message of messages) {
    if (!Array.isArray(message.content)) continue;
    for (const block of message.content) {
      if (block.type === 'tool_use' && typeof block.id === 'string') toolUseIds.add(block.id);
      if (block.type === 'tool_result' && typeof block.tool_use_id === 'string') toolResultIds.add(block.tool_use_id);
    }
  }

  const orphanedUses = new Set([...toolUseIds].filter(id => !toolResultIds.has(id)));
  const orphanedResults = new Set([...toolResultIds].filter(id => !toolUseIds.has(id)));
  if (orphanedUses.size === 0 && orphanedResults.size === 0) return bodyStr;

  console.log(`[REPAIR] Removing ${orphanedUses.size} orphaned tool_use and ${orphanedResults.size} orphaned tool_result blocks`);

  const candidateRepaired = messages.map((message) => {
    if (!Array.isArray(message.content)) return message;
    const filtered = message.content.filter((block) => {
      if (block.type === 'tool_use' && typeof block.id === 'string') return !orphanedUses.has(block.id);
      if (block.type === 'tool_result' && typeof block.tool_use_id === 'string') return !orphanedResults.has(block.tool_use_id);
      return true;
    });
    if (filtered.length === 0) return null;
    return { ...message, content: filtered };
  });

  const repaired = [];
  for (let i = 0; i < candidateRepaired.length; i++) {
    if (candidateRepaired[i] !== null) {
      repaired.push(candidateRepaired[i]);
    } else {
      const prevRole = repaired.length > 0 ? repaired[repaired.length - 1].role : null;
      const nextMsg = candidateRepaired.slice(i + 1).find(m => m !== null);
      const nextRole = nextMsg ? nextMsg.role : null;
      if (prevRole && nextRole && prevRole === nextRole) {
        repaired.push({ ...messages[i], content: [{ type: 'text', text: '(removed)' }] });
      }
    }
  }

  return bodyStr.slice(0, arrayOpenIdx) + JSON.stringify(repaired) + bodyStr.slice(arrayCloseIdx + 1);
}

// ─── Request Processing ─────────────────────────────────────────────────────
// BILLING_OBJ removed — now uses dynamic buildBillingBlock()
const CACHE_1H = { type: 'ephemeral', ttl: '1h' };

function processBody(bodyStr, config) {
  // Repair orphaned tool_use/tool_result pairs before any transforms
  bodyStr = repairToolPairs(bodyStr);

  // [dario] Layer 11: Strip orchestration tags from messages before any other transforms
  bodyStr = sanitizeMessageOrchestration(bodyStr);

  // Extract original first user text for billing tag computation BEFORE any transforms
  const originalFirstUserText = extractFirstUserMessageText(bodyStr);

  // Thinking block preservation: mask thinking blocks before any transforms
  const thinkingActive = hasThinkingEnabled(bodyStr);
  let thinkingStore = [];
  let modified = bodyStr;
  if (thinkingActive) {
    const masked = maskThinkingBlocks(modified);
    modified = masked.masked;
    thinkingStore = masked.store;
    if (thinkingStore.length > 0) {
      console.log(`[THINKING] Masked ${thinkingStore.length} thinking block(s) before transforms`);
    }
  }

  // Layer 2: String trigger sanitization (global split/join)
  for (const [find, replace] of config.replacements) {
    modified = modified.split(find).join(replace);
  }

  // Layer 3: Tool name fingerprint bypass
  // Use "name":"X" pattern to avoid renaming content type tags (e.g. "type":"image")
  // See: https://github.com/zacdcook/openclaw-billing-proxy/issues/14
  for (const [orig, cc] of (config.toolRenames || [])) {
    // Rename tool names: "name":"exec" -> "name":"Bash"
    modified = modified.split('"name":"' + orig + '"').join('"name":"' + cc + '"');
    // Also handle tool_use blocks: "name": "exec" (with space after colon)
    modified = modified.split('"name": "' + orig + '"').join('"name": "' + cc + '"');
  }

  // Layer 6: Property name renaming
  for (const [orig, renamed] of (config.propRenames || [])) {
    modified = modified.split('"' + orig + '"').join('"' + renamed + '"');
  }

  // Layer 4: System prompt template bypass
  // Strip the OC config section (~28K) between identity line and first workspace doc
  if (config.stripSystemConfig) {
    // Anchor to system array start for reliable stripping
    const sysArrayStart = modified.indexOf('"system":[');
    const IDENTITY_MARKER = 'You are a personal assistant';
    const configStart = sysArrayStart !== -1 ? modified.indexOf(IDENTITY_MARKER, sysArrayStart) : modified.indexOf(IDENTITY_MARKER);
    if (configStart !== -1) {
      let stripFrom = configStart;
      if (stripFrom >= 2 && modified[stripFrom - 2] === '\\' && modified[stripFrom - 1] === 'n') {
        stripFrom -= 2;
      }
      // Use filesystem path header patterns as boundary landmark.
      // "AGENTS.md" can appear in skill content; \n## / (Unix) or \n## C:\ (Windows)
      // only appear in workspace doc headers injected by the platform.
      let configEnd = -1;
      const unixBoundary = modified.indexOf('\\n## /', configStart);
      const winBoundary = modified.indexOf('\\n## C:\\\\', configStart);
      if (unixBoundary !== -1 && (winBoundary === -1 || unixBoundary < winBoundary)) {
        configEnd = unixBoundary + 3; // point past \n to the ##
      } else if (winBoundary !== -1) {
        configEnd = winBoundary + 3;
      }
      // Fallback to AGENTS.md if path patterns not found
      if (configEnd === -1) configEnd = modified.indexOf('AGENTS.md', configStart);
      if (configEnd !== -1) {
        let boundary = configEnd;
        for (let i = configEnd - 1; i > stripFrom; i--) {
          if (modified[i] === '#' && modified[i - 1] === '#' && i >= 3 && modified[i - 3] === '\\' && modified[i - 2] === 'n') {
            boundary = i - 3;
            break;
          }
        }
        const strippedLen = boundary - stripFrom;
        if (strippedLen > 1000) {
          const PARAPHRASE =
            '\\nYou are an AI operations assistant with access to all tools listed in this request ' +
            'for file operations, command execution, web search, browser control, scheduling, ' +
            'messaging, and session management. Tool names are case-sensitive and must be called ' +
            'exactly as listed. Your responses route to the active channel automatically. ' +
            'For cross-session communication, use the task messaging tools. ' +
            'Skills defined in your workspace should be invoked when they match user requests. ' +
            'Consult your workspace reference files for detailed operational configuration.\\n';
          modified = modified.slice(0, stripFrom) + PARAPHRASE + modified.slice(boundary);
          console.log(`[STRIP] Removed ${strippedLen} chars of config template`);
        }
      }
    }
  }

  // Layer 5: Tool description stripping + CC tool stub injection (string-based)
  if (config.stripToolDescriptions) {
    const toolsIdx = modified.indexOf('"tools":[');
    if (toolsIdx !== -1) {
      const toolsEndIdx = findMatchingBracket(modified, toolsIdx + '"tools":'.length);
      if (toolsEndIdx !== -1) {
        let section = modified.slice(toolsIdx, toolsEndIdx + 1);
        let from = 0;
        while (true) {
          const d = section.indexOf('"description":"', from);
          if (d === -1) break;
          const vs = d + '"description":"'.length;
          let i = vs;
          while (i < section.length) {
            if (section[i] === '\\' && i + 1 < section.length) { i += 2; continue; }
            if (section[i] === '"') break;
            i++;
          }
          section = section.slice(0, vs) + section.slice(i);
          from = vs + 1;
        }
        if (config.injectCCStubs) {
          // Dedupe: skip stubs whose name matches a toolRename target (issue #43)
          const renamedTargets = new Set((config.toolRenames || []).map(([, cc]) => cc));
          const filteredStubs = CC_TOOL_STUBS.filter(s => {
            const m = s.match(/"name":"([^"]+)"/);
            return m ? !renamedTargets.has(m[1]) : true;
          });
          if (filteredStubs.length > 0) {
            const insertAt = '"tools":['.length;
            section = section.slice(0, insertAt) + filteredStubs.join(',') + ',' + section.slice(insertAt);
          }
        }
        modified = modified.slice(0, toolsIdx) + section + modified.slice(toolsEndIdx + 1);
      }
    }
  } else if (config.injectCCStubs) {
    const toolsIdx = modified.indexOf('"tools":[');
    if (toolsIdx !== -1) {
      // Dedupe: skip stubs whose name matches a toolRename target (issue #43)
      const renamedTargets = new Set((config.toolRenames || []).map(([, cc]) => cc));
      const filteredStubs = CC_TOOL_STUBS.filter(s => {
        const m = s.match(/"name":"([^"]+)"/);
        return m ? !renamedTargets.has(m[1]) : true;
      });
      if (filteredStubs.length > 0) {
        const insertAt = toolsIdx + '"tools":['.length;
        modified = modified.slice(0, insertAt) + filteredStubs.join(',') + ',' + modified.slice(insertAt);
      }
    }
  }

  // Restore thinking blocks after string transforms, before JSON parse
  if (thinkingActive && thinkingStore.length > 0) {
    modified = unmaskThinkingBlocks(modified, thinkingStore);
  }

  // 2. Parse JSON for structured modifications (billing + cache_control)
  try {
    const parsed = JSON.parse(modified);

    // Layer 8: Dynamic billing block + Claude Code identity
    // Use pre-transform text so CCH hash is computed from original content
    const billingObj = buildBillingBlock(originalFirstUserText);
    const identityObj = { type: 'text', text: CLAUDE_CODE_IDENTITY_STRING, cache_control: CACHE_1H };

    // Inject billing + identity into system prompt
    if (Array.isArray(parsed.system)) {
      parsed.system.unshift(identityObj);
      parsed.system.unshift(billingObj);
    } else if (typeof parsed.system === 'string') {
      parsed.system = [billingObj, identityObj, { type: 'text', text: parsed.system }];
    } else {
      parsed.system = [billingObj, identityObj];
    }

    // Layer 8: Request metadata injection (only user_id is allowed by the API)
    // [dario] Session ID now rotated dynamically via getOrRotateSessionId()
    parsed.metadata = {
      ...(parsed.metadata || {}),
      user_id: JSON.stringify({ device_id: DEVICE_ID, session_id: getOrRotateSessionId() })
    };

    // Layer 8: Temperature normalization
    const hasThinking = parsed.thinking && typeof parsed.thinking === 'object' && (parsed.thinking.type === 'adaptive' || parsed.thinking.type === 'enabled');
    if (hasThinking) {
      delete parsed.temperature;
    } else {
      parsed.temperature = 1;
    }

    // Layer 8: Context management injection for thinking requests
    if (hasThinking && !parsed.context_management) {
      parsed.context_management = { edits: [{ type: 'clear_thinking_20251015', keep: 'all' }] };
    }

    // Layer 8: Strip stale betas body field (API rejects it; betas are header-only)
    delete parsed.betas;

    // [dario] Layer 14: Reorder body fields to match CC's wire order
    // JSON key order is observable; CC sends model,messages,system,tools,... in that order
    const orderedParsed = orderBodyForOutbound(parsed);
    // Copy ordered keys back (we return JSON.stringify of parsed, so replace in-place)
    for (const key of Object.keys(parsed)) delete parsed[key];
    Object.assign(parsed, orderedParsed);

    // Strip trailing assistant messages (prefill).
    // OpenClaw sometimes pre-fills the next assistant turn to resume interrupted responses.
    // Opus 4.6 disabled assistant prefill and returns 400:
    //   "This model does not support assistant message prefill."
    // The error is permanent for the session — every retry includes the same prefill.
    // Strip ALL trailing assistant messages until the array ends with a user message.
    // See: https://github.com/zacdcook/openclaw-billing-proxy/pull/17
    if (config.stripTrailingAssistantPrefill !== false) {
      if (Array.isArray(parsed.messages) && parsed.messages.length > 0) {
        let popped = 0;
        while (parsed.messages.length > 0 &&
               parsed.messages[parsed.messages.length - 1].role === 'assistant') {
          parsed.messages.pop();
          popped++;
        }
        if (popped > 0) {
          console.log(`[STRIP-PREFILL] Removed ${popped} trailing assistant message(s) (${parsed.messages.length} remain)`);
        }
      }
    }

    return JSON.stringify(parsed);
  } catch (e) {
    // Fallback: string-based injection if JSON parse fails
    const sysArrayIdx = modified.indexOf('"system":[');
    if (sysArrayIdx !== -1) {
      const insertAt = sysArrayIdx + '"system":['.length;
      modified = modified.slice(0, insertAt) + JSON.stringify(buildBillingBlock('')) + ',' + modified.slice(insertAt);
    } else if (modified.includes('"system":"')) {
      const sysStart = modified.indexOf('"system":"');
      let i = sysStart + '"system":"'.length;
      while (i < modified.length) {
        if (modified[i] === '\\') { i += 2; continue; }
        if (modified[i] === '"') break;
        i++;
      }
      const sysEnd = i + 1;
      const originalSysStr = modified.slice(sysStart + '"system":'.length, sysEnd);
      modified = modified.slice(0, sysStart)
        + '"system":[' + JSON.stringify(buildBillingBlock('')) + ',{"type":"text","text":' + originalSysStr + '}]'
        + modified.slice(sysEnd);
    } else {
      modified = '{"system":[' + JSON.stringify(buildBillingBlock('')) + '],' + modified.slice(1);
    }
    return modified;
  }
}

// ─── Response Processing ────────────────────────────────────────────────────
function reverseMap(text, config) {
  let result = text;
  // Reverse tool names first (use "name":"X" pattern to avoid clobbering content types)
  // Handle BOTH plain JSON ("name":"X") AND escaped JSON inside string fields (\"name\":\"X\").
  // SSE input_json_delta deltas put nested JSON inside a string field (partial_json),
  // so the inner quotes are escaped. Without the escaped variant, tool_use args
  // never get reverted and the OpenClaw tool runtime fails.
  // See: https://github.com/zacdcook/openclaw-billing-proxy/pull/16
  if (config.toolRenames) {
    for (const [orig, cc] of config.toolRenames) {
      result = result.split('"name":"' + cc + '"').join('"name":"' + orig + '"');
      result = result.split('"name": "' + cc + '"').join('"name": "' + orig + '"');
      result = result.split('\\"' + cc + '\\"').join('\\"' + orig + '\\"');
    }
  }
  // Reverse property names — same dual handling (plain + escaped)
  if (config.propRenames) {
    for (const [orig, renamed] of config.propRenames) {
      result = result.split('"' + renamed + '"').join('"' + orig + '"');
      result = result.split('\\"' + renamed + '\\"').join('\\"' + orig + '\\"');
    }
  }
  // Reverse string replacements
  for (const [sanitized, original] of config.reverseMap) {
    result = result.split(sanitized).join(original);
  }
  return result;
}

// Maximum keyword length across all reverse-map patterns.
// Used to determine how much tail data to hold back between SSE chunks,
// so that a keyword split across two chunks is still caught.
function maxPatternLen(config) {
  let max = 0;
  for (const [sanitized] of config.reverseMap) {
    if (sanitized.length > max) max = sanitized.length;
  }
  // Also consider renamed tool/prop names (they appear in responses as "name":"X")
  if (config.toolRenames) {
    for (const [, cc] of config.toolRenames) {
      const quoted = '"name":"' + cc + '"';
      if (quoted.length > max) max = quoted.length;
      const quotedSpaced = '"name": "' + cc + '"';
      if (quotedSpaced.length > max) max = quotedSpaced.length;
    }
  }
  if (config.propRenames) {
    for (const [, renamed] of config.propRenames) {
      const quoted = '"' + renamed + '"';
      if (quoted.length > max) max = quoted.length;
    }
  }
  return max;
}

// Creates a stateful streaming reverse-mapper that buffers potential
// partial matches at chunk boundaries.
function createStreamReverser(config) {
  const holdBack = Math.max(0, maxPatternLen(config) - 1);
  let pending = '';

  return {
    // Process an incoming chunk; returns the safe-to-flush portion.
    write(chunk) {
      pending += chunk;
      if (pending.length <= holdBack) return '';
      let sliceIdx = pending.length - holdBack;
      // Prefer newline-aligned slicing for SSE (defense-in-depth)
      const lastNl = pending.lastIndexOf('\n', sliceIdx);
      if (lastNl >= 0) sliceIdx = lastNl + 1;
      const safe = pending.slice(0, sliceIdx);
      pending = pending.slice(sliceIdx);
      return reverseMap(safe, config);
    },
    // Flush remaining buffer (call on stream end).
    flush() {
      const rest = pending;
      pending = '';
      return reverseMap(rest, config);
    }
  };
}

// ─── Usage Data Persistence ─────────────────────────────────────────────────
function loadUsageData() {
  try {
    return JSON.parse(fs.readFileSync(USAGE_FILE, 'utf8'));
  } catch (e) { /* missing or corrupt file, start fresh */ }
  return { version: 1, days: {} };
}

let usageData = loadUsageData();
let saveTimer = null;
let usageDirEnsured = false;

function saveUsageData() {
  try {
    if (!usageDirEnsured) {
      fs.mkdirSync(path.dirname(USAGE_FILE), { recursive: true });
      usageDirEnsured = true;
    }
    fs.writeFileSync(USAGE_FILE, JSON.stringify(usageData, null, 2));
  } catch (e) { /* silent */ }
}

function recordUsage(inputTokens, outputTokens) {
  const today = new Date().toISOString().substring(0, 10);
  if (!usageData.days[today]) {
    usageData.days[today] = { input_tokens: 0, output_tokens: 0, requests: 0 };
  }
  usageData.days[today].input_tokens += inputTokens;
  usageData.days[today].output_tokens += outputTokens;
  usageData.days[today].requests += 1;
  if (saveTimer) clearTimeout(saveTimer);
  saveTimer = setTimeout(saveUsageData, 2000);
}

// ─── SSE Token Extraction ──────────────────────────────────────────────────
// Incremental tracker: feed chunks via push(), read totals at end
function createSSETokenTracker() {
  let inputTokens = 0;
  let outputTokens = 0;
  let pending = ''; // leftover partial event from previous chunk
  return {
    push(chunk) {
      pending += chunk;
      const parts = pending.split('\n\n');
      pending = parts.pop(); // last element may be incomplete
      for (const event of parts) {
        const lines = event.split('\n');
        let eventType = '';
        let dataStr = '';
        for (const line of lines) {
          if (line.startsWith('event: ')) eventType = line.slice(7).trim();
          if (line.startsWith('data: ')) dataStr = line.slice(6);
        }
        if (!dataStr) continue;
        try {
          const data = JSON.parse(dataStr);
          if (eventType === 'message_start' && data.message && data.message.usage) {
            inputTokens = data.message.usage.input_tokens || 0;
          }
          if (eventType === 'message_delta' && data.usage) {
            outputTokens = data.usage.output_tokens || 0;
          }
        } catch (e) { /* partial JSON, skip */ }
      }
    },
    get inputTokens() { return inputTokens; },
    get outputTokens() { return outputTokens; },
  };
}

// Batch helper kept for testing convenience
function extractTokensFromSSE(buffer) {
  const tracker = createSSETokenTracker();
  tracker.push(buffer);
  return { inputTokens: tracker.inputTokens, outputTokens: tracker.outputTokens };
}

// ─── Terminal Dashboard ────────────────────────────────────────────────────
const ANSI = {
  hide: '\x1b[?25l', show: '\x1b[?25h',
  home: '\x1b[H', clearDown: '\x1b[J', clearLine: '\x1b[K',
  bold: '\x1b[1m', dim: '\x1b[2m', reset: '\x1b[0m',
  cyan: '\x1b[36m', green: '\x1b[32m', yellow: '\x1b[33m', red: '\x1b[31m',
  gray: '\x1b[90m', white: '\x1b[37m',
  moveTo: (r, c) => `\x1b[${r};${c}H`,
};

function fmt(n) { return n.toLocaleString(); }

const dashboard = {
  isTTY: false,
  config: null,
  startedAt: 0,
  recentLogs: [],     // ring buffer, max 10
  lastRateLimit: null,
  showInfo: false,

  init(config, oauth) {
    this.config = config;
    this.startedAt = Date.now();
    this.isTTY = process.stdout.isTTY || false;
    if (!this.isTTY) {
      // Non-TTY fallback: plain text banner
      const expiresIn = (oauth.expiresAt - Date.now()) / 3600000;
      const h = isFinite(expiresIn) ? expiresIn.toFixed(1) + 'h' : 'n/a (env var)';
      console.log(`\n  Claude Proxy v${VERSION}`);
      console.log(`  Port: ${config.port}  Sub: ${oauth.subscriptionType}  Token: ${h}h  Cache: ${config.cacheEnabled ? '1h TTL' : 'off'}`);
      console.log(`  CC Emulation: v${CC_VERSION}  SDK: 0.81.0  Pacing: ${PACING_MIN_GAP_MS}+${PACING_JITTER_MS}ms`);
      console.log(`  Ready. Set openclaw.json baseUrl to http://127.0.0.1:${config.port}\n`);
      return;
    }
    process.stdout.write(ANSI.hide);
    this._oauth = oauth;
    this.render();
    // Refresh uptime every 60s
    this._uptimeInterval = setInterval(() => { this.refreshToken(); this.renderHeader(); }, 60000);
    process.stdout.on('resize', () => this.render());
    // Key handler for info overlay
    if (process.stdin.isTTY) {
      process.stdin.setRawMode(true);
      process.stdin.resume();
      process.stdin.setEncoding('utf8');
      process.stdin.on('data', (key) => {
        if (key === '\u0003') { dashboard.shutdown(); process.exit(0); } // Ctrl+C
        if (key === 'i' || key === 'I') {
          this.showInfo = !this.showInfo;
          this.render();
        }
        if (key === 'q' || key === 'Q') {
          dashboard.shutdown(); process.exit(0);
        }
      });
    }
  },

  render() {
    if (!this.isTTY) return;
    process.stdout.write(ANSI.home + ANSI.clearDown);
    if (this.showInfo) {
      this.renderInfo();
      return;
    }
    this.renderHeader();
    this.renderRateLimit();
    this.renderSeparator();
    this.renderTokenTable();
    this.renderSeparator();
    this.renderLog();
    // Footer hint
    process.stdout.write(`\n  ${ANSI.gray}[i] info  [q] quit${ANSI.reset}\n`);
  },

  renderInfo() {
    if (!this.isTTY) return;
    const c = ANSI.cyan, g = ANSI.green, y = ANSI.yellow, r = ANSI.reset, b = ANSI.bold, d = ANSI.gray;
    process.stdout.write(`\n  ${b}${c}INFO${r}\n\n`);
    process.stdout.write(`  ${b}Header${r}\n`);
    process.stdout.write(`    ${c}Sub${r}          Subscription tier from Claude Code credentials\n`);
    process.stdout.write(`    ${c}Token${r}        Hours until OAuth token expires (auto-refreshes in CLI)\n`);
    process.stdout.write(`    ${c}Uptime${r}       Time since proxy started\n\n`);
    process.stdout.write(`  ${b}Rate Limit${r}\n`);
    process.stdout.write(`    ${c}5h${r}           5-hour rolling window utilization\n`);
    process.stdout.write(`    ${c}7d${r}           7-day rolling window utilization\n`);
    process.stdout.write(`    ${g}Green${r} <50%   ${y}Yellow${r} 50-80%   ${ANSI.red}Red${r} >80%\n`);
    process.stdout.write(`    ${c}Time${r}         Countdown until that window resets\n\n`);
    process.stdout.write(`  ${b}Token Usage${r}\n`);
    process.stdout.write(`    ${g}Input${r}        Tokens sent to the API (prompts)\n`);
    process.stdout.write(`    ${y}Output${r}       Tokens received from the API (completions)\n`);
    process.stdout.write(`    ${c}(N)${r}          Number of requests that day\n`);
    process.stdout.write(`    Data persisted to ${d}./data/usage.json${r}\n\n`);
    process.stdout.write(`  ${b}Recent Activity${r}\n`);
    process.stdout.write(`    ${c}S/H/O${r}        Model: ${b}S${r}onnet / ${b}H${r}aiku / ${b}O${r}pus\n`);
    process.stdout.write(`    ${g}\u2191N${r}           Input tokens for this request\n`);
    process.stdout.write(`    ${y}\u2193N${r}           Output tokens for this request\n\n`);
    process.stdout.write(`  ${b}Keys${r}\n`);
    process.stdout.write(`    ${c}i${r}            Toggle this info screen\n`);
    process.stdout.write(`    ${c}q${r}            Quit the proxy\n`);
    process.stdout.write(`\n  ${d}Press [i] to return${r}\n`);
  },

  refreshToken() {
    try {
      this._oauth = getToken(this.config.credsPath);
    } catch (e) { /* keep last known oauth */ }
  },

  renderHeader() {
    if (!this.isTTY) return;
    const upSec = Math.floor((Date.now() - this.startedAt) / 1000);
    const upH = Math.floor(upSec / 3600);
    const upM = Math.floor((upSec % 3600) / 60);
    const upStr = upH > 0 ? `${upH}h ${upM}m` : `${upM}m`;

    const h = ((this._oauth.expiresAt - Date.now()) / 3600000).toFixed(1);
    const tokenStr = `Token: ${h}h remaining`;

    process.stdout.write(ANSI.moveTo(1, 1) + ANSI.clearLine);
    process.stdout.write(`  ${ANSI.bold}${ANSI.cyan}Claude Proxy v${VERSION}${ANSI.reset}                  Port: ${this.config.port}   Uptime: ${upStr}`);
    process.stdout.write(ANSI.moveTo(2, 1) + ANSI.clearLine);
    process.stdout.write(`  Sub: ${this._oauth.subscriptionType || 'unknown'}            ${tokenStr}`);
  },

  _renderBar(pct) {
    const barLen = 15;
    const filled = Math.round((pct / 100) * barLen);
    return '\u2588'.repeat(filled) + '\u2591'.repeat(barLen - filled);
  },

  _pctColor(pct) {
    return pct < 50 ? ANSI.green : pct < 80 ? ANSI.yellow : ANSI.red;
  },

  _fmtReset(epoch) {
    if (!epoch) return '';
    const diff = epoch - Math.floor(Date.now() / 1000);
    if (diff <= 0) return 'now';
    const h = Math.floor(diff / 3600);
    const m = Math.floor((diff % 3600) / 60);
    return h > 0 ? `${h}h${m}m` : `${m}m`;
  },

  renderRateLimit() {
    if (!this.isTTY) return;
    process.stdout.write(ANSI.moveTo(3, 1) + ANSI.clearLine);
    if (!this.lastRateLimit) {
      process.stdout.write(`  ${ANSI.gray}Rate: waiting for first request...${ANSI.reset}`);
      return;
    }
    const rl = this.lastRateLimit;
    const parts = [];

    for (const [label, bucket] of [['5h', rl.fiveH], ['7d', rl.sevenD]]) {
      if (!bucket) continue;
      const pct = Math.round(bucket.util * 100);
      const c = this._pctColor(pct);
      const reset = this._fmtReset(bucket.reset);
      parts.push(`${label} ${c}[${this._renderBar(pct)}] ${pct}%${ANSI.reset} ${ANSI.gray}${reset}${ANSI.reset}`);
    }

    if (parts.length > 0) {
      process.stdout.write(`  ${parts.join('    ')}`);
    } else {
      process.stdout.write(`  ${ANSI.gray}Rate: no utilization data${ANSI.reset}`);
    }
  },

  renderSeparator() {
    if (!this.isTTY) return;
    const cols = process.stdout.columns || 70;
    process.stdout.write('\n' + `  ${ANSI.gray}${'─'.repeat(Math.min(cols - 4, 66))}${ANSI.reset}`);
  },

  renderTokenTable() {
    if (!this.isTTY) return;
    const days = usageData.days;
    const sortedKeys = Object.keys(days).sort().reverse().slice(0, 7);
    const today = new Date().toISOString().substring(0, 10);
    const yesterday = new Date(Date.now() - 86400000).toISOString().substring(0, 10);

    process.stdout.write('\n');
    //                    label (28 chars)              10-col     4sp  10-col
    process.stdout.write(`  ${''.padEnd(28)}${ANSI.green}${'Input'.padStart(10)}${ANSI.reset}    ${ANSI.yellow}${'Output'.padStart(10)}${ANSI.reset}\n`);

    let totalIn = 0, totalOut = 0, totalReqs = 0;

    if (sortedKeys.length === 0) {
      process.stdout.write(`  ${ANSI.gray}No usage data yet${ANSI.reset}\n`);
    } else {
      for (const key of sortedKeys) {
        const d = days[key];
        totalIn += d.input_tokens;
        totalOut += d.output_tokens;
        totalReqs += d.requests;

        let label;
        if (key === today) label = `Today (${key})`;
        else if (key === yesterday) label = 'Yesterday';
        else label = key;

        const highlight = key === today ? ANSI.bold : '';
        process.stdout.write(`  ${highlight}${label.padEnd(28)}${ANSI.green}${fmt(d.input_tokens).padStart(10)}${ANSI.reset}    ${ANSI.yellow}${fmt(d.output_tokens).padStart(10)}${ANSI.reset}   (${d.requests})${ANSI.reset}\n`);
      }

      if (sortedKeys.length > 1) {
        const cols = process.stdout.columns || 70;
        process.stdout.write(`  ${ANSI.gray}${'─'.repeat(Math.min(cols - 4, 66))}${ANSI.reset}\n`);
        const totalLabel = `Total (${sortedKeys.length}d)`;
        process.stdout.write(`  ${ANSI.bold}${totalLabel.padEnd(28)}${ANSI.reset}${ANSI.green}${fmt(totalIn).padStart(10)}${ANSI.reset}    ${ANSI.yellow}${fmt(totalOut).padStart(10)}${ANSI.reset}   (${totalReqs})\n`);
      }
    }
  },

  renderLog() {
    if (!this.isTTY) return;
    process.stdout.write(`\n  ${ANSI.bold}RECENT ACTIVITY${ANSI.reset}\n`);
    if (this.recentLogs.length === 0) {
      process.stdout.write(`  ${ANSI.gray}No requests yet${ANSI.reset}\n`);
    } else {
      for (const entry of this.recentLogs) {
        process.stdout.write(`  ${entry}\n`);
      }
    }
  },

  logRequest(reqNum, method, url, statusCode, inputTokens, outputTokens, modelTag) {
    const ts = new Date().toISOString().substring(11, 19);
    const inRaw = inputTokens > 0 ? `\u2191${fmt(inputTokens)}` : '';
    const outRaw = outputTokens > 0 ? `\u2193${fmt(outputTokens)}` : '';
    // Fixed-width columns so entries align even when input is 0
    const inStr = `${ANSI.green}${inRaw.padStart(8)}${ANSI.reset}`;
    const outStr = `${ANSI.yellow}${outRaw.padStart(8)}${ANSI.reset}`;
    const statusColor = statusCode < 400 ? ANSI.green : ANSI.red;
    const tag = modelTag || '?';

    const entry = `${ANSI.bold}${tag}${ANSI.reset} [${ts}] #${reqNum} ${method} ${url} ${statusColor}${statusCode}${ANSI.reset} ${inStr} ${outStr}`;

    this.recentLogs.unshift(entry);
    if (this.recentLogs.length > 10) this.recentLogs.pop();

    if (inputTokens > 0 || outputTokens > 0) {
      recordUsage(inputTokens, outputTokens);
    }

    if (this.isTTY) {
      this.render();
    } else {
      const inPlain = inputTokens > 0 ? `^${inputTokens}` : '';
      const outPlain = outputTokens > 0 ? `v${outputTokens}` : '';
      const plainText = `${tag} [${ts}] #${reqNum} ${method} ${url} ${statusCode} ${inPlain.padStart(8)} ${outPlain.padStart(8)}`;
      console.log(plainText);
    }
  },

  logError(reqNum, method, url, message) {
    const ts = new Date().toISOString().substring(11, 19);
    const entry = `[${ts}] #${reqNum} ${method} ${url} ${ANSI.red}ERR: ${message}${ANSI.reset}`;
    this.recentLogs.unshift(entry);
    if (this.recentLogs.length > 10) this.recentLogs.pop();

    if (this.isTTY) {
      this.render();
    } else {
      console.error(`[${ts}] #${reqNum} ERR: ${message}`);
    }
  },

  updateRateLimit(upRes) {
    const h = upRes.headers;
    const fiveHUtil = parseFloat(h['anthropic-ratelimit-unified-5h-utilization']);
    const sevenDUtil = parseFloat(h['anthropic-ratelimit-unified-7d-utilization']);
    const fiveHReset = parseInt(h['anthropic-ratelimit-unified-5h-reset']) || 0;
    const sevenDReset = parseInt(h['anthropic-ratelimit-unified-7d-reset']) || 0;
    if (!isNaN(fiveHUtil) || !isNaN(sevenDUtil)) {
      this.lastRateLimit = {
        fiveH: isNaN(fiveHUtil) ? null : { util: fiveHUtil, reset: fiveHReset },
        sevenD: isNaN(sevenDUtil) ? null : { util: sevenDUtil, reset: sevenDReset },
      };
    }
  },

  shutdown() {
    if (this.isTTY) {
      process.stdout.write(ANSI.show);
      if (this._uptimeInterval) clearInterval(this._uptimeInterval);
    }
    if (saveTimer) clearTimeout(saveTimer);
    saveUsageData();
  }
};

// ─── Server ─────────────────────────────────────────────────────────────────
const MAX_BODY_SIZE = 10 * 1024 * 1024; // 10 MB
let serverRefreshInterval = null;

function startServer(config) {
  let requestCount = 0;

  const server = http.createServer((req, res) => {
    if (req.url === '/health' && req.method === 'GET') {
      try {
        const oauth = getToken(config.credsPath);
        const expiresIn = (oauth.expiresAt - Date.now()) / 3600000;
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          status: expiresIn > 0 ? 'ok' : 'token_expired',
          proxy: 'claude-proxy',
          version: VERSION,
          requestsServed: requestCount,
          uptime: Math.floor((Date.now() - dashboard.startedAt) / 1000) + 's',
          tokenExpiresInHours: expiresIn.toFixed(1),
          subscriptionType: oauth.subscriptionType,
          replacementPatterns: config.replacements.length,
          reverseMapPatterns: config.reverseMap.length,
          ccEmulation: {
            ccVersion: CC_VERSION,
            deviceId: DEVICE_ID.slice(0, 8) + '...',
            sessionId: SESSION_ID.slice(0, 8) + '...',
            headerOrdering: true,
            bodyFieldOrdering: true,
            sessionRotation: true,
            interRequestPacing: `${PACING_MIN_GAP_MS}+${PACING_JITTER_MS}ms`
          },
          layers: {
            stringReplacements: config.replacements.length,
            toolNameRenames: config.toolRenames.length,
            propertyRenames: config.propRenames.length,
            ccToolStubs: config.injectCCStubs ? CC_TOOL_STUBS.length : 0,
            systemStripEnabled: config.stripSystemConfig,
            descriptionStripEnabled: config.stripToolDescriptions
          }
        }));
      } catch (e) {
        console.error('[PROXY] Health check error:', e.message);
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ status: 'error', message: 'Internal server error' }));
      }
      return;
    }

    requestCount++;
    const reqNum = requestCount;
    const chunks = [];
    let bodySize = 0;

    req.on('data', c => {
      bodySize += c.length;
      if (bodySize > MAX_BODY_SIZE) {
        req.destroy();
        res.writeHead(413, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ type: 'error', error: { message: 'Request body too large (max 10MB)' } }));
        return;
      }
      chunks.push(c);
    });
    req.on('end', () => {
      let body = Buffer.concat(chunks);

      let oauth;
      try {
        oauth = getToken(config.credsPath);
      } catch (e) {
        console.error('[PROXY] Token error:', e.message);
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ type: 'error', error: { message: 'Failed to load credentials' } }));
        return;
      }

      // Process body: sanitize triggers + inject billing header
      let bodyStr = body.toString('utf8');
      // Extract model before processBody transforms it (for beta selection)
      const betaModelMatch = bodyStr.match(/"model"\s*:\s*"([^"]+)"/);
      const requestModel = betaModelMatch ? betaModelMatch[1] : '';
      bodyStr = processBody(bodyStr, config);
      body = Buffer.from(bodyStr, 'utf8');

      // Build upstream headers
      const headers = {};
      for (const [key, value] of Object.entries(req.headers)) {
        const lk = key.toLowerCase();
        if (lk === 'host' || lk === 'connection') continue;
        if (lk === 'authorization' || lk === 'x-api-key') continue;
        if (lk === 'content-length') continue;
        headers[key] = value;
      }

      // [dario] Layer 9: Rotate session ID on idle gaps (matches CC behavior)
      const currentSessionId = getOrRotateSessionId();

      // [dario] Layer 8: Stainless SDK headers (Claude Code request signature)
      // Header values updated to match CC v2.1.114 captured by dario v3.30
      headers['accept'] = 'application/json';
      headers['content-type'] = 'application/json';
      headers['authorization'] = `Bearer ${oauth.accessToken}`;
      headers['content-length'] = body.length;

      // Anthropic API version (required, matches real CC)
      headers['anthropic-version'] = '2023-06-01';

      // Merge required betas — model-aware (Haiku/non-4.6 get filtered set)
      const modelBetas = getModelBetas(requestModel);
      const existingBeta = headers['anthropic-beta'] || '';
      const betas = existingBeta ? existingBeta.split(',').map(b => b.trim()) : [];
      for (const b of modelBetas) {
        if (!betas.includes(b)) betas.push(b);
      }
      // [dario] Layer 12: Filter billable betas that require Extra Usage
      headers['anthropic-beta'] = filterBillableBetas(betas.join(','));

      headers['user-agent'] = buildUserAgent();
      headers['x-app'] = 'cli';
      headers['x-claude-code-session-id'] = currentSessionId;
      headers['x-stainless-arch'] = getStainlessArch();
      headers['x-stainless-lang'] = 'js';
      headers['x-stainless-os'] = getStainlessOs();
      // [dario] Stainless SDK version updated to match CC v2.1.114
      headers['x-stainless-package-version'] = '0.81.0';
      headers['x-stainless-runtime'] = 'node';
      // [dario] CC runs on Bun which reports v24.3.0 as Node compat version
      headers['x-stainless-runtime-version'] = 'v24.3.0';
      headers['x-stainless-retry-count'] = '0';
      headers['x-stainless-timeout'] = '600';
      headers['anthropic-dangerous-direct-browser-access'] = 'true';

      // Strip headers not sent by real Claude Code
      delete headers['x-session-affinity'];
      delete headers['accept-encoding'];

      // Extract model shortcode from request body
      let modelTag = '?';
      const modelMatch = bodyStr.match(/"model"\s*:\s*"([^"]+)"/);
      if (modelMatch) {
        const m = modelMatch[1].toLowerCase();
        if (m.includes('opus')) modelTag = 'O';
        else if (m.includes('sonnet')) modelTag = 'S';
        else if (m.includes('haiku')) modelTag = 'H';
      }

      // Layer 8: URL transform — normalize path and append ?beta=true
      let upstreamPath = req.url;
      try {
        const url = new URL(req.url, `https://${UPSTREAM_HOST}`);
        const p = url.pathname;
        const isMessages = p === '/v1/messages' || p === '/messages' || p === '/v1/messages/count_tokens' || p === '/messages/count_tokens';
        if (isMessages && !url.searchParams.has('beta')) {
          if (!p.startsWith('/v1/')) {
            url.pathname = '/v1' + p;
          }
          url.searchParams.set('beta', 'true');
          upstreamPath = url.pathname + url.search;
        }
      } catch (e) {
        // Keep original path on parse error
      }

      // [dario] Layer 13: Reorder headers to match CC's exact wire order
      const orderedHeaders = orderHeadersForOutbound(headers);

      // [dario] Layer 10: Inter-request pacing (avoid machine-speed patterns)
      const pacingDelay = computePacingDelay();
      const sendUpstream = () => {
        lastRequestTime = Date.now();

      const upstream = https.request({
        hostname: UPSTREAM_HOST, port: 443,
        path: upstreamPath, method: req.method, headers: orderedHeaders
      }, (upRes) => {
        // Capture rate-limit headers from every response
        dashboard.updateRateLimit(upRes);

        // For SSE streaming responses, extract tokens + reverse-map each chunk
        if (upRes.headers['content-type'] && upRes.headers['content-type'].includes('text/event-stream')) {
          const sseHeaders = { ...upRes.headers };
          delete sseHeaders['content-length'];      // SSE is streamed, no fixed length
          delete sseHeaders['transfer-encoding'];   // avoid header conflicts
          res.writeHead(upRes.statusCode, sseHeaders);
          const tracker = createSSETokenTracker();
          const reverser = createStreamReverser(config);
          // StringDecoder buffers incomplete UTF-8 sequences across TCP chunks.
          // chunk.toString() would emit U+FFFD whenever a multi-byte char (emoji,
          // CJK, etc.) lands on a chunk boundary.
          const decoder = new StringDecoder('utf8');
          let ssePending = ''; // buffer for splitting SSE events
          upRes.on('data', (chunk) => {
            const raw = decoder.write(chunk);
            tracker.push(raw);

            // Split into complete SSE events to detect thinking blocks
            ssePending += raw;
            const events = ssePending.split('\n\n');
            ssePending = events.pop(); // last element may be incomplete

            for (const evt of events) {
              const evtWithDelim = evt + '\n\n';
              if (isThinkingSSEEvent(evt)) {
                // Pass thinking events through unchanged — no reverse mapping
                reverser.write(''); // keep reverser in sync (empty input)
                res.write(evtWithDelim);
              } else {
                const out = reverser.write(evtWithDelim);
                if (out) res.write(out);
              }
            }
          });
          upRes.on('end', () => {
            // Flush any remaining bytes from StringDecoder
            const decoderRemainder = decoder.end();
            if (decoderRemainder) ssePending += decoderRemainder;
            // Flush any remaining partial event
            if (ssePending) {
              if (isThinkingSSEEvent(ssePending)) {
                res.write(ssePending);
              } else {
                const out = reverser.write(ssePending);
                if (out) res.write(out);
              }
            }
            const tail = reverser.flush();
            if (tail) res.write(tail);
            dashboard.logRequest(reqNum, req.method, req.url, upRes.statusCode, tracker.inputTokens, tracker.outputTokens, modelTag);
            res.end();
          });
        }
        // For JSON responses (errors, non-streaming), extract tokens + buffer and reverse-map
        // For JSON responses (errors, non-streaming), extract tokens + buffer and reverse-map.
        // Some upstream proxies (e.g. CLIProxyAPI with nonstream-keepalive-interval)
        // inject blank-line heartbeat bytes during long-running inference so clients
        // don't time out. We forward leading ASCII whitespace immediately to keep
        // the client alive, then buffer actual JSON content for reverseMap.
        // See: https://github.com/zacdcook/openclaw-billing-proxy/pull/40
        else {
          let seenRealContent = false;
          let headersWritten = false;
          const respChunks = [];
          const ensureHeaders = () => {
            if (headersWritten) return;
            const nh = { ...upRes.headers };
            delete nh['content-length'];
            delete nh['transfer-encoding'];
            try { res.writeHead(status, nh); headersWritten = true; } catch (e) {}
          };
          upRes.on('data', (c) => {
            if (!seenRealContent) {
              // Forward leading whitespace bytes (heartbeat keepalives) immediately
              let i = 0;
              while (i < c.length) {
                const b = c[i];
                if (b === 0x20 || b === 0x09 || b === 0x0a || b === 0x0d) { i++; }
                else { break; }
              }
              if (i > 0) {
                ensureHeaders();
                try { res.write(c.subarray(0, i)); } catch (e) {}
              }
              if (i < c.length) {
                seenRealContent = true;
                respChunks.push(c.subarray(i));
              }
            } else {
              respChunks.push(c);
            }
          });
          upRes.on('end', () => {
            ensureHeaders();
            let respBody = Buffer.concat(respChunks).toString();

            // Extract token usage before reverse mapping
            let inputTokens = 0, outputTokens = 0;
            try {
              const parsed = JSON.parse(respBody);
              if (parsed.usage) {
                inputTokens = parsed.usage.input_tokens || 0;
                outputTokens = parsed.usage.output_tokens || 0;
              }
              if (parsed.error) {
                console.error(`[DEBUG] #${reqNum} Error: ${parsed.error.type}: ${parsed.error.message}`);
              }
            } catch (e) { /* non-JSON or error response */ }

            // Preserve thinking blocks in non-streaming responses
            let respThinkingStore = [];
            if (hasThinkingEnabled(bodyStr)) {
              const masked = maskThinkingBlocks(respBody);
              respBody = masked.masked;
              respThinkingStore = masked.store;
            }
            respBody = reverseMap(respBody, config);
            if (respThinkingStore.length > 0) {
              respBody = unmaskThinkingBlocks(respBody, respThinkingStore);
            }
            try { res.write(respBody); res.end(); } catch (e) {}

            dashboard.logRequest(reqNum, req.method, req.url, upRes.statusCode, inputTokens, outputTokens, modelTag);
          });
        }
      });

      upstream.on('error', (e) => {
        dashboard.logError(reqNum, req.method, req.url, e.message);
        if (!res.headersSent) {
          res.writeHead(502, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ type: 'error', error: { message: 'Upstream connection failed' } }));
        }
      });

      upstream.write(body);
      upstream.end();
      }; // end sendUpstream

      // [dario] Layer 10: Apply pacing delay before sending
      if (pacingDelay > 0) {
        sleep(pacingDelay).then(sendUpstream);
      } else {
        sendUpstream();
      }
    });
  });

  const bindHost = process.env.PROXY_HOST || '127.0.0.1';
  server.listen(config.port, bindHost, () => {
    if (process.platform === 'darwin') {
      if (!readKeychainToken()) {
        console.error('[PROXY] WARNING: macOS Keychain not readable. Automatic token refresh disabled.');
        console.error('[PROXY]   If prompted by macOS, choose "Always Allow" for "security" to access "Claude Code-credentials".');
        console.error('[PROXY]   You can pre-authorize by running: security find-generic-password -s "Claude Code-credentials" -w');
      } else {
        const result = proactiveKeychainSync(config.credsPath);
        if (result.updated) {
          const h = ((result.newExpiresAt - Date.now()) / 3600000).toFixed(1);
          console.log(`[PROXY] Keychain sync: refreshed token from Keychain (${h}h remaining).`);
        }
      }
      // Periodic proactive refresh — picks up Claude Code's background token
      // refreshes before the file token expires.
      serverRefreshInterval = setInterval(() => {
        try {
          const r = proactiveKeychainSync(config.credsPath);
          // Only log when stdout isn't owned by the dashboard renderer,
          // otherwise the line corrupts the in-place TTY output.
          if (r.updated && !dashboard.isTTY) {
            const h = ((r.newExpiresAt - Date.now()) / 3600000).toFixed(1);
            console.log(`[PROXY] Token auto-refreshed from Keychain (${h}h remaining)`);
          }
        } catch(e) { /* silent */ }
      }, 5 * 60 * 1000);
      serverRefreshInterval.unref();
    }

    try {
      const oauth = getToken(config.credsPath);
      dashboard.init(config, oauth);
    } catch (e) {
      console.error(`  Started on port ${config.port} but credentials error: ${e.message}`);
    }

    // Periodic credential refresh via Claude CLI + Keychain re-extraction.
    // Schedules next check based on actual expiry time, retries quickly
    // if refresh was a no-op. See: PR #32
    if (config.refreshEnabled && config.credsPath !== 'env') {
      const thresholdMin = (config.refreshThresholdMs / 60000).toFixed(0);
      const retrySec = (config.refreshRetryMs / 1000).toFixed(0);
      console.log(`  Token refresh:     when <${thresholdMin}m remaining (retry ${retrySec}s on no-op)`);
      const computeNextDelay = () => {
        try {
          const oauth = getToken(config.credsPath);
          const untilCheck = oauth.expiresAt - Date.now() - config.refreshThresholdMs;
          return Math.max(untilCheck, 0);
        } catch(e) {
          return config.refreshRetryMs;
        }
      };
      const scheduleNext = (delay) => setTimeout(() => {
        const result = maybeRefreshCredentials(config);
        scheduleNext(result === 'retry' ? config.refreshRetryMs : computeNextDelay());
      }, delay).unref();
      scheduleNext(computeNextDelay());
    }
  });

  for (const sig of ['SIGINT', 'SIGTERM']) {
    process.on(sig, () => {
      if (serverRefreshInterval) clearInterval(serverRefreshInterval);
      dashboard.shutdown();
      process.exit(0);
    });
  }
}

// ─── Main ───────────────────────────────────────────────────────────────────
if (require.main === module) {
  const config = loadConfig();
  startServer(config);
}

// Export internals for testing
module.exports = {
  createSSETokenTracker,
  extractTokensFromSSE,
  processBody,
  reverseMap,
  createStreamReverser,
  maxPatternLen,
  readKeychainToken,
  refreshFromKeychain,
  proactiveKeychainSync,
  getToken,
  loadUsageData,
  saveUsageData,
  recordUsage,
  dashboard,
  fmt,
  USAGE_FILE,
  CC_VERSION,
  BILLING_HASH_SALT,
  BILLING_HASH_INDICES,
  DEVICE_ID,
  SESSION_ID,
  CLAUDE_CODE_IDENTITY_STRING,
  computeBillingFingerprint,
  buildBillingBlock,
  extractFirstUserMessageText,
  buildUserAgent,
  REQUIRED_BETAS,
  DEFAULT_REPLACEMENTS,
  DEFAULT_REVERSE_MAP,
  DEFAULT_TOOL_RENAMES,
  DEFAULT_PROP_RENAMES,
  CC_TOOL_STUBS,
  VERSION,
  findMatchingBracket,
  maskThinkingBlocks,
  unmaskThinkingBlocks,
  hasThinkingEnabled,
  isThinkingSSEEvent,
  refreshCredentials,
  maybeRefreshCredentials,
  DEFAULT_REFRESH_THRESHOLD_MINUTES,
  DEFAULT_REFRESH_RETRY_SECONDS,
  CLAUDE_CLI_REFRESH_TIMEOUT_MS,
  _usageData: () => usageData,
  _resetUsageData: () => { usageData = { version: 1, days: {} }; },
  // v2.4.0 exports (dario ports)
  getOrRotateSessionId,
  computePacingDelay,
  orderHeadersForOutbound,
  orderBodyForOutbound,
  stripOrchestrationTags,
  sanitizeMessageOrchestration,
  filterBillableBetas,
  computeCch,
  CC_HEADER_ORDER,
  CC_BODY_FIELD_ORDER,
  ORCHESTRATION_TAG_NAMES,
  PACING_MIN_GAP_MS,
  PACING_JITTER_MS,
  SESSION_ROTATION_IDLE_MS,
  SESSION_ROTATION_JITTER_MS,
};
