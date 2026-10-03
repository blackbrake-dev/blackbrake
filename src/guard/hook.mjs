#!/usr/bin/env node
// Entry point an agent runs for each hook event: `node hook.mjs <Event> [--harness <id>]` with the
// event JSON on stdin. Answers in that agent's format (stdout, and exit code 2 where the agent uses it
// to block). Uncheckable tool calls are refused: even observe must enforce the tamper check.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { detectLang, setLang, t } from '../i18n.mjs';
import { loadRules } from '../secrets/engine.mjs';
import { ADAPTERS, asShell, renderError } from './harnesses.mjs';
import { decide, isSensitivePath, linkedPlaces, loginItemFile, protectedTarget, shellViews, withinBudget } from './policy.mjs';
import { isLocalPath, localFileStat } from '../text.mjs';
import { isPaused } from './pause.mjs';
import { declareProgram } from './safety.mjs';
import { appendLog, getMode, getSavedLang, getSession, setSession, trustedHome } from './state.mjs';
import { maybeOpenWindow } from './window.mjs';

const MAX_INPUT = 32 * 1024 * 1024;

class TooLarge extends Error {
  constructor(raw) {
    super('hook input too large');
    this.raw = raw;
  }
}

function readStdin() {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;

    const timer = setTimeout(() => {
      process.stdin.destroy();
      reject(new Error('Hook input deadline'));
    }, 5000);

    process.stdin.on('data', (chunk) => {
      size += chunk.length;

      // Keep memory bounded, but drain the pipe so a large sender does not get a broken pipe.
      if (size <= MAX_INPUT) chunks.push(chunk);
      else chunks.length = 0;
    });
    process.stdin.once('end', () => {
      clearTimeout(timer);

      // Cursor on Windows starts the JSON with a byte order mark (seen in a real session, 2026-10-01).
      if (size > MAX_INPUT) reject(new TooLarge(''));
      else resolve(Buffer.concat(chunks).toString('utf8').replace(/^﻿/, ''));
    });
    process.stdin.once('error', (e) => { clearTimeout(timer); reject(e); });
  });
}

function argValue(name) {
  const i = process.argv.indexOf(name);

  return i > 0 ? process.argv[i + 1] : null;
}

function emit({ stdout = '', stderr = '', code = 0 }) {
  if (stdout) process.stdout.write(stdout);

  if (stderr) process.stderr.write(stderr);
  process.exitCode = code;
}

// A file's real path (following links and long-naming short names), or of its folder when the file
// does not exist yet. Local paths only; null when nothing resolves.
function realPathOf(file, depth = 0) {
  if (!isLocalPath(file) || depth > 16) return null;
  const absolute = path.resolve(file);
  const root = path.parse(absolute).root;
  const parts = absolute.slice(root.length).split(path.sep).filter(Boolean);
  let current = root;

  for (let i = 0; i < parts.length; i++) {
    current = path.join(current, parts[i]);
    let st;

    try { st = fs.lstatSync(current); } catch (e) {
      if (e.code !== 'ENOENT') return null;

      try { return path.join(fs.realpathSync.native(path.dirname(current)), ...parts.slice(i)); } catch { return null; }
    }

    // Inspect links before realpath: following a remote link on Windows can send NTLM credentials.
    if (st.isSymbolicLink()) {
      const target = fs.readlinkSync(current);

      if (!isLocalPath(target)) return null;

      return realPathOf(path.resolve(path.dirname(current), target, ...parts.slice(i + 1)), depth + 1);
    }
  }

  try { return fs.realpathSync.native(absolute); } catch { return null; }
}

const GLOB = /[*?[]/;

// [Environment]::GetFolderPath('Startup' | [Environment+SpecialFolder]::Startup | 7), any casing.
const STARTUP_LOOKUP = /\[(?:System\.)?Environment\]::GetFolderPath\(\s*(?:(["'])Startup\1|\[(?:System\.)?Environment\+SpecialFolder\]::Startup|7)\s*\)/gi;

// POSIX named classes inside a bracket expression ([[:alpha:]]), as bash reads them in globs.
const POSIX_CLASSES = {
  alpha: /\p{L}/u, digit: /[0-9]/, alnum: /[\p{L}0-9]/u, upper: /\p{Lu}/u, lower: /\p{Ll}/u,
  space: /\s/, blank: /[ \t]/, punct: /[!-/:-@[-`{-~]/, xdigit: /[0-9a-f]/i, word: /[\p{L}0-9_]/u,
  // oxlint-disable-next-line no-control-regex -- The cntrl class is exactly the control characters.
  cntrl: /[\x00-\x1f\x7f]/, print: /[^\x00-\x1f\x7f]/, graph: /[^\x00-\x20\x7f]/,
};

// One bracket expression starting at part[i] ('['): a character test and where it ends, or null
// when there is no closing ']' (then '[' is literal). An unknown [:class:], or the rare [=x=] and
// [.x.] forms, throw: refused rather than read as a narrower set than the shell uses.
function bracket(part, i) {
  let j = i + 1;
  const negate = part[j] === '!' || part[j] === '^';

  if (negate) j++;
  const tests = [];

  for (let first = true; j < part.length; first = false) {
    if (part[j] === ']' && !first) return { end: j, test: (c) => negate !== tests.some((f) => f(c)) };

    if (part[j] === '[' && /[:=.]/.test(part[j + 1] ?? '')) {
      const close = part.indexOf(`${part[j + 1]}]`, j + 2);
      const name = close > 0 ? part.slice(j + 2, close) : '';

      if (part[j + 1] !== ':' || !Object.hasOwn(POSIX_CLASSES, name)) throw new RangeError('Unsupported glob class');
      const re = POSIX_CLASSES[name];
      tests.push((c) => re.test(c));
      j = close + 2;
    } else if (part[j + 1] === '-' && part[j + 2] && part[j + 2] !== ']') {
      const [from, to] = [part[j], part[j + 2]];
      tests.push((c) => c >= from && c <= to);
      j += 3;
    } else {
      const x = part[j];
      tests.push((c) => c === x);
      j++;
    }
  }

  return null;
}

// One path segment of a shell glob as tokens: '*', '?', a [class] test, or a literal character.
function globTokens(part) {
  const tokens = [];

  for (let i = 0; i < part.length; i++) {
    const b = part[i] === '[' ? bracket(part, i) : null;

    if (part[i] === '*' || part[i] === '?') tokens.push(part[i]);
    else if (b) {
      tokens.push(b.test);
      i = b.end;
    } else tokens.push(part[i]);
  }

  return tokens;
}

// Wildcard matching with a single backtrack point: linear in practice, no regex to blow up.
function globMatch(tokens, name) {
  const fold = process.platform === 'win32' ? (s) => s.toLowerCase() : (s) => s;
  // oxlint-disable-next-line anti-slop/no-runtime-typeof -- Tokens are either literal characters or class predicates.
  const one = (tok, c) => tok === '?' || (typeof tok === 'function' ? tok(c) || tok(fold(c)) : fold(tok) === fold(c));
  let t = 0;
  let n = 0;
  let star = -1;
  let mark = 0;

  while (n < name.length) {
    if (t < tokens.length && tokens[t] !== '*' && one(tokens[t], name[n])) { t++; n++; }
    else if (tokens[t] === '*') { star = t++; mark = n; }
    else if (star >= 0) { t = star + 1; n = ++mark; }
    else return false;
  }

  while (tokens[t] === '*') t++;

  return t === tokens.length;
}

// What a shell glob (settings.jso[n], ~/.cl*/s*.json, .en?) expands to on this disk, so the files it
// names are checked like any other. Linked folders are read only once resolved to a local path.
// `hidden` marks a dot name matched by a pattern without the dot, which bash leaves out but
// PowerShell and cmd include. Past its budget it throws (refused like any input too large to
// check): silently skipping would let padding hide the glob that matters.
function expandGlob(pattern, budget) {
  const root = path.parse(pattern).root;
  let found = [{ file: root, hidden: false }];

  for (const part of pattern.slice(root.length).split(/[\\/]+/).filter(Boolean)) {
    if (!GLOB.test(part)) {
      found = found.map((m) => ({ ...m, file: path.join(m.file, part) }));
      continue;
    }

    const tokens = globTokens(part);
    const next = [];

    for (const m of found) {
      const dir = realPathOf(m.file);

      if (!dir) continue;
      let names = [];

      try { names = fs.readdirSync(dir); } catch { continue; }

      budget.reads -= 1;
      budget.names -= names.length;

      if (budget.reads < 0 || budget.names < 0) throw new RangeError('Too many paths to inspect');

      for (const name of names) {
        if (globMatch(tokens, name)) next.push({ file: path.join(m.file, name), hidden: m.hidden || (name.startsWith('.') && !part.startsWith('.')) });
      }
    }

    found = next;
  }

  return found.filter((m) => m.file !== root);
}

async function main() {
  // This is the blackbrake program: it may change its own folder (src/guard/safety.mjs).
  declareProgram();
  let native = process.argv[2];
  const harness = Object.hasOwn(ADAPTERS, argValue('--harness')) ? argValue('--harness') : 'claude';
  const adapter = ADAPTERS[harness];
  // An installed copy ignores a BLACKBRAKE_HOME the agent's environment points elsewhere.
  const home = trustedHome(import.meta.url);
  process.env.BLACKBRAKE_HOME = home;
  let mode = 'observe';

  try {
    mode = getMode(home);
    setLang(detectLang({ saved: getSavedLang(home) }));
    const raw = JSON.parse(await readStdin() || '{}');

    // oxlint-disable-next-line anti-slop/no-runtime-typeof -- Validate untrusted JSON or assert the boundary contract; preserve primitive type checks.
    if (!raw || typeof raw !== 'object' || Array.isArray(raw)) throw new TypeError('Invalid hook input');
    const nativeEvent = native || raw.hook_event_name || raw.agent_action_name;
    native = nativeEvent;
    const canonical = Object.hasOwn(adapter.events, nativeEvent) ? adapter.events[nativeEvent] : null;

    if (!canonical) throw new TypeError('Unknown hook event');

    // Paused by the user ("blackbrake pause"): a neutral answer in the agent's own format, nothing
    // analysed, blocked or recorded beyond one "paused" line per session. SessionStart says so.
    // Paused by the user ("blackbrake pause"): a neutral answer in the agent's own format, nothing
    // analysed, blocked or recorded beyond one "paused" line per session. SessionStart says so.
    // A tool call is still checked for tampering with blackbrake itself (review A, 2026-10-01): the
    // pause stops the secret and spend checks, it does not let an agent rewrite or remove guard.
    const paused = isPaused(home);
    const pausedId = raw.session_id ?? raw.conversation_id ?? raw.trajectory_id ?? raw.sessionId ?? null;

    const neutral = () => {
      try {
        if (!getSession(pausedId, home).paused) {
          setSession(pausedId, { paused: new Date().toISOString() }, home);
          appendLog([{ ev: canonical, kind: 'session', action: 'paused', harness, mode }], pausedId, home);
        }
      } catch { /* the answer stays neutral */ }

      const note = canonical === 'SessionStart' ? { systemMessage: t('blackbrake is PAUSED: only attempts to switch it off are checked; secrets and spend are not. Resume it in your terminal with "blackbrake resume".') } : null;
      emit(adapter.render(canonical, note, { native: nativeEvent, input: {} }));
    };

    if (paused && canonical !== 'PreToolUse') {
      neutral();

      return;
    }

    if (adapter.skip?.(nativeEvent, raw)) {
      emit(adapter.render(canonical, null, { native: nativeEvent, input: {} }));

      return;
    }

    const normalized = adapter.normalize(canonical, raw, nativeEvent);
    const event = normalized.event;
    const input = event === 'PreToolUse' ? asShell(normalized.input) : normalized.input;

    if (!withinBudget(input)) throw new RangeError('Hook analysis limit');

    // oxlint-disable-next-line anti-slop/no-runtime-typeof -- Validate untrusted JSON or assert the boundary contract; preserve primitive type checks.
    if (event === 'PreToolUse' && (typeof input.tool_name !== 'string' || !input.tool_name || !input.tool_input || typeof input.tool_input !== 'object' || Array.isArray(input.tool_input))) throw new TypeError('Invalid tool input');

    // oxlint-disable-next-line anti-slop/no-runtime-typeof -- Validate untrusted JSON or assert the boundary contract; preserve primitive type checks.
    if (event === 'PreToolUse' && /^(Bash|PowerShell)$/.test(input.tool_name) && (typeof input.tool_input.command !== 'string' || !input.tool_input.command.trim())) throw new TypeError('Missing command');

    // oxlint-disable-next-line anti-slop/no-runtime-typeof -- Validate untrusted JSON or assert the boundary contract; preserve primitive type checks.
    if (event === 'UserPromptSubmit' && typeof input.prompt !== 'string') throw new TypeError('Invalid prompt input');
    const session = getSession(input.session_id, home);

    if (event === 'PostCompact') {
      try { setSession(input.session_id, { compactedAt: new Date().toISOString() }, home); } catch { /* reporting must not discard a decision */ }
    }

    let rules = null;
    let realDirs = null;

    const claudeDir = process.env.CLAUDE_CONFIG_DIR && path.isAbsolute(process.env.CLAUDE_CONFIG_DIR) ? process.env.CLAUDE_CONFIG_DIR : '';

    const ctx = {
      mode,
      canBlockPrompt: harness !== 'copilot',
      canRedact: harness !== 'devin' && harness !== 'windsurf' && (harness !== 'cursor' || /^(mcp__|MCP)/i.test(input.tool_name ?? '')),
      home: os.homedir(),
      guardDir: home,
      claudeDir,
      platform: process.platform,
      appData: process.env.APPDATA ?? '',
      xdgConfigHome: process.env.XDG_CONFIG_HOME ?? '',
      agentDirs: Object.fromEntries([
        [process.env.CODEX_HOME, 'codex'],
        [process.env.COPILOT_HOME, 'copilot'],
        [process.env.XDG_CONFIG_HOME ? path.join(process.env.XDG_CONFIG_HOME, 'devin') : '', 'devin'],
      ].filter(([dir]) => dir && path.isAbsolute(dir) && isLocalPath(dir))),
      compactedAt: session.compactedAt ?? null,
      // The same folders by their real paths, which is how globs and links resolve a target.
      get canonical() {
        const real = (dir) => (dir && realPathOf(dir)) || dir;

        // Only a place that is itself a link is resolved (one lstat each); links above home are
        // covered by the real folders here. Local absolute paths only (a UNC lstat sends NTLM).
        const linkTarget = (p) => {
          try { return isLocalPath(p) && path.isAbsolute(p) && fs.lstatSync(p).isSymbolicLink() ? realPathOf(p) : null; } catch { return null; }
        };

        realDirs ??= {
          home: real(this.home), guardDir: real(this.guardDir), claudeDir: real(this.claudeDir), platform: this.platform,
          appData: real(this.appData), xdgConfigHome: real(this.xdgConfigHome),
          agentDirs: Object.fromEntries(Object.entries(this.agentDirs).map(([dir, name]) => [real(dir), name])),
          links: linkedPlaces(this, linkTarget),
        };

        return realDirs;
      },
      get rules() {
        rules ??= loadRules();

        return rules;
      },
    };

    // The real path of each file a tool is about to write: a Windows short name (ALUCE~1\.BLACKB~1)
    // or a link names a protected file without spelling it. Checked alongside the given path.
    const ti = input.tool_input;

    // oxlint-disable-next-line anti-slop/no-runtime-typeof -- Validate untrusted JSON or assert the boundary contract; preserve primitive type checks.
    if (event === 'PreToolUse' && ti && typeof ti === 'object') {
      // oxlint-disable-next-line anti-slop/no-runtime-typeof -- Validate untrusted JSON or assert the boundary contract; preserve primitive type checks.
      const cwd = [ti.workdir, raw.cwd, process.cwd()].find((v) => typeof v === 'string' && path.isAbsolute(v) && isLocalPath(v));

      const envValue = (name) => (/^home$/i.test(name) ? os.homedir() : process.env[name] ?? '');

      const expand = (s) => String(s)
        // ${VAR:-default}, ${VAR-default}, ${VAR:=default}: the shell uses the value when set, the fallback otherwise.
        .replace(/\$\{(HOME|XDG_CONFIG_HOME|APPDATA)(?::?[-=])([^{}]*)\}/g, (_, name, fallback) => envValue(name) || fallback)
        .replace(/\$\{APPDATA\}|\$APPDATA\b/g, (m) => process.env.APPDATA ?? m)
        .replace(/^~(?=[\\/]|$)|\$\{HOME\}|\$HOME\b|\$env:USERPROFILE\b|%USERPROFILE%/gi, os.homedir())
        .replace(/\$\{XDG_CONFIG_HOME\}|\$XDG_CONFIG_HOME\b/gi, process.env.XDG_CONFIG_HOME ?? '$XDG_CONFIG_HOME')
        .replace(/\$env:APPDATA\b|%APPDATA%/gi, process.env.APPDATA ?? '%APPDATA%');

      const files = [ti.file_path, ti.path, ti.notebook_path, ...(Array.isArray(ti.files) ? ti.files : [])];

      if (/^(Bash|PowerShell)$/.test(input.tool_name) && ti.command.length <= 65536) {
        const words = new Set();

        // PowerShell can ask .NET for the Startup folder instead of spelling it.
        const startup = process.platform === 'win32' ? path.dirname(loginItemFile(ctx)) : '';

        for (const shown of shellViews(ti.command)) {
          const view = startup ? shown.replace(STARTUP_LOOKUP, () => ` "${startup}" `) : shown;

          for (const m of view.matchAll(/"([^"\n]*)"|'([^'\n]*)'|[^\s;&|<>()"'`=,]+/g)) {
            const word = m[1] ?? m[2] ?? m[0];

            if ((/[\\/]|^\./.test(word) || /\.[\w-]+$/.test(word)) && word.length <= 4096 && !word.includes('://')) words.add(word);
          }
        }

        if (words.size > 128) throw new RangeError('Too many paths to inspect');
        files.push(...words);
      }

      if (files.length > 128) throw new RangeError('Too many paths to inspect');
      const resolved = new Set();
      const shell = /^(Bash|PowerShell)$/.test(input.tool_name);
      const budget = { reads: 256, names: 200000 };

      for (const f of files) {
        // oxlint-disable-next-line anti-slop/no-runtime-typeof -- Validate untrusted JSON or assert the boundary contract; preserve primitive type checks.
        if (typeof f !== 'string' || !f) continue;
        const expanded = expand(f);

        if (!isLocalPath(expanded)) continue;
        const absolute = path.resolve(cwd, expanded);
        const real = realPathOf(absolute);

        if (!shell || protectedTarget(absolute, ctx)) resolved.add(absolute);

        if (real && (!shell || protectedTarget(real, ctx) || (isSensitivePath(real) && fs.existsSync(real)))) resolved.add(real);

        // The shell expands globs before the program runs: what they match on disk is checked too.
        if (!shell || !GLOB.test(expanded)) continue;

        for (const m of expandGlob(absolute, budget)) {
          const target = realPathOf(m.file);

          if (protectedTarget(m.file, ctx) || (target && protectedTarget(target, ctx))) resolved.add(target ?? m.file);
          else if (target && (!m.hidden || input.tool_name === 'PowerShell') && isSensitivePath(target)) resolved.add(target);
        }
      }

      if (resolved.size) input.tool_input = { ...ti, files: [...(Array.isArray(ti.files) ? ti.files : []), ...resolved] };
    }

    // A full overwrite of a settings or hook file: what it held before counts as removed, so dropping
    // guard's entry is seen (a small local file; a link is followed only to a local regular file).
    if (event === 'PreToolUse' && input.tool_name === 'Write' && [input.tool_input?.file_path, ...(input.tool_input?.files ?? [])].some((f) => protectedTarget(f, ctx) === 'settings')) {
      // Every existing target is read (a protected one may be reachable only through files[]); one
      // that exists but cannot be read (too large, a link elsewhere) makes the overwrite unverifiable.
      const olds = [];
      const seenFiles = new Set();

      // oxlint-disable-next-line anti-slop/no-runtime-typeof -- Validate untrusted JSON or assert the boundary contract; preserve primitive type checks.
      for (const file of [input.tool_input.file_path, ...(input.tool_input.files ?? [])].filter((f) => typeof f === 'string' && isLocalPath(f))) {
        let exists = false;

        try { exists = Boolean(fs.lstatSync(file)); } catch { /* new file */ }

        // The same file under two names (given path and real path) is read once.
        const key = (realPathOf(file) ?? file).toLowerCase();

        if (!exists || seenFiles.has(key)) continue;
        seenFiles.add(key);
        let st = null;

        try { st = localFileStat(file); } catch { /* unreadable */ }

        if (st && st.size <= 1024 * 1024) olds.push(fs.readFileSync(file, 'utf8'));
        else input.tool_input = { ...input.tool_input, old_content_unverified: true };
      }

      if (olds.length) input.tool_input = { ...input.tool_input, old_content: olds.join('\n') };
    }

    let { output, log } = decide(event, input, ctx);

    // Paused: only a tampering finding stands (refused and recorded); anything else is neutral.
    if (paused) {
      const tampering = log.filter((e) => e.kind === 'tamper');

      if (!tampering.length) {
        neutral();

        return;
      }

      try { appendLog(tampering.map((e) => ({ ...e, mode, harness })), input.session_id, home); } catch { /* the denial still applies */ }

      emit(adapter.render(event, output, { native: nativeEvent, input }));

      return;
    }

    // The common tool path does not load spend parsing/state code. An open episode, a real prompt
    // or a transcript event loads it on demand; failures cannot weaken the security decision.
    if (session.spend || event === 'UserPromptSubmit' || (harness === 'claude' && input.transcript_path)) {
      try {
        ({ output, log } = await (await import('./spend-hook.mjs')).applySpendEvent({ session, event, input, harness, adapter, mode, home, output, log }));
      } catch { /* advisory spend processing is fail-open */ }
    }

    // An agent that hands over the file's contents before a read (Cursor): a file holding real
    // credentials is not read in protect mode.
    // oxlint-disable-next-line anti-slop/no-runtime-typeof -- Validate untrusted JSON or assert the boundary contract; preserve primitive type checks.
    if (event === 'PreToolUse' && typeof input.content === 'string' && output?.hookSpecificOutput?.permissionDecision !== 'deny') {
      const seen = decide('PostToolUse', { tool_name: 'Read', tool_response: input.content }, ctx);

      if (seen.output) {
        const why = t('blackbrake: this file contains credentials; reading it would send them to the model provider.');
        log = [...log, ...seen.log.map((e) => ({ ...e, ev: 'PreToolUse', action: mode === 'protect' ? 'denied' : 'warned' }))];
        output = mode === 'protect' ? { hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: 'deny', permissionDecisionReason: why } } : { systemMessage: [output?.systemMessage, why].filter(Boolean).join(' ') };
      }
    }

    // The first event of a session marks the agent as running (for `blackbrake watch`).
    if (!session.seen) {
      try { setSession(input.session_id, { seen: new Date().toISOString() }, home); } catch { /* the policy result still applies */ }

      if (!log.some((e) => e.kind === 'session')) log = [{ ev: event, kind: 'session', action: 'start' }, ...log];
    }

    try { appendLog(log.map((e) => ({ ...e, mode, harness })), input.session_id, home); } catch {
      // Full disks and inaccessible logs must never turn a denial into an allow.
      process.stderr.write(t('blackbrake could not save its security log; the decision still applies.'));
    }

    emit(adapter.render(event, output, { native: nativeEvent, input }));

    // The alerts window, once per session (after answering: it never delays the agent).
    try { maybeOpenWindow(input.session_id, { home, background: harness === 'cursor' && input.is_background_agent === true, cli: path.join(path.dirname(fileURLToPath(import.meta.url)), 'watch-main.mjs') }); } catch { /* optional */ }
  } catch (e) {
    // No unchecked suffix is safe: refusing oversize tool calls keeps padding from bypassing
    // the mandatory tamper check in either mode.
    const canonical = Object.hasOwn(adapter.events, native) ? adapter.events[native] : null;

    if (e instanceof TooLarge && (canonical === 'PreToolUse' || !canonical)) {
      try { appendLog([{ ev: canonical ?? 'unknown', kind: 'error', action: 'denied', harness, mode }], null, home); } catch { /* still refused */ }

      const reason = t('blackbrake cannot fully inspect this input within its size or nesting limits. Split it into smaller steps.');
      emit(adapter.render('PreToolUse', { hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: 'deny', permissionDecisionReason: reason } }, { native, input: {} }));

      return;
    }

    // The tamper check is mandatory even in observe; malformed tool calls cannot skip it.
    const failureMode = canonical === 'PreToolUse' || !canonical ? 'protect' : mode;

    try { appendLog([{ ev: canonical ?? 'unknown', kind: 'error', action: failureMode === 'protect' ? 'denied' : 'skipped', harness, mode, error: String(e?.code ?? e?.name ?? 'Error') }], null, home); } catch { /* nothing else to do */ }

    // Said in both modes: a guard that silently stops working is worse than none.
    // oxlint-disable-next-line anti-slop/no-runtime-typeof -- Validate untrusted JSON or assert the boundary contract; preserve primitive type checks.
    emit(renderError(harness, typeof native === 'string' ? native : '', t(failureMode === 'protect' ? 'blackbrake guard could not check this step. Unchecked actions are refused; run "blackbrake status" in your terminal.' : 'blackbrake guard could not check this step. Run "blackbrake status" in your terminal.'), failureMode));
  }
}

main();
