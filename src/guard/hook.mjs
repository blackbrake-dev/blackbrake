#!/usr/bin/env node
// Entry point an agent runs for each hook event: `node hook.mjs <Event> [--harness <id>]` with the
// event JSON on stdin. Answers in that agent's format (stdout, and exit code 2 where the agent uses it
// to block). If anything fails, guard stays out of the way and says so.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { detectLang, setLang, t } from '../i18n.mjs';
import { loadRules } from '../secrets/engine.mjs';
import { ADAPTERS, renderError } from './harnesses.mjs';
import { decide, protectedTarget } from './policy.mjs';
import { isLocalPath, localFileStat } from '../text.mjs';
import { appendLog, getMode, getSavedLang, getSession, setSession, trustedHome } from './state.mjs';
import { maybeOpenWindow } from './window.mjs';

const MAX_INPUT = 32 * 1024 * 1024;

function readStdin() {
  const buf = fs.readFileSync(0);

  if (buf.length > MAX_INPUT) throw new Error('hook input too large');

  return buf.toString('utf8');
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
function realPathOf(file) {
  try { return fs.realpathSync.native(file); } catch { /* maybe a new file */ }

  try { return path.join(fs.realpathSync.native(path.dirname(file)), path.basename(file)); } catch { return null; }
}

function main() {
  const native = process.argv[2];
  const harness = ADAPTERS[argValue('--harness')] ? argValue('--harness') : 'claude';
  const adapter = ADAPTERS[harness];
  // An installed copy ignores a BLACKBRAKE_HOME the agent's environment points elsewhere.
  const home = trustedHome(import.meta.url);
  process.env.BLACKBRAKE_HOME = home;
  let mode = 'observe';

  try {
    mode = getMode(home);
    setLang(detectLang({ saved: getSavedLang(home) }));
    const raw = JSON.parse(readStdin() || '{}');
    const nativeEvent = native || raw.hook_event_name || raw.agent_action_name;
    const canonical = adapter.events[nativeEvent];

    if (!canonical || adapter.skip?.(nativeEvent, raw)) {
      emit(adapter.render(canonical ?? 'none', null, { native: nativeEvent, input: {} }));

      return;
    }

    const { event, input } = adapter.normalize(canonical, raw, nativeEvent);
    const session = getSession(input.session_id, home);

    if (event === 'PostCompact') setSession(input.session_id, { compactedAt: new Date().toISOString() }, home);

    let rules = null;

    const claudeDir = process.env.CLAUDE_CONFIG_DIR && path.isAbsolute(process.env.CLAUDE_CONFIG_DIR) ? process.env.CLAUDE_CONFIG_DIR : '';

    const ctx = {
      mode,
      home: os.homedir(),
      guardDir: home,
      claudeDir,
      compactedAt: session.compactedAt ?? null,
      get rules() {
        rules ??= loadRules();

        return rules;
      },
    };

    // The real path of each file a tool is about to write: a Windows short name (ALUCE~1\.BLACKB~1)
    // or a link names a protected file without spelling it. Checked alongside the given path.
    const ti = input.tool_input;

    if (event === 'PreToolUse' && ti && typeof ti === 'object' && /^(Write|Edit|MultiEdit|NotebookEdit)$/.test(input.tool_name ?? '')) {
      const real = [ti.file_path, ...(ti.files ?? [])].filter((f) => typeof f === 'string' && isLocalPath(f)).map(realPathOf).filter(Boolean);

      if (real.length) input.tool_input = { ...ti, files: [...(ti.files ?? []), ...real] };
    }

    // A full overwrite of a settings or hook file: what it held before counts as removed, so dropping
    // guard's entry is seen (a small local file; a link is followed only to a local regular file).
    if (event === 'PreToolUse' && input.tool_name === 'Write' && [input.tool_input?.file_path, ...(input.tool_input?.files ?? [])].some((f) => protectedTarget(f, ctx) === 'settings')) {
      // Every existing target is read (a protected one may be reachable only through files[]); one
      // that exists but cannot be read (too large, a link elsewhere) makes the overwrite unverifiable.
      const olds = [];
      const seenFiles = new Set();

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

    // An agent that hands over the file's contents before a read (Cursor): a file holding real
    // credentials is not read in protect mode.
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
      setSession(input.session_id, { seen: new Date().toISOString() }, home);

      if (!log.some((e) => e.kind === 'session')) log = [{ ev: event, kind: 'session', action: 'start' }, ...log];
    }

    appendLog(log.map((e) => ({ ...e, mode, harness })), input.session_id, home);
    emit(adapter.render(event, output, { native: nativeEvent, input }));

    // The alerts window, once per session (after answering: it never delays the agent).
    try { maybeOpenWindow(input.session_id, { home, cli: path.join(path.dirname(fileURLToPath(import.meta.url)), 'watch-main.mjs') }); } catch { /* optional */ }
  } catch (e) {
    try { appendLog([{ ev: native ?? 'unknown', kind: 'error', action: 'skipped', harness, error: String(e?.code ?? e?.name ?? 'Error') }], null, home); } catch { /* nothing else to do */ }

    // Said in both modes: a guard that silently stops working is worse than none.
    emit(renderError(harness, native ?? '', t(mode === 'protect' ? 'blackbrake guard could not check this step, so it was not protected. Run "blackbrake status" in your terminal.' : 'blackbrake guard could not check this step. Run "blackbrake status" in your terminal.')));
  }
}

main();
