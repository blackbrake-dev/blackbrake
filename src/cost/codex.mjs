// Codex tail warning (F5.4). Codex session files carry cumulative token totals, not prices, so the
// measure is tokens per episode: from a real prompt to the next real prompt, as in V0. Nothing here
// keeps text; what is written is numbers and hashes only.
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { t } from '../i18n.mjs';
import { isLocalPath } from '../text.mjs';
import { isHarnessText } from '../transcripts.mjs';
import { baselineFromEpisodes } from '../guard/spend.mjs';
import { appendLog, guardHome, writePrivate } from '../guard/state.mjs';
import { tailTranscript } from './live.mjs';

const MIB = 1024 * 1024;

const finite = (value) => Number.isFinite(value) && value >= 0;

// A remote CODEX_HOME (\\host\share) is never listed: on Windows that can send NTLM credentials.
export const codexRoot = (env = process.env) => {
  const home = env.CODEX_HOME && path.isAbsolute(env.CODEX_HOME) && isLocalPath(env.CODEX_HOME) ? env.CODEX_HOME : path.join(os.homedir(), '.codex');

  return path.join(home, 'sessions');
};

// Codex sends its own blocks (environment, AGENTS.md, skill and subagent notices) with role "user".
const injected = (text) => isHarnessText(text) || /^# AGENTS\.md\b/.test(text.trimStart());

const isRealPrompt = (record) => {
  const p = record?.payload;

  if (record?.type !== 'response_item' || p?.type !== 'message' || p.role !== 'user' || !Array.isArray(p.content) || !p.content.length) return false;

  // oxlint-disable-next-line anti-slop/no-runtime-typeof -- Session files are untrusted JSON.
  return !injected(p.content.map((c) => (typeof c?.text === 'string' ? c.text : '')).join(''));
};

const rateOf = (limits) => {
  const out = {};

  for (const k of ['primary', 'secondary']) {
    const w = limits?.[k];

    if (finite(w?.used_percent) && finite(w?.window_minutes)) out[k] = { usedPercent: w.used_percent, windowMinutes: w.window_minutes };
  }

  return Object.keys(out).length ? out : null;
};

// state: { total, cached, open, rate }. total null means the running total is not known yet (a file
// read again after rotation): the next count sets it without being assigned to any episode.
export const freshCodexState = () => ({ total: 0, cached: 0, open: null, rate: null });

// Applies one record; returns the episode a real prompt closed, if any.
export function stepCodex(state, record, { prompts = true } = {}) {
  if (prompts && isRealPrompt(record)) {
    const closed = state.open ? { tokens: state.open.tokens, cached: state.open.cached } : null;
    state.open = { tokens: 0, cached: 0, alerted: false };

    return closed;
  }

  if (record?.type !== 'event_msg' || record.payload?.type !== 'token_count') return null;
  state.rate = rateOf(record.payload.rate_limits) ?? state.rate;
  const usage = record.payload.info?.total_token_usage;

  if (!finite(usage?.total_tokens)) return null;
  const total = usage.total_tokens;
  const cached = finite(usage.cached_input_tokens) ? usage.cached_input_tokens : 0;

  // The same cumulative total repeated adds nothing; a total that goes down is a counter that
  // started again from zero.
  if (state.total !== null && state.open) {
    const restarted = total < state.total;
    state.open.tokens += restarted ? total : total - state.total;
    state.open.cached += restarted ? cached : Math.max(0, cached - state.cached);
  }

  state.total = total;
  state.cached = cached;

  return null;
}

export function episodesFromRecords(records, state = freshCodexState()) {
  const episodes = [];

  for (const record of records) {
    const closed = stepCodex(state, record);

    if (closed) episodes.push(closed);
  }

  if (state.open) episodes.push({ tokens: state.open.tokens, cached: state.open.cached });

  return { episodes, state, rate: state.rate };
}

// Session files under the root, without following any link (a junction or symlink is neither a
// file nor a directory to readdir).
export function listCodexSessions(root = codexRoot(), { maxFiles = 5000 } = {}) {
  const out = [];
  const stack = [[root, 0]];

  while (stack.length && out.length < maxFiles) {
    const [dir, depth] = stack.pop();
    let entries = [];

    try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { continue; }

    for (const e of entries) {
      const full = path.join(dir, e.name);

      if (e.isDirectory() && depth < 6) stack.push([full, depth + 1]);
      else if (e.isFile() && e.name.endsWith('.jsonl')) out.push(full);
    }
  }

  return out.sort();
}

// Reads one file up to its end, 1 MiB at a time (longer lines are skipped by the tail).
function readToEnd(file, root, onRecord) {
  let tail = {};

  for (;;) {
    const read = tailTranscript(file, { roots: [root], state: tail, maxBytes: MIB });

    for (const record of read.records) onRecord(record);
    const moved = read.state.offset !== tail.offset;
    tail = read.state;

    if (!moved || tail.offset >= tail.size) return tail;
  }
}

const baselineOf = (tokens) => {
  // The baseline math is unit-free: here the unit is tokens.
  const { n, p50, p90, ready } = baselineFromEpisodes(tokens.map((cost) => ({ cost })), 'codex');

  return { n, p50, p90, ready };
};

function scanHistory(root) {
  const files = new Map();
  const tokens = [];
  let rate = null;

  for (const file of listCodexSessions(root)) {
    const state = freshCodexState();
    let tail;

    try {
      tail = readToEnd(file, root, (record) => {
        const closed = stepCodex(state, record);

        if (closed) tokens.push(closed.tokens);
      });
    } catch { continue; }

    if (state.open) tokens.push(state.open.tokens);
    rate = state.rate ?? rate;
    files.set(file, { tail, state: { total: state.total, cached: state.cached, open: null, rate: state.rate } });
  }

  return { files, tokens, rate };
}

export function summarizeCodexHistory({ root = codexRoot() } = {}) {
  const { files, tokens, rate } = scanHistory(root);
  const baseline = baselineOf(tokens);

  return {
    harness: 'codex',
    sessions: files.size,
    episodes: tokens.length,
    baseline,
    aboveP90: baseline.ready ? tokens.filter((n) => n > baseline.p90).length : 0,
    rate,
  };
}

// The live part, run by the background watcher. Files that exist when it starts are followed from
// their end (an episode already running is never measured from its middle); files that appear later
// are new sessions and are read from their first line. A file rewritten or replaced is read again
// only to learn its running total.
export function createCodexSpend({ home = guardHome(), root = codexRoot(), notifier = null, budget = 16 * MIB } = {}) {
  const history = scanHistory(root);
  const files = history.files;
  const tokens = history.tokens;
  let baseline = baselineOf(tokens);
  let rate = history.rate;
  let saved = '';

  const save = () => {
    const text = `${JSON.stringify({ baseline, rate })}\n`;

    if (text === saved) return;
    writePrivate(path.join(home, 'spend', 'codex.json'), text);
    saved = text;
  };

  save();

  const warn = (file, open) => {
    open.alerted = true;

    const entry = {
      ev: 'Codex', kind: 'spend-tokens', action: 'warned', harness: 'codex', tokens: open.tokens, cached: open.cached, p90: baseline.p90, n: baseline.n,
      primaryPercent: rate?.primary?.usedPercent, secondaryPercent: rate?.secondary?.usedPercent,
    };

    appendLog([entry], `codex:${crypto.createHash('sha256').update(file).digest('hex')}`, home);

    try { notifier?.('blackbrake · Codex', t('This Codex episode is at {tokens} tokens; your p90 is {p90}.', { tokens: open.tokens, p90: baseline.p90 })); } catch { /* the log keeps it */ }

    return entry;
  };

  return {
    tick() {
      const alerts = [];
      let left = budget;

      for (const file of listCodexSessions(root)) {
        if (left <= 0) break;
        const known = files.get(file) ?? { tail: {}, state: freshCodexState() };
        let read;

        try { read = tailTranscript(file, { roots: [root], state: known.tail, maxBytes: Math.min(MIB, left) }); } catch { continue; }

        const prev = known.tail;
        const reset = Boolean(prev.identity) && (read.state.identity !== prev.identity || read.state.size < prev.offset);

        if (reset) known.state = { total: null, cached: 0, open: null, rate: known.state.rate, catchUp: true };
        left -= Math.max(0, read.state.offset - (reset ? 0 : prev.offset ?? 0));
        const { state } = known;

        for (const record of read.records) {
          const closed = stepCodex(state, record, { prompts: !state.catchUp });

          if (closed) {
            tokens.push(closed.tokens);
            baseline = baselineOf(tokens);
          }

          rate = state.rate ?? rate;

          if (state.open && !state.open.alerted && baseline.ready && state.open.tokens > baseline.p90) alerts.push(warn(file, state.open));
        }

        if (state.catchUp && read.state.offset >= read.state.size) state.catchUp = false;
        known.tail = read.state;
        files.set(file, known);
      }

      save();

      return alerts;
    },
  };
}

// Manual probe: aggregates only (sessions, episodes, token p50/p90, quota percentages).
if (process.argv[1] && path.resolve(process.argv[1]) === path.resolve(fileURLToPath(import.meta.url))) {
  process.stdout.write(`${JSON.stringify(summarizeCodexHistory())}\n`);
}
