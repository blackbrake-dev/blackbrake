import crypto from 'node:crypto';
import os from 'node:os';
import path from 'node:path';
import { t } from '../i18n.mjs';
import { isHarnessText } from '../transcripts.mjs';
import { createLoopDetector } from './loops.mjs';
import {
  appendLoopCall, appendSpendEpisode, getSpendBaseline, getSpendSecret, readLoopSnapshot,
  resetLoopCalls,
} from './spend-state.mjs';
import { setSession } from './state.mjs';
import { spendAlert, withinTokenBudget } from './spend.mjs';

const MIB = 1024 * 1024;

const safeTail = (tail) => {
  // oxlint-disable-next-line anti-slop/no-runtime-typeof -- Per-session state is untrusted JSON.
  if (!tail || typeof tail !== 'object') return {};
  const offset = Number.isInteger(tail.offset) && tail.offset >= 0 ? tail.offset : 0;
  const size = Number.isInteger(tail.size) && tail.size >= 0 ? tail.size : 0;
  const identity = /^[a-f0-9]{16}$/.test(tail.identity ?? '') ? tail.identity : undefined;
  const safe = { offset, size };

  if (identity) safe.identity = identity;

  if (tail.skip === true) safe.skip = true;

  return safe;
};

const inspectChildRecords = (records, sessionId, previous = {}) => {
  let validated = previous.validated === true;
  let started = Number.isFinite(previous.started) ? previous.started : null;

  for (const record of records) {
    // oxlint-disable-next-line anti-slop/no-runtime-typeof -- Child transcript JSON is validated at this boundary.
    const declared = [record?.sessionId, record?.session_id, record?.parentSessionId].filter((value) => typeof value === 'string');

    if (declared.some((value) => value !== sessionId)) return { validated, started, rejected: true };

    if (declared.some((value) => value === sessionId)) validated = true;

    // oxlint-disable-next-line anti-slop/no-runtime-typeof -- Child transcript JSON is validated at this boundary.
    if (started === null && validated && typeof record?.timestamp === 'string') {
      const parsed = Date.parse(record.timestamp);

      if (Number.isFinite(parsed)) started = parsed;
    }
  }

  return { validated, started, rejected: false };
};

const childKey = (file, secret) => crypto.createHmac('sha256', secret).update(`claude-subagent\0${path.basename(file)}`).digest('hex');

const safeChildState = (stored, silent = false) => {
  const state = {
    tail: safeTail(stored?.tail),
    validated: stored?.validated === true,
    started: Number.isFinite(stored?.started) ? stored.started : null,
    rejected: stored?.rejected === true,
    silent: stored?.silent === true || silent,
  };

  if (Object.hasOwn(stored ?? {}, 'episodeStart')) state.episodeStart = Number.isFinite(stored.episodeStart) ? stored.episodeStart : null;

  return state;
};

// Follow only children of the validated parent session. The first enumeration is a silent snapshot:
// it cannot turn spend from an already-running episode into a historical alert. Later files are new
// subagents and are assigned by their first timestamp to the parent episode open at that moment.
function accountClaudeSubagents({ live, transcript, root, sessionId, spend, secret }) {
  let listed;

  try { listed = live.listClaudeSubagentFiles(transcript, sessionId, { roots: [root] }); } catch { return false; }

  // oxlint-disable-next-line anti-slop/no-runtime-typeof -- Per-session state is untrusted JSON.
  const prior = spend.subagents && typeof spend.subagents === 'object' ? spend.subagents : {};
  // oxlint-disable-next-line anti-slop/no-runtime-typeof -- Per-session state is untrusted JSON.
  const priorFiles = prior.files && typeof prior.files === 'object' ? prior.files : {};
  const initialized = prior.initialized === true;
  const files = {};
  let budget = MIB;
  let changed = !initialized;

  // Preserve bounded state for a temporarily missing/rotated child. Without this, the same file
  // could reappear as "new" and lose both its temporal assignment and rewrite deduplication.
  for (const [key, value] of Object.entries(priorFiles).slice(0, 256)) {
    if (/^[a-f0-9]{64}$/.test(key)) files[key] = safeChildState(value);
  }

  for (const child of listed) {
    const key = childKey(child.file, secret);
    // oxlint-disable-next-line anti-slop/no-runtime-typeof -- Per-session state is untrusted JSON.
    const stored = files[key] && typeof files[key] === 'object' ? files[key] : null;
    const firstSight = !stored;
    const silent = !initialized && firstSight;
    const state = safeChildState(stored, silent);

    if (state.rejected || budget <= 0) {
      files[key] = state;

      continue;
    }

    const seed = state.silent;
    const maxBytes = Math.min(seed ? 64 * 1024 : 256 * 1024, budget);
    let tailed;

    try {
      tailed = live.tailTranscript(child.file, { roots: [path.dirname(path.dirname(child.file))], state: state.tail, maxBytes, fromEnd: seed });
    } catch {
      files[key] = { ...state, rejected: true };
      changed = true;

      continue;
    }

    const reset = Boolean(state.tail.identity) && tailed.state.identity !== state.tail.identity;
    const consumed = seed ? Math.min(maxBytes, child.size) : reset ? tailed.state.offset : Math.max(0, tailed.state.offset - state.tail.offset);

    budget -= Math.min(maxBytes, consumed);
    const inspected = inspectChildRecords(tailed.records, sessionId, state);
    Object.assign(state, inspected, { tail: tailed.state });
    changed = true;

    if (inspected.rejected) {
      state.rejected = true;
      files[key] = state;

      continue;
    }

    if (seed) {
      state.episodeStart = null;
      state.silent = false;
    }
    else if (!Object.hasOwn(state, 'episodeStart') && inspected.validated && Number.isFinite(inspected.started)) {
      state.episodeStart = spend.open && inspected.started >= spend.open.start ? spend.open.start : null;
    }

    if (inspected.validated && Number.isFinite(inspected.started)) {
      const usage = live.accountTranscriptRecords(tailed.records, { responses: spend.responses }, secret);

      spend.responses = usage.responses;

      if (state.episodeStart !== null && state.episodeStart === spend.open?.start) {
        spend.open = {
          ...spend.open,
          cost: (spend.open.cost ?? 0) + usage.costDelta,
          responses: (spend.open.responses ?? 0) + usage.responseDelta,
          tokens: (spend.open.tokens ?? 0) + usage.tokensDelta,
        };
      }
    }

    files[key] = state;
  }

  spend.subagents = { initialized: true, files };

  return changed;
}

export async function applySpendEvent({ session, event, input, harness, adapter, mode, home, output, log }) {
  let secret = null;

  const spendSecret = () => {
    secret ??= getSpendSecret(home);

    return secret;
  };

  // oxlint-disable-next-line anti-slop/no-runtime-typeof -- Session state is untrusted JSON read at this boundary.
  const spend = session.spend && typeof session.spend === 'object' ? { ...session.spend } : {};

  let spendChanged = false;
  const notices = [];
  const spendLog = [];
  // oxlint-disable-next-line anti-slop/no-runtime-typeof -- Normalized hook input is validated at this boundary.
  const realPrompt = event === 'UserPromptSubmit' && typeof input.prompt === 'string' && !isHarnessText(input.prompt);
  // oxlint-disable-next-line anti-slop/no-runtime-typeof -- Native transcript paths are validated before any read.
  const transcript = harness === 'claude' && typeof input.transcript_path === 'string' ? input.transcript_path : null;

  const root = process.env.CLAUDE_CONFIG_DIR && path.isAbsolute(process.env.CLAUDE_CONFIG_DIR)
    ? path.join(process.env.CLAUDE_CONFIG_DIR, 'projects')
    : path.join(os.homedir(), '.claude', 'projects');

  let live = null;

  if (transcript && spend.open && spend.tail) {
    live = await import('../cost/live.mjs');

    const tailed = live.tailTranscript(transcript, { roots: [root], state: spend.tail });
    const usage = live.accountTranscriptRecords(tailed.records, { responses: spend.responses }, spendSecret());

    spend.tail = tailed.state;
    spend.responses = usage.responses;
    spend.open = { ...spend.open, cost: (spend.open.cost ?? 0) + usage.costDelta, responses: (spend.open.responses ?? 0) + usage.responseDelta, tokens: (spend.open.tokens ?? 0) + usage.tokensDelta };
    spendChanged = true;
  } else if (transcript && !spend.tail) {
    live = await import('../cost/live.mjs');

    // Establish the byte boundary without assigning earlier history to a new live episode.
    spend.tail = live.tailTranscript(transcript, { roots: [root], fromEnd: true }).state;
    spendChanged = true;
  }

  if (transcript) {
    live ??= await import('../cost/live.mjs');

    if (accountClaudeSubagents({ live, transcript, root, sessionId: input.session_id, spend, secret: spendSecret() })) spendChanged = true;
  }

  if (realPrompt) {
    if (spend.open) appendSpendEpisode({ ...spend.open, harness }, home);

    spend.open = { start: Date.now(), cost: 0, responses: 0, tokens: 0, label: null, costAlerted: false };
    spend.responses = [];
    resetLoopCalls(input.session_id, home);
    spendChanged = true;
  }

  // Only a PreToolUse answer can ask; elsewhere a protect alert waits for the next tool call.
  const canAsk = Boolean(adapter.spendAsk) && event === 'PreToolUse';

  if (event === 'PreToolUse' && spend.open) {
    const now = Date.now();
    const detector = createLoopDetector({ secret: spendSecret(), snapshot: readLoopSnapshot(input.session_id, home, now) });
    const repeated = detector.record(input.tool_name, input.tool_input, now);

    appendLoopCall(input.session_id, { ...repeated, at: now }, home);

    if (repeated.alert) {
      const message = t('blackbrake: the same call was requested 3 times in 2 minutes. It may be a loop; continue?');

      notices.push({ action: mode === 'protect' && canAsk ? 'ask' : 'warn', message });
      spendLog.push({ ev: event, kind: 'spend-loop', action: mode === 'protect' && canAsk ? 'asked' : 'warned', fingerprint: repeated.fingerprint.slice(0, 16) });
    }
  }

  if (spend.open && adapter.spendCost && (canAsk || !(mode === 'protect' && adapter.spendAsk))) {
    const alert = spendAlert({ baseline: getSpendBaseline(harness, home), episode: spend.open, mode, canAsk });

    if (alert) {
      notices.push(alert);
      spendLog.push({ ev: event, kind: 'spend-cost', action: alert.action === 'ask' ? 'asked' : 'warned', cost: spend.open.cost, responses: spend.open.responses });
      spendChanged = true;
    }
  }

  if (spendChanged) setSession(input.session_id, { spend }, home);

  const nextLog = [...log, ...spendLog];
  const denied = output?.decision === 'block' || output?.hookSpecificOutput?.permissionDecision === 'deny';

  if (!notices.length || denied) return { output, log: nextLog };
  const message = notices.map((notice) => notice.message).join(' ');
  const ask = notices.some((notice) => notice.action === 'ask');

  if (!(ask || withinTokenBudget(message, spend.open?.tokens))) return { output, log: nextLog };

  const nextOutput = ask
    ? { ...output, hookSpecificOutput: { ...output?.hookSpecificOutput, hookEventName: event, permissionDecision: 'ask', permissionDecisionReason: [output?.hookSpecificOutput?.permissionDecisionReason, message].filter(Boolean).join(' ') } }
    : { ...output, systemMessage: [output?.systemMessage, message].filter(Boolean).join(' ') };

  return { output: nextOutput, log: nextLog };
}
