import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { t } from '../i18n.mjs';
import { isLocalPath } from '../text.mjs';
import { isHarnessText } from '../transcripts.mjs';
import { createLoopDetector } from './loops.mjs';
import {
  appendLoopCall, appendSpendEpisode, getSpendBaseline, getSpendSecret, readLoopSnapshot,
  resetLoopCalls,
} from './spend-state.mjs';
import { setSession } from './state.mjs';
import { spendAlert, withinTokenBudget } from './spend.mjs';

const MIB = 1024 * 1024;

const EDIT_MAX_AGE = 120_000;

const editPath = (file) => {
  // oxlint-disable-next-line anti-slop/no-runtime-typeof -- Native hook payload is untrusted.
  if (typeof file !== 'string' || file.length > 4096 || !path.isAbsolute(file) || !isLocalPath(file)) return null;

  return path.normalize(file);
};

const editPathKey = (file) => process.platform === 'win32' ? file.toLowerCase() : file;

// Read metadata only. Never traverse an agent-owned link, including a Windows junction in a parent.
const editStamp = (file) => {
  const root = path.parse(file).root;
  let current = root;
  const parts = path.relative(root, file).split(path.sep).filter(Boolean);

  for (const [index, part] of parts.entries()) {
    current = path.join(current, part);
    let stat;

    try { stat = fs.lstatSync(current, { bigint: true }); } catch (error) {
      if (error.code === 'ENOENT' && index === parts.length - 1) return 'missing';

      return null;
    }

    if (stat.isSymbolicLink()) {
      // Keep the system-owned top-level link exception used by writePrivate (/var on macOS).
      if (process.platform !== 'win32' && stat.uid === 0n && path.dirname(current) === root && index < parts.length - 1) continue;

      return null;
    }

    if (index < parts.length - 1) {
      if (!stat.isDirectory()) return null;

      continue;
    }

    if (!stat.isFile() || stat.nlink !== 1n) return null;

    return `${stat.dev}:${stat.ino}:${stat.size}:${stat.mtimeNs}:${stat.ctimeNs}`;
  }

  return null;
};

const editProof = (secret, id, file) => crypto.createHmac('sha256', secret)
  .update(`${id}\0${editPathKey(file)}`)
  .digest('hex');

const confirmedEdit = ({ spend, event, input, harness, secret, output, now }) => {
  if (harness !== 'claude' || !spend.open || !['Edit', 'Write'].includes(input.tool_name)) return false;
  const file = editPath(input.tool_input?.file_path);
  const id = input.tool_use_id;

  // oxlint-disable-next-line anti-slop/no-runtime-typeof -- Hook identifiers must be bounded before HMAC.
  if (!file || typeof id !== 'string' || !id || id.length > 256) return false;

  const proof = editProof(secret, id, file);

  if (event === 'PreToolUse') {
    if (output?.decision === 'block' || output?.hookSpecificOutput?.permissionDecision === 'deny') return false;
    const before = editStamp(file);

    if (before === null) return false;

    spend.pendingEdit = { proof, before, at: now };

    return false;
  }

  if (event !== 'PostToolUse' || spend.pendingEdit?.proof !== proof) return false;
  const { before, at } = spend.pendingEdit;

  delete spend.pendingEdit;

  if (output?.decision === 'block' || output?.hookSpecificOutput?.permissionDecision === 'deny') return false;

  // oxlint-disable-next-line anti-slop/no-runtime-typeof -- Tool result schema is checked without reading its text.
  const result = input.tool_response && typeof input.tool_response === 'object' && !Array.isArray(input.tool_response) ? input.tool_response : null;

  const validResult = input.tool_name === 'Edit'
    ? Array.isArray(result?.structuredPatch) || ['create', 'update', 'edit'].includes(result?.type)
    : ['create', 'update'].includes(result?.type);

  if (!Number.isFinite(at) || at < spend.open.start || now - at < 0 || now - at > EDIT_MAX_AGE
    || !result || editPathKey(editPath(result.filePath) ?? '') !== editPathKey(file) || !validResult
    || result.error || result.is_error === true || result.isError === true || result.success === false) return false;

  const after = editStamp(file);

  return after !== null && after !== 'missing' && after !== before;
};

const safeTail = (tail) => {
  // oxlint-disable-next-line anti-slop/no-runtime-typeof -- Per-session state is untrusted JSON.
  if (!tail || typeof tail !== 'object') return {};
  const offset = Number.isInteger(tail.offset) && tail.offset >= 0 ? tail.offset : 0;
  const size = Number.isInteger(tail.size) && tail.size >= 0 ? tail.size : 0;
  const identity = /^[a-f0-9]{16}$/.test(tail.identity ?? '') ? tail.identity : undefined;
  const modified = Number.isFinite(tail.modified) && tail.modified >= 0 ? tail.modified : undefined;
  const changed = Number.isFinite(tail.changed) && tail.changed >= 0 ? tail.changed : undefined;
  const safe = { offset, size };

  if (identity) safe.identity = identity;

  if (modified !== undefined) safe.modified = modified;

  if (changed !== undefined) safe.changed = changed;

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
export function accountClaudeSubagents({ live, transcript, root, sessionId, spend, secret }) {
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

    if (!seed && state.tail.offset >= child.size && state.tail.skip !== true
      && state.tail.identity === child.identity && state.tail.size === child.size
      && state.tail.modified === child.modified && state.tail.changed === child.changed) {
      files[key] = state;

      continue;
    }

    const maxBytes = Math.min(seed ? 64 * 1024 : 256 * 1024, budget);
    let tailed;

    try {
      tailed = live.tailTranscript(child.file, { roots: [root], state: state.tail, maxBytes, fromEnd: seed });
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

  if (spend.pendingEdit && (!Number.isFinite(spend.pendingEdit.at) || Date.now() - spend.pendingEdit.at > EDIT_MAX_AGE)) {
    delete spend.pendingEdit;
    spendChanged = true;
  }

  if (harness === 'claude' && spend.open && ['Edit', 'Write'].includes(input.tool_name)
    && (event === 'PreToolUse' || event === 'PostToolUse')) {
    const pendingBefore = spend.pendingEdit;
    const edited = confirmedEdit({ spend, event, input, harness, secret: spendSecret(), output, now: Date.now() });

    if (pendingBefore !== spend.pendingEdit) spendChanged = true;

    if (edited) resetLoopCalls(input.session_id, home);
  }

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
    delete spend.pendingEdit;
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
