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

  if (transcript && spend.open && spend.tail) {
    const { accountTranscriptRecords, tailTranscript } = await import('../cost/live.mjs');

    const root = process.env.CLAUDE_CONFIG_DIR && path.isAbsolute(process.env.CLAUDE_CONFIG_DIR)
      ? path.join(process.env.CLAUDE_CONFIG_DIR, 'projects')
      : path.join(os.homedir(), '.claude', 'projects');

    const tailed = tailTranscript(transcript, { roots: [root], state: spend.tail });
    const usage = accountTranscriptRecords(tailed.records, { responses: spend.responses }, spendSecret());

    spend.tail = tailed.state;
    spend.responses = usage.responses;
    spend.open = { ...spend.open, cost: (spend.open.cost ?? 0) + usage.costDelta, responses: (spend.open.responses ?? 0) + usage.responseDelta, tokens: (spend.open.tokens ?? 0) + usage.tokensDelta };
    spendChanged = true;
  } else if (transcript && !spend.tail) {
    const { tailTranscript } = await import('../cost/live.mjs');

    const root = process.env.CLAUDE_CONFIG_DIR && path.isAbsolute(process.env.CLAUDE_CONFIG_DIR)
      ? path.join(process.env.CLAUDE_CONFIG_DIR, 'projects')
      : path.join(os.homedir(), '.claude', 'projects');

    // Establish the byte boundary without assigning earlier history to a new live episode.
    spend.tail = tailTranscript(transcript, { roots: [root], fromEnd: true }).state;
    spendChanged = true;
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
