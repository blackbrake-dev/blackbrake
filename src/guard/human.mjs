// The human gate: who may lower protection. A person sitting at a terminal, and not an AI agent
// that got hold of a pseudo-terminal. This is a heuristic, not a wall (see "What guard cannot
// promise" in the README): an agent that cleans its environment gets past the marker check.
import { t } from '../i18n.mjs';

// Environment variables that an AI agent sets in the processes it starts. Only markers that have
// been seen in a real session belong here.
// To add one: (1) confirm the variable in the agent's own documentation or in a real session of
// it, (2) add it below with a comment naming that source, (3) add a case to test/human.test.mjs.
export const AGENT_MARKERS = [
  'CLAUDECODE', // Claude Code sets CLAUDECODE=1 in every shell it runs (seen in a real session, 2026-09-30).
];

// The marker that is present (non-empty), or null.
export const agentMarker = (env = process.env) => AGENT_MARKERS.find((m) => Boolean(env[m])) ?? null;

// { ok: true } for a person at a terminal. Otherwise { ok: false, reason, message?, how? }:
// 'no-terminal' (stdin or stdout is not a terminal; callers say "Nothing changed") or 'agent'
// (an agent marker is present; `message` says what is wrong and `how` how to do it properly).
export function requireHuman({ env = process.env, input = process.stdin, output = process.stdout } = {}) {
  if (!input?.isTTY || !output?.isTTY) return { ok: false, reason: 'no-terminal' };

  if (agentMarker(env)) {
    return {
      ok: false,
      reason: 'agent',
      message: t('Run this in your own terminal window, not inside an AI agent.'),
      how: t('Open a normal terminal yourself (outside Claude Code or any other agent), run the same command there and type the word yourself.'),
    };
  }

  return { ok: true };
}
