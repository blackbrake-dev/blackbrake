// Opens the user's own AI agent, interactively, with one first message. The agent keeps its own
// permission prompts: the user approves each change there. No shell unless the only copy of the
// agent is an npm .cmd shim on Windows, and then only for arguments cmd.exe cannot reinterpret.
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { CMD_UNSAFE, claudeCommand } from '../guard/install.mjs';
import { isLocalPath } from '../text.mjs';

// How each agent starts interactively with a first message.
export const AGENT_CLIS = [
  { id: 'claude', name: 'Claude Code', bin: 'claude', args: (msg) => [msg] },
  { id: 'codex', name: 'Codex', bin: 'codex', args: (msg) => [msg] },
  { id: 'gemini', name: 'Gemini CLI', bin: 'gemini', args: (msg) => ['-i', msg] },
];

function onPath(bin, { env = process.env, platform = process.platform } = {}) {
  const dirs = String(env.PATH ?? env.Path ?? '').split(platform === 'win32' ? ';' : ':').map((d) => d.replace(/"/g, '')).filter((d) => d && isLocalPath(d) && path.isAbsolute(d));
  const names = platform === 'win32' ? [`${bin}.exe`, `${bin}.cmd`] : [bin];

  // Like the system: each folder in PATH order, every extension in it, before the next folder.
  for (const d of dirs) {
    for (const name of names) {
      const file = path.join(d, name);

      try { if (fs.statSync(file).isFile()) return file; } catch { /* not here */ }
    }
  }

  return null;
}

// The agents this machine can start.
export const availableAgents = (opts) => AGENT_CLIS.filter((a) => onPath(a.bin, opts));

export function agentCommand(agent, msg, opts = {}) {
  const args = agent.args(msg);

  if (agent.id === 'claude') return claudeCommand(args);
  const file = onPath(agent.bin, opts);

  if (!file) throw new Error(`${agent.name} was not found on PATH.`);

  if (!/\.cmd$/i.test(file)) return { file, args, shell: false };

  if ([file, ...args].some((a) => CMD_UNSAFE.test(a))) throw new Error('The path or message contains characters cmd.exe would reinterpret.');

  return { file: [`"${file}"`, ...args.map((a) => `"${a}"`)].join(' '), args: [], shell: true };
}

export function launchAgent(agent, msg) {
  return new Promise((resolve) => {
    let c;

    try { c = agentCommand(agent, msg); } catch (e) {
      resolve({ ok: false, error: e.message });

      return;
    }

    const child = spawn(c.file, c.args, { stdio: 'inherit', shell: c.shell });
    child.on('error', (e) => resolve({ ok: false, error: e.message }));
    child.on('exit', (code) => resolve({ ok: code === 0, code }));
  });
}
