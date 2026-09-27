// Every local AI harness blackbrake knows: how to tell it is installed, where it keeps history and
// sessions (what `blackbrake scan` reads and the watcher follows), the process names it runs as, and
// whether it supports hooks (then guard runs inside it) or is watched from outside.
//   hooks:  guard answers inside the agent (block, ask, hide) — see harnesses.mjs / agents.mjs
//   watch:  no hook system (or not supported yet): blackbrake scans its files on demand, follows
//           them as they grow and notices when it runs. It can warn, not stop.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const home = () => os.homedir();

// The user's roaming folder on Windows: APPDATA only when it lies inside the user's home.
export const roamingDir = () => {
  const v = process.env.APPDATA;

  return v && path.isAbsolute(v) && v.toLowerCase().startsWith(home().toLowerCase()) ? v : path.join(home(), 'AppData', 'Roaming');
};

const appData = roamingDir;

const envDir = (name, fallback) => (process.env[name] && path.isAbsolute(process.env[name]) ? process.env[name] : fallback);

// dirs: where it lives (first existing wins for detection; all are scanned).
export const HARNESSES = [
  { id: 'claude', name: 'Claude Code', kind: 'hooks', dirs: () => [envDir('CLAUDE_CONFIG_DIR', path.join(home(), '.claude'))], procs: ['claude'] },
  { id: 'codex', name: 'Codex', kind: 'hooks', dirs: () => [envDir('CODEX_HOME', path.join(home(), '.codex'))], procs: ['codex'] },
  { id: 'gemini', name: 'Gemini CLI', kind: 'hooks', dirs: () => [path.join(home(), '.gemini')], procs: ['gemini'] },
  { id: 'cursor', name: 'Cursor', kind: 'hooks', dirs: () => [path.join(home(), '.cursor')], procs: ['cursor', 'cursor-agent'] },
  { id: 'copilot', name: 'GitHub Copilot CLI', kind: 'hooks', dirs: () => [envDir('COPILOT_HOME', path.join(home(), '.copilot'))], procs: ['copilot'] },
  { id: 'windsurf', name: 'Windsurf', kind: 'hooks', dirs: () => [path.join(home(), '.codeium', 'windsurf')], procs: ['windsurf'] },
  { id: 'devin', name: 'Devin CLI', kind: 'hooks', dirs: () => [process.platform === 'win32' ? path.join(appData(), 'devin') : path.join(home(), '.config', 'devin')], procs: ['devin'] },
  { id: 'ollama', name: 'Ollama', kind: 'watch', dirs: () => [path.join(home(), '.ollama')], procs: ['ollama', 'ollama app'] },
  { id: 'hermes', name: 'Hermes Agent', kind: 'watch', dirs: () => [path.join(home(), '.hermes')], procs: ['hermes'] },
  { id: 'kimi', name: 'Kimi Code', kind: 'watch', dirs: () => [envDir('KIMI_CODE_HOME', path.join(home(), '.kimi-code'))], procs: ['kimi'] },
  { id: 'grok', name: 'Grok Build', kind: 'watch', dirs: () => [envDir('GROK_HOME', path.join(home(), '.grok'))], procs: ['grok'] },
  { id: 'opencode', name: 'OpenCode', kind: 'watch', dirs: () => [path.join(home(), '.local', 'share', 'opencode'), path.join(home(), '.config', 'opencode')], procs: ['opencode'] },
  { id: 'qwen', name: 'Qwen Code', kind: 'watch', dirs: () => [path.join(home(), '.qwen')], procs: ['qwen'] },
  { id: 'goose', name: 'Goose', kind: 'watch', dirs: () => [path.join(home(), '.config', 'goose'), path.join(home(), '.local', 'share', 'goose')], procs: ['goose'] },
  { id: 'continue', name: 'Continue', kind: 'watch', dirs: () => [path.join(home(), '.continue')], procs: [] },
  { id: 'pi', name: 'Pi', kind: 'watch', dirs: () => [path.join(home(), '.pi')], procs: [] },
  { id: 'cline', name: 'Cline', kind: 'watch', dirs: () => [path.join(appData(), 'Code', 'User', 'globalStorage', 'saoudrizwan.claude-dev'), path.join(home(), '.config', 'Code', 'User', 'globalStorage', 'saoudrizwan.claude-dev'), path.join(home(), 'Library', 'Application Support', 'Code', 'User', 'globalStorage', 'saoudrizwan.claude-dev')], procs: [] },
  { id: 'aider', name: 'Aider', kind: 'watch', dirs: () => [path.join(home(), '.aider')], procs: ['aider'] },
  { id: 'lmstudio', name: 'LM Studio', kind: 'watch', dirs: () => [path.join(home(), '.lmstudio'), path.join(home(), '.cache', 'lm-studio')], procs: ['lm studio', 'lms'] },
  { id: 'amp', name: 'Amp', kind: 'watch', dirs: () => [path.join(home(), '.config', 'amp'), path.join(home(), '.local', 'share', 'amp')], procs: [] },
];

const isDir = (d) => {
  try { return fs.lstatSync(d).isDirectory(); } catch { return false; }
};

export const harnessDirs = (h) => h.dirs().filter((d) => d && !/^[\\/]{2}/.test(d) && isDir(d));

export const detected = (h) => harnessDirs(h).length > 0;

export const detectedHarnesses = () => HARNESSES.filter(detected);

export const harness = (id) => HARNESSES.find((h) => h.id === id) ?? null;
