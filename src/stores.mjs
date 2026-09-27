// Other places where Claude Code keeps text in plain files, besides the session transcripts:
// prompt history, pasted content, pre-edit file copies, shell snapshots, large tool outputs, and
// configuration (user and per project). Read-only. Files that exist to hold credentials
// (~/.claude/.credentials.json) are skipped on purpose.
import fs from 'node:fs';
import path from 'node:path';
import { clean, isLocalPath, localFileStat } from './text.mjs';

const MAX_BYTES = 20e6;

const TEXT_EXT = /\.(jsonl?|txt|md|log|sh|bash|zsh|ps1|html?|tmp|env|toml|ya?ml)$/i;

function walk(dir, depth = 6) {
  const out = [];
  let entries;

  try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return out; }

  for (const e of entries) {
    const full = path.join(dir, e.name);

    if (e.isDirectory() && depth > 0) out.push(...walk(full, depth - 1));
    else if (e.isFile()) out.push(full);
  }

  return out;
}

// Text only: skip large files and anything with NUL bytes near the start (images, PDFs).
export function readTextFile(file) {
  try {
    // A symlink could point at a device, a FIFO (blocks forever) or a network path.
    const st = localFileStat(file);

    if (!st || st.size > MAX_BYTES) return null;
    const buf = fs.readFileSync(file);

    if (buf.subarray(0, 4096).includes(0)) return null;

    return buf.toString('utf8');
  } catch {
    return null;
  }
}

// [{ store, kind: 'history' | 'config', file }]
export function listStores({ home, projects = [] }) {
  const claude = path.join(home, '.claude');
  const out = [];
  const add = (store, kind, files) => { for (const file of files) out.push({ store, kind, file }); };

  const exists = (f) => fs.existsSync(f);

  add('prompt history', 'history', [path.join(claude, 'history.jsonl')].filter(exists));
  add('paste cache', 'history', walk(path.join(claude, 'paste-cache')));
  add('file history', 'history', walk(path.join(claude, 'file-history')));
  add('shell snapshots', 'history', walk(path.join(claude, 'shell-snapshots')));
  add('session data', 'history', walk(path.join(claude, 'session-data')));
  add('tool outputs', 'history', walk(path.join(claude, 'projects')).filter((f) => !f.endsWith('.jsonl') && TEXT_EXT.test(f)));
  add('config backups', 'config', walk(path.join(claude, 'backups')).filter((f) => TEXT_EXT.test(f) || /\.json\b/.test(f)));
  add('user config', 'config', [
    path.join(home, '.claude.json'),
    path.join(claude, 'settings.json'),
    path.join(claude, 'settings.local.json'),
  ].filter(exists));

  for (const dir of projects.filter((d) => isLocalPath(d) && path.isAbsolute(d))) {
    add(`project config (${clean(path.basename(dir), 60)})`, 'config', [
      path.join(dir, '.claude', 'settings.json'),
      path.join(dir, '.claude', 'settings.local.json'),
      path.join(dir, '.mcp.json'),
    ].filter(exists));
  }

  // A crafted folder with millions of entries must not exhaust memory.
  return out.slice(0, 50_000);
}

// Is ~/.claude inside a git repository or a folder that syncs to the cloud? Either way, the
// transcripts leave the machine without anyone deciding it (a real case: 15 GitHub secret-scanning
// alerts from a ~/.claude mirrored to git, anthropics/claude-code#63593).
export function claudeDirExposure(home) {
  const claude = path.join(home, '.claude');
  const synced = /[\\/](OneDrive[^\\/]*|Dropbox|iCloud ?Drive|iCloudDrive|Google ?Drive|Mobile Documents)([\\/]|$)/i.exec(claude);
  let dir = claude;

  for (;;) {
    if (fs.existsSync(path.join(dir, '.git'))) return { kind: 'git', where: dir };
    const up = path.dirname(dir);

    if (up === dir) break;
    dir = up;
  }

  return synced ? { kind: 'synced', where: synced[1] } : null;
}
