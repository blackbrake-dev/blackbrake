// Removes the copies of chosen secrets from local files (transcripts, prompt history, an AI tool's
// history): each value is replaced by its masked shape, so the file keeps its structure and stays
// valid JSON. Pattern after agentscrub and maskara (backup + rollback), reimplemented.
//
// Safety:
// - Only the secrets the user picked (by hash), only in regular local files; a tool's own
//   credential store (auth.json, credentials…) is never touched.
// - Before a file changes, its original is copied to ~/.blackbrake/backups/scrub-<time>/, readable
//   only by the user, and deleted after 7 days. `undo` puts the originals back while it exists.
// - Each file is replaced whole (temporary file + rename); if it changed while being read (an agent
//   writing to it), it is left alone and reported.
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { assertNoLinks } from '../guard/install.mjs';
import { skippedAsOwnCredential } from '../guard/scan.mjs';
import { mayChange } from '../guard/safety.mjs';
import { guardHome } from '../guard/state.mjs';
import { scanText } from '../secrets/engine.mjs';
import { mask } from '../secrets/audit.mjs';
import { isLocalPath } from '../text.mjs';
import { isText } from '../kinds.mjs';

export const KEEP_DAYS = 7;

const MAX_FILE = 200 * 1024 * 1024;

export const secretKey = (value) => crypto.createHash('sha256').update(value).digest('hex').slice(0, 12);

const backupsDir = (home) => path.join(home, 'backups');

// What replaces a value: its masked shape, without quotes or backslashes (JSON stays valid).
const placeholder = (ruleId, value) => `[removed by blackbrake: ${ruleId} ${mask(value)}]`.replace(/["\\]/g, '');

function readRegular(file) {
  if (!isLocalPath(file)) return null;
  const st = fs.lstatSync(file);

  if (!st.isFile() || st.size === 0 || st.size > MAX_FILE) return null;
  const buf = fs.readFileSync(file);

  return buf.subarray(0, 4096).includes(0) ? null : { text: buf.toString('utf8'), st };
}

// A folder that syncs to the cloud must not receive copies that hold secrets.
export const SYNCED = /[\\/](OneDrive[^\\/]*|Dropbox|iCloud ?Drive|Google ?Drive|Mobile Documents|Box)([\\/]|$)/i;

const sha = (text) => crypto.createHash('sha256').update(text).digest('hex');

const sameFile = (a, b) => a.size === b.size && a.mtimeMs === b.mtimeMs && a.ino === b.ino;

// files: absolute paths. keys: Set of 12-character hashes (the audit's and the scan's keys).
export function scrub({ files, keys, rules, home = guardHome(), now = Date.now } = {}) {
  // Rewrites transcripts and keeps a backup in guard's folder: both only by the program (safety.mjs).
  mayChange(path.resolve(backupsDir(home)));

  for (const f of files ?? []) mayChange(path.resolve(f));

  if (SYNCED.test(path.resolve(home))) throw new Error(`blackbrake's folder (${home}) is inside a folder that syncs to the cloud; the backups would hold the secrets. Nothing was changed.`);
  const id = `scrub-${new Date(now()).toISOString().replace(/[:.]/g, '-')}-${crypto.randomBytes(3).toString('hex')}`;
  const dir = path.join(backupsDir(home), id);
  const result = { id, changed: [], replaced: 0, busy: [], failed: [] };
  const index = [];

  for (const file of [...new Set(files)]) {
    if (skippedAsOwnCredential(file)) continue;
    let read = null;

    try {
      read = readRegular(file);

      // Too large to handle whole: reported, not silently skipped.
      if (!read && fs.lstatSync(file).size > MAX_FILE) result.failed.push(file);
    } catch { continue; }

    if (!read) continue;
    let out = read.text;
    let n = 0;

    for (const f of scanText(rules, read.text)) {
      if (!keys.has(secretKey(f.secret)) || !out.includes(f.secret)) continue;
      const parts = out.split(f.secret);
      n += parts.length - 1;
      out = parts.join(placeholder(f.ruleId, f.secret));
    }

    if (!n) continue;
    const tmp = `${file}.${crypto.randomBytes(6).toString('hex')}.tmp`;
    const copy = `${String(index.length).padStart(5, '0')}.bak`;
    let backedUp = false;

    try {
      // The new content goes to a temporary file first; then, right before replacing, the file must
      // be exactly as it was read (an agent appending to it in between: left alone, reported).
      fs.writeFileSync(tmp, out, { flag: 'wx', mode: read.st.mode & 0o777 });

      if (!sameFile(fs.lstatSync(file), read.st)) {
        result.busy.push(file);
        continue;
      }

      // Only now the backup (private folder, never written through a link, a new file), recorded
      // with the fingerprint of what blackbrake wrote, so undo can tell if the file changed since.
      if (!index.length) {
        assertNoLinks(dir);
        fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
      }

      fs.writeFileSync(path.join(dir, copy), read.text, { flag: 'wx', mode: 0o600 });
      index.push({ file, copy, after: sha(out) });
      backedUp = true;
      fs.writeFileSync(path.join(dir, 'index.json'), JSON.stringify({ created: new Date(now()).toISOString(), files: index }), { mode: 0o600 });

      // Checked once more right before the swap, to keep the window as small as it can be.
      if (!sameFile(fs.lstatSync(file), read.st)) throw Object.assign(new Error('busy'), { busy: true });
      fs.renameSync(tmp, file);
      result.changed.push(file);
      result.replaced += n;
    } catch (e) {
      (e?.busy ? result.busy : result.failed).push(file);

      // Nothing replaced: its backup (which holds the secrets) is not kept.
      if (backedUp) {
        index.pop();
        fs.rmSync(path.join(dir, copy), { force: true });

        try { fs.writeFileSync(path.join(dir, 'index.json'), JSON.stringify({ created: new Date(now()).toISOString(), files: index }), { mode: 0o600 }); } catch { /* removed below if empty */ }
      }
    } finally {
      fs.rmSync(tmp, { force: true });
    }
  }

  if (!result.changed.length) fs.rmSync(dir, { recursive: true, force: true });

  return result;
}

// Backups still available: newest first.
export function listScrubs(home = guardHome()) {
  let names = [];

  try { names = fs.readdirSync(backupsDir(home)).filter((n) => n.startsWith('scrub-')); } catch { return []; }

  return names.map((name) => {
    try {
      const index = JSON.parse(fs.readFileSync(path.join(backupsDir(home), name, 'index.json'), 'utf8'));

      return { id: name, created: index.created, files: index.files.length };
    } catch { return null; }
  }).filter(Boolean).sort((a, b) => String(b.created).localeCompare(String(a.created)));
}

// Puts the original files of one clean-up back (the secrets return to them).
export function undoScrub(id, home = guardHome()) {
  if (!/^scrub-[\w-]+$/.test(id)) throw new Error('Unknown clean-up.');
  const dir = mayChange(path.resolve(backupsDir(home), id));
  const index = JSON.parse(fs.readFileSync(path.join(dir, 'index.json'), 'utf8'));
  const result = { restored: 0, changed: [] };

  // A file is put back only if it is still exactly what the clean-up wrote: otherwise it changed
  // since (new transcript lines) or the index was edited, and restoring would overwrite that.
  for (const { file, copy, after } of index.files) {
    if (!/^\d{5}\.bak$/.test(copy) || !isText(file) || !path.isAbsolute(file) || !isLocalPath(file) || !/^[0-9a-f]{64}$/.test(after ?? '')) continue;
    const tmp = `${file}.${crypto.randomBytes(6).toString('hex')}.tmp`;

    try {
      assertNoLinks(path.dirname(file));
      const st = fs.lstatSync(file);

      if (!st.isFile() || sha(fs.readFileSync(file)) !== after) {
        result.changed.push(file);
        continue;
      }

      fs.writeFileSync(tmp, fs.readFileSync(path.join(dir, copy)), { flag: 'wx', mode: st.mode & 0o777 });

      // Still the same file right before the swap (an agent writing to it meanwhile: left alone).
      if (!sameFile(fs.lstatSync(file), st)) {
        result.changed.push(file);
        continue;
      }

      fs.renameSync(tmp, file);
      result.restored++;
    } catch { result.changed.push(file); } finally {
      fs.rmSync(tmp, { force: true });
    }
  }

  // Kept while some file could not be restored, so the user still has the originals.
  if (!result.changed.length) fs.rmSync(dir, { recursive: true, force: true });

  return result;
}

// Deletes clean-up backups older than KEEP_DAYS (they hold the secrets that were removed).
// A folder whose index cannot be read goes by its own modification time.
export function pruneScrubs(home = guardHome(), now = Date.now) {
  mayChange(path.resolve(backupsDir(home)));
  let removed = 0;
  let names = [];

  try { names = fs.readdirSync(backupsDir(home)).filter((n) => /^scrub-[\w-]+$/.test(n)); } catch { return 0; }

  for (const name of names) {
    const dir = path.join(backupsDir(home), name);
    let created = NaN;

    try { created = Date.parse(JSON.parse(fs.readFileSync(path.join(dir, 'index.json'), 'utf8')).created); } catch { /* no index */ }

    try {
      if (!Number.isFinite(created)) created = fs.lstatSync(dir).mtimeMs;

      if (now() - created > KEEP_DAYS * 864e5) {
        fs.rmSync(dir, { recursive: true, force: true });
        removed++;
      }
    } catch { /* gone */ }
  }

  return removed;
}
