// `blackbrake scan`: reads the local files of each AI harness found (history, sessions, config) and
// reports the secrets sitting in them, the way `audit` does for Claude Code. Read-only, bounded,
// never prints a value. Each tool's own credential store (its login token, its SSH key) is skipped:
// that is where a secret is supposed to be, not an exposure.
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { mask } from '../secrets/audit.mjs';
import { CLASSES, classifyOccurrence } from '../secrets/context.mjs';
import { scanText } from '../secrets/engine.mjs';
import { clean } from '../text.mjs';
import { isSensitivePath } from './policy.mjs';
import { harnessDirs } from './registry.mjs';

// Installed plugins and marketplaces are third-party code and docs (their security examples are not
// the user's secrets); `audit` reviews them separately.
export const SKIP_DIRS = /^(node_modules|\.git|models|blobs|cache|Cache|CachedData|GPUCache|Code Cache|extensions|marketplace|marketplaces|plugins|app|backups|logs-archive|bin|lib|site-packages|venv|\.venv)$/;

// A tool's own credential store: login tokens, keys, and IDE connection lock files (they hold the
// token the IDE and the CLI use to talk to each other).
// Only names a tool gives its credential store (auth.json, credentials.toml, tokens.db…), not any
// file that merely mentions a token (token-usage.json, auth.log are scanned).
const OWN_CREDENTIALS = /^(auth|oauth|credentials?|tokens?|keychain|cookies|secrets?|\.credentials|access[-_]tokens?|refresh[-_]tokens?)(\.(json|toml|ya?ml|db|sqlite3?|txt|bin))?$|^id_(rsa|dsa|ecdsa|ed25519)(\.pub)?$|^[^\\/]+\.lock$/i;

const LIMITS = { files: 4000, bytes: 300e6, fileBytes: 5e6, depth: 8, ms: 20000 };

function* walk(dir, depth = 0) {
  if (depth > LIMITS.depth) return;
  let entries = [];

  try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }

  for (const e of entries) {
    const full = path.join(dir, e.name);

    // Dirent types come from lstat: links are neither files nor directories here, so none is followed.
    if (e.isDirectory()) {
      if (!SKIP_DIRS.test(e.name)) yield* walk(full, depth + 1);
    } else if (e.isFile()) yield full;
  }
}

const readSmallText = (file) => {
  try {
    const st = fs.lstatSync(file);

    if (!st.isFile() || st.size === 0 || st.size > LIMITS.fileBytes) return null;
    const buf = fs.readFileSync(file);

    return buf.subarray(0, 4096).includes(0) ? null : buf.toString('utf8');
  } catch { return null; }
};

export const skippedAsOwnCredential = (file) => isSensitivePath(file) || OWN_CREDENTIALS.test(path.basename(file));

// The files a harness keeps that blackbrake reads (and may clean up): never its credential stores.
export function harnessFiles(h, { limit = LIMITS.files } = {}) {
  const out = [];

  for (const dir of harnessDirs(h)) {
    for (const file of walk(dir)) {
      if (out.length >= limit) return out;

      if (!skippedAsOwnCredential(file)) out.push(file);
    }
  }

  return out;
}

export function scanHarness(h, rules, { now = Date.now } = {}) {
  const started = now();
  const found = new Map();
  let files = 0;
  let bytes = 0;
  let skipped = 0;
  let truncated = false;

  for (const dir of harnessDirs(h)) {
    for (const file of walk(dir)) {
      if (files >= LIMITS.files || bytes >= LIMITS.bytes || now() - started > LIMITS.ms) {
        truncated = true;
        break;
      }

      if (skippedAsOwnCredential(file)) {
        skipped++;
        continue;
      }

      const text = readSmallText(file);

      if (text === null) continue;
      files++;
      bytes += text.length;

      for (const f of scanText(rules, text)) {
        const key = crypto.createHash('sha256').update(f.secret).digest('hex');
        const cls = classifyOccurrence({ secret: f.secret, text, index: f.index, filePath: file });
        const entry = found.get(key) ?? { key: key.slice(0, 12), ruleId: f.ruleId, masked: mask(f.secret), classes: new Set(), files: new Set() };
        entry.classes.add(cls);
        entry.files.add(clean(path.relative(dir, file), 160));
        found.set(key, entry);
      }
    }
  }

  const findings = [...found.values()].map((e) => ({
    key: e.key,
    ruleId: e.ruleId,
    // oxlint-disable-next-line anti-slop/no-shape-in-symbol-names -- "shape" is the documented key of the audit finding schema (also in --json); renaming it would change the output.
    shape: e.masked,
    classification: e.classes.has(CLASSES.real) ? CLASSES.real : [...e.classes][0],
    files: [...e.files].slice(0, 5),
    fileCount: e.files.size,
  }));

  return { id: h.id, name: h.name, kind: h.kind, dirs: harnessDirs(h).map((d) => clean(d, 200)), files, bytes, skipped, truncated, findings };
}
