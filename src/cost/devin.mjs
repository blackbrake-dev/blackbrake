// Devin spend warning (F5.5). Devin rewrites each session as one complete JSON document and bills
// in ACU, so this measures tokens per episode without claiming a dollar cost. Only numbers and
// hashes leave the transcript directory.
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { t } from '../i18n.mjs';
import { isLocalPath } from '../text.mjs';
import { baselineFromEpisodes } from '../guard/spend.mjs';
import { appendLog, guardHome, writePrivate } from '../guard/state.mjs';

const MIB = 1024 * 1024;

export const DEVIN_MAX_BYTES = 32 * MIB;

const finite = (value) => Number.isFinite(value) && value >= 0;

// oxlint-disable-next-line anti-slop/no-runtime-typeof -- Environment values are an untrusted I/O boundary.
const localAbsolute = (value) => typeof value === 'string' && path.isAbsolute(value) && isLocalPath(value);

// Devin follows the operating system's per-user config directory. Windows is verified locally;
// the macOS and Linux locations follow their platform conventions and remain natively unverified.
export const devinRoot = (env = process.env, { platform = process.platform, home = os.homedir() } = {}) => {
  let fallback;
  let configured;

  if (platform === 'win32') {
    fallback = path.join(home, 'AppData', 'Roaming');
    configured = env.APPDATA;
  } else if (platform === 'darwin') {
    fallback = path.join(home, 'Library', 'Application Support');
  } else {
    fallback = path.join(home, '.config');
    configured = env.XDG_CONFIG_HOME;
  }

  const base = localAbsolute(configured) ? configured : fallback;

  return path.join(base, 'devin', 'cli', 'transcripts');
};

const hash = (...parts) => crypto.createHash('sha256').update(parts.map((part) => String(part)).join('\0')).digest('hex');

// oxlint-disable-next-line anti-slop/no-runtime-typeof -- Transcript JSON is an untrusted I/O boundary.
const stepHash = (session, step, index) => hash(session, typeof step?.step_id === 'string' ? step.step_id : `index:${index}`);

const metric = (value) => finite(value) ? value : 0;

// `source=user` is the real user boundary. `source=system` contains injected context and agent
// steps contain the token metrics. Repeated step ids are counted only once.
export function episodesFromDevin(document, { fallbackSession = 'unknown-session' } = {}) {
  if (!Array.isArray(document?.steps)) return { episodes: [] };
  // oxlint-disable-next-line anti-slop/no-runtime-typeof -- Transcript JSON is an untrusted I/O boundary.
  const session = typeof document.session_id === 'string' ? document.session_id : fallbackSession;
  const episodes = [];
  const seen = new Set();
  let open = null;

  for (const [index, step] of document.steps.entries()) {
    const stepId = stepHash(session, step, index);

    if (seen.has(stepId)) continue;
    seen.add(stepId);

    if (step?.source === 'user') {
      if (open) episodes.push({ ...open, closed: true });
      open = { id: stepId, fingerprint: stepId.slice(0, 16), tokens: 0, cached: 0, cacheCreation: 0 };
    }

    if (!open) continue;
    const value = step?.metrics;

    // oxlint-disable-next-line anti-slop/no-runtime-typeof -- Transcript JSON is an untrusted I/O boundary.
    if (!value || typeof value !== 'object') continue;
    open.tokens += metric(value.prompt_tokens) + metric(value.completion_tokens);
    open.cached += metric(value.cached_tokens);
    open.cacheCreation += metric(value.extra?.cache_creation_input_tokens);
  }

  if (open) episodes.push({ ...open, closed: false });

  return { episodes };
}

const validRoot = (root) => {
  if (!localAbsolute(root)) return false;

  try {
    const stat = fs.lstatSync(root);

    return stat.isDirectory() && !stat.isSymbolicLink();
  } catch {
    return false;
  }
};

// Session JSON files are direct children of the transcript folder. Links and nested junctions are
// never traversed.
export function listDevinSessions(root = devinRoot(), { maxFiles = 5000 } = {}) {
  if (!validRoot(root)) return [];
  let entries;

  try { entries = fs.readdirSync(root, { withFileTypes: true }); } catch { return []; }

  return entries.filter((entry) => entry.isFile() && entry.name.endsWith('.json')).slice(0, maxFiles).map((entry) => path.join(root, entry.name)).sort();
}

const signature = (stat) => `${stat.dev}:${stat.ino}:${stat.size}:${stat.mtimeMs}`;

const safeStat = (file) => {
  try {
    const stat = fs.lstatSync(file);

    if (!stat.isFile() || stat.isSymbolicLink()) return null;

    return stat;
  } catch {
    return null;
  }
};

const within = (root, file) => {
  const relative = path.relative(root, file);

  return relative !== '' && !relative.startsWith(`..${path.sep}`) && relative !== '..' && !path.isAbsolute(relative);
};

// The descriptor is checked against lstat after O_NOFOLLOW open. A fixed-size buffer prevents a
// file that grows during the read from exceeding the 32 MiB ceiling.
function readSession(file, root, stat, maxBytes) {
  if (!within(root, file) || !stat) return { status: 'invalid' };

  if (stat.size > maxBytes) return { status: 'limit', bytes: stat.size, signature: signature(stat) };

  let descriptor;

  try {
    descriptor = fs.openSync(file, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0) | (fs.constants.O_NONBLOCK ?? 0));
    const opened = fs.fstatSync(descriptor);

    if (!opened.isFile() || opened.dev !== stat.dev || opened.ino !== stat.ino || opened.size !== stat.size || opened.size > maxBytes) return { status: 'invalid' };
    const buffer = Buffer.alloc(opened.size);
    let offset = 0;

    while (offset < buffer.length) {
      const read = fs.readSync(descriptor, buffer, offset, buffer.length - offset, offset);

      if (!read) break;
      offset += read;
    }

    if (offset !== buffer.length) return { status: 'invalid' };
    const document = JSON.parse(buffer.toString('utf8'));

    if (!Array.isArray(document?.steps)) return { status: 'invalid' };

    return { status: 'ok', document, signature: signature(opened) };
  } catch {
    return { status: 'invalid' };
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
  }
}

const baselineOf = (values) => {
  const { n, p50, p90, ready } = baselineFromEpisodes([...values].map((cost) => ({ cost })), 'devin');

  return { n, p50, p90, ready };
};

function scanHistory(root, maxBytes) {
  const files = new Map();
  const counted = new Map();
  let sessions = 0;

  for (const file of listDevinSessions(root)) {
    const stat = safeStat(file);
    const read = readSession(file, root, stat, maxBytes);

    if (read.status !== 'ok') {
      files.set(file, { signature: read.signature ?? (stat ? signature(stat) : ''), limited: read.status === 'limit' });
      continue;
    }

    const { episodes } = episodesFromDevin(read.document, { fallbackSession: hash(file) });

    sessions++;

    for (const episode of episodes) if (!counted.has(episode.id)) counted.set(episode.id, episode.tokens);
    files.set(file, {
      signature: read.signature,
      // The episode already open when the watcher starts is deliberately never warned about.
      suppressed: episodes.length && !episodes.at(-1).closed ? episodes.at(-1).id : null,
      limited: false,
    });
  }

  return { files, counted, sessions };
}

export function summarizeDevinHistory({ root = devinRoot(), maxBytes = DEVIN_MAX_BYTES } = {}) {
  const { counted, sessions } = scanHistory(root, maxBytes);
  const tokens = [...counted.values()];
  const baseline = baselineOf(tokens);

  return {
    harness: 'devin',
    sessions,
    episodes: tokens.length,
    baseline,
    aboveP90: baseline.ready ? tokens.filter((value) => value > baseline.p90).length : 0,
  };
}

export function createDevinSpend({ home = guardHome(), root = devinRoot(), notifier = null, maxBytes = DEVIN_MAX_BYTES } = {}) {
  const history = scanHistory(root, maxBytes);
  const files = history.files;
  const counted = history.counted;
  const alerted = new Set();
  let baseline = baselineOf(counted.values());
  let saved = '';

  const save = () => {
    const text = `${JSON.stringify({ baseline, maxBytes })}\n`;

    if (text === saved) return;
    writePrivate(path.join(home, 'spend', 'devin.json'), text);
    saved = text;
  };

  const sessionKey = (file) => `devin:${hash(file)}`;

  const logLimit = (file, bytes) => {
    appendLog([{ ev: 'Devin', kind: 'spend-limit', action: 'skipped', harness: 'devin', bytes, maxBytes }], sessionKey(file), home);
  };

  const warn = (file, episode) => {
    alerted.add(episode.id);

    const entry = {
      ev: 'Devin', kind: 'spend-tokens', action: 'warned', harness: 'devin', tokens: episode.tokens, cached: episode.cached,
      cacheCreation: episode.cacheCreation, p90: baseline.p90, n: baseline.n, fingerprint: episode.fingerprint,
    };

    appendLog([entry], sessionKey(file), home);

    const body = t('This Codex episode is at {tokens} tokens; your p90 is {p90}.', { tokens: episode.tokens, p90: baseline.p90 }).replaceAll('Codex', 'Devin');

    try { notifier?.('blackbrake · Devin', body); } catch { /* the log keeps it */ }

    return entry;
  };

  save();

  return {
    tick() {
      const alerts = [];
      const listed = listDevinSessions(root);
      const present = new Set(listed);

      for (const file of files.keys()) if (!present.has(file)) files.delete(file);

      for (const file of listed) {
        const stat = safeStat(file);

        if (!stat) continue;
        const current = signature(stat);
        const known = files.get(file);

        // Whole JSON documents are opened only after mtime or size/identity changes.
        if (known?.signature === current) continue;
        const read = readSession(file, root, stat, maxBytes);

        if (read.status === 'limit') {
          if (!known?.limited || known.signature !== read.signature) logLimit(file, read.bytes);
          files.set(file, { signature: read.signature, limited: true, suppressed: known?.suppressed ?? null });
          continue;
        }

        if (read.status !== 'ok') continue;
        const { episodes } = episodesFromDevin(read.document, { fallbackSession: hash(file) });
        const suppressed = known?.suppressed ?? null;
        let changed = false;

        for (const episode of episodes) {
          if (episode.id === suppressed) continue;

          if (episode.closed && !counted.has(episode.id)) {
            counted.set(episode.id, episode.tokens);
            changed = true;
          }

          if (!episode.closed && !alerted.has(episode.id) && baseline.ready && episode.tokens > baseline.p90) alerts.push(warn(file, episode));
        }

        if (changed) baseline = baselineOf(counted.values());
        files.set(file, { signature: read.signature, suppressed, limited: false });
      }

      save();

      return alerts;
    },
  };
}

// Manual probe: aggregate counts and token percentiles only.
if (process.argv[1] && path.resolve(process.argv[1]) === path.resolve(fileURLToPath(import.meta.url))) {
  process.stdout.write(`${JSON.stringify(summarizeDevinHistory())}\n`);
}
