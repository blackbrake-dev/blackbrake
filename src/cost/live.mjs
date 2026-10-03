// Incremental local transcript reader. Returned records stay in memory; persisted callers must
// retain aggregates only.
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createCostAnalyzer, createUsageLedger } from './analyzer.mjs';
import { defaultRoot, describeFile, listTranscripts, readTranscript } from '../transcripts.mjs';
import { baselineFromEpisodes } from '../guard/spend.mjs';

const localAbsolute = (file) => path.isAbsolute(file) && !/^[\\/]{2}/.test(file);

const CLAUDE_SESSION_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

const CLAUDE_SUBAGENT_FILE = /^agent-[0-9a-f]{8,64}\.jsonl$/i;

const inside = (root, file) => {
  const rel = path.relative(root, file);

  return rel === '' || (!rel.startsWith(`..${path.sep}`) && rel !== '..' && !path.isAbsolute(rel));
};

const identityOf = (stat) => crypto.createHash('sha256').update(`${stat.dev}:${stat.ino}`).digest('hex').slice(0, 16);

// Only a local absolute path lexically under a known root or its canonical spelling, reached
// without links below that root. The target is never resolved before checking its path, so a
// planted link (or a remote share behind one) is never followed.
// The root is the user's own configuration and may itself be a link; below it nothing may be.
const trustedFile = (file, roots) => {
  if (!localAbsolute(file)) throw new Error('Untrusted transcript path');
  const target = path.resolve(file);
  let root;
  let current;

  for (const candidate of roots.filter(localAbsolute)) {
    const lexical = path.resolve(candidate);
    let canonical;

    // Known configuration roots alone may be resolved. macOS /var and /private/var are two
    // spellings of one root; enumeration returns the latter and reads must revalidate its children.
    try { canonical = fs.realpathSync(lexical); } catch { continue; }

    if (!localAbsolute(canonical)) continue;

    if (inside(lexical, target)) root = lexical;
    else if (inside(canonical, target)) root = canonical;
    else continue;
    current = canonical;

    break;
  }

  if (!root) throw new Error('Untrusted transcript path');
  let stat = null;

  for (const part of path.relative(root, target).split(path.sep).filter(Boolean)) {
    current = path.join(current, part);
    stat = fs.lstatSync(current);

    if (stat.isSymbolicLink()) throw new Error('Untrusted transcript path');
  }

  if (!stat?.isFile()) throw new Error('Transcript is not a regular file');

  return current;
};

// Real Claude Code data (checked before F5.7) keeps direct agent-<hex>.jsonl children under
// <project>/<parent session UUID>/subagents. Enumerate only that observed layout: no recursive walk,
// no journals, no link/junction traversal, and bounded entries/files. The returned paths are used in
// memory only; callers persist an HMAC key, never a path or agent id.
export function listClaudeSubagentFiles(file, sessionId, {
  roots = [], maxEntries = 256, maxFiles = 128, maxFileBytes = 32 * 1024 * 1024,
} = {}) {
  if (!CLAUDE_SESSION_ID.test(String(sessionId ?? ''))) return [];
  const main = trustedFile(file, roots);

  if (path.basename(main) !== `${sessionId}.jsonl`) return [];

  const realRoots = roots.flatMap((root) => {
    if (!localAbsolute(root)) return [];

    try { return [fs.realpathSync(root)]; } catch { return []; }
  });

  const root = realRoots.find((candidate) => inside(candidate, main));

  if (!root) return [];
  const relative = path.relative(root, main).split(path.sep).filter(Boolean);

  // A parent transcript is a direct child of one project directory. This prevents a crafted
  // transcript deeper in the tree from selecting an unrelated sibling as its child-session root.
  if (relative.length !== 2) return [];
  const sessionRoot = path.join(path.dirname(main), sessionId);
  const childRoot = path.join(sessionRoot, 'subagents');
  let sessionStat;
  let rootStat;

  try {
    sessionStat = fs.lstatSync(sessionRoot);
    rootStat = fs.lstatSync(childRoot);
  } catch { return []; }

  if (sessionStat.isSymbolicLink() || !sessionStat.isDirectory() || rootStat.isSymbolicLink() || !rootStat.isDirectory()) return [];
  const entriesLimit = Math.max(0, Math.min(4096, Math.trunc(maxEntries)));
  const filesLimit = Math.max(0, Math.min(1024, Math.trunc(maxFiles)));
  const bytesLimit = Number.isFinite(maxFileBytes) && maxFileBytes >= 0 ? maxFileBytes : 0;
  const out = [];
  let dir;

  try {
    dir = fs.opendirSync(childRoot);

    for (let seen = 0; seen < entriesLimit && out.length < filesLimit; seen++) {
      const entry = dir.readSync();

      if (!entry) break;

      if (!CLAUDE_SUBAGENT_FILE.test(entry.name) || !entry.isFile() || entry.isSymbolicLink()) continue;
      const child = path.join(childRoot, entry.name);
      let stat;

      try { stat = fs.lstatSync(child); } catch { continue; }

      if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink > 1 || stat.size > bytesLimit) continue;
      out.push({ file: child, size: stat.size, identity: identityOf(stat), modified: stat.mtimeMs, changed: stat.ctimeMs });
    }
  } catch {
    return [];
  } finally {
    try { dir?.closeSync(); } catch { /* already closed or unreadable */ }
  }

  return out;
}

// Non-blocking and no final link on POSIX: a file swapped for a FIFO or link after the check is not
// waited on or followed; the descriptor is checked again before reading.
const OPEN = fs.constants.O_RDONLY | (fs.constants.O_NONBLOCK ?? 0) | (fs.constants.O_NOFOLLOW ?? 0);

// fromEnd: the first sight of a transcript starts at its last complete line; earlier history never
// belongs to a live episode (a resumed or long session would otherwise feed it in 1 MiB steps).
export function tailTranscript(file, { roots = [], state = {}, maxBytes = 1024 * 1024, fromEnd = false } = {}) {
  const fd = fs.openSync(trustedFile(file, roots), OPEN);
  let stat;
  let bytes;
  let bytesRead;
  let offset;

  try {
    stat = fs.fstatSync(fd);

    if (!stat.isFile()) throw new Error('Transcript is not a regular file');
    const identity = identityOf(stat);

    const rewritten = state.identity === identity && state.size === stat.size
      && ((Number.isFinite(state.modified) && state.modified !== stat.mtimeMs) || (Number.isFinite(state.changed) && state.changed !== stat.ctimeMs));

    const reset = (state.identity && state.identity !== identity) || stat.size < (state.offset ?? 0) || rewritten;

    const start = fromEnd && !state.identity ? Math.max(0, stat.size - maxBytes) : null;

    offset = start ?? (reset ? 0 : state.offset ?? 0);
    state = start > 0 ? { skip: true } : reset ? {} : state;
    bytes = Buffer.alloc(Math.min(maxBytes, Math.max(0, stat.size - offset)));
    bytesRead = fs.readSync(fd, bytes, 0, bytes.length, offset);
    bytes = bytes.subarray(0, bytesRead);
  } finally { fs.closeSync(fd); }

  const identity = identityOf(stat);
  const metadata = { size: stat.size, identity, modified: stat.mtimeMs, changed: stat.ctimeMs };
  // A line longer than one read would stall the tail for the rest of the session: it is skipped up
  // to its newline, never buffered (in practice a large pasted image or tool result, not usage).
  let from = 0;

  if (state.skip) {
    const end = bytes.indexOf(0x0a);

    if (end < 0) return { records: [], bytesRead, state: { offset: offset + bytes.length, ...metadata, skip: true } };
    from = end + 1;
  }

  const newline = bytes.lastIndexOf(0x0a);

  if (newline < from) {
    const skip = from === 0 && bytes.length > 0 && bytes.length === maxBytes;

    return { records: [], bytesRead, state: { offset: offset + (skip ? bytes.length : from), ...metadata, skip } };
  }

  const records = [];

  for (const line of bytes.subarray(from, newline + 1).toString('utf8').split('\n')) {
    if (!line) continue;

    try { records.push(JSON.parse(line)); } catch { /* malformed transcript lines are ignored */ }
  }

  return { records, bytesRead, state: { offset: offset + newline + 1, ...metadata } };
}

export async function summarizeHistory({ root = defaultRoot(), harness = 'claude' } = {}) {
  if (harness !== 'claude') return { harness, episodes: 0, baseline: baselineFromEpisodes([], harness), aboveP90: 0 };
  const analyzer = createCostAnalyzer();

  for (const file of listTranscripts(root)) {
    analyzer.onFile(describeFile(root, file));

    for await (const { record } of readTranscript(file)) analyzer.onRecord(record);
  }

  const result = analyzer.finish();
  const baseline = baselineFromEpisodes(result.episodeCosts, harness);

  return {
    harness,
    episodes: result.episodes,
    baseline,
    aboveP90: baseline.ready ? result.episodeCosts.filter((episode) => episode.cost > baseline.p90).length : 0,
  };
}

export function accountTranscriptRecords(records, previous = {}, secret) {
  if (!secret) throw new TypeError('Usage ledger secret is required');

  const keyOf = (record, msg) => {
    const id = msg.id ?? record.requestId ?? null;

    return id === null ? null : crypto.createHmac('sha256', secret).update(String(id)).digest('hex');
  };

  const ledger = createUsageLedger({ keyOf, entries: previous.responses ?? [] });
  let costDelta = 0;
  let responseDelta = 0;
  let tokensDelta = 0;

  for (const record of records) {
    const msg = record?.message;

    if (msg?.role !== 'assistant' || !msg.usage) continue;

    const result = ledger.account(record, msg);
    costDelta += result.delta;
    tokensDelta += result.sizeDelta;

    if (result.first) responseDelta++;
  }

  return { costDelta, responseDelta, tokensDelta, responses: ledger.snapshot() };
}

// Manual/bootstrap probe: intentionally emits aggregates only.
if (process.argv[1] && path.resolve(process.argv[1]) === path.resolve(fileURLToPath(import.meta.url))) {
  const summary = await summarizeHistory();

  process.stdout.write(`${JSON.stringify(summary)}\n`);
}
