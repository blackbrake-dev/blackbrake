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

const inside = (root, file) => {
  const rel = path.relative(root, file);

  return rel === '' || (!rel.startsWith(`..${path.sep}`) && rel !== '..' && !path.isAbsolute(rel));
};

const identityOf = (stat) => crypto.createHash('sha256').update(`${stat.dev}:${stat.ino}`).digest('hex').slice(0, 16);

// Only a local absolute path lexically under a known root, reached without links. Nothing is resolved
// or opened before that check, so a planted link (or a remote share behind one) is never followed.
// The root is the user's own configuration and may itself be a link; below it nothing may be.
const trustedFile = (file, roots) => {
  if (!localAbsolute(file)) throw new Error('Untrusted transcript path');
  const target = path.resolve(file);
  const root = roots.filter(localAbsolute).map((r) => path.resolve(r)).find((r) => inside(r, target));

  if (!root) throw new Error('Untrusted transcript path');
  let current = fs.realpathSync(root);
  let stat = null;

  for (const part of path.relative(root, target).split(path.sep).filter(Boolean)) {
    current = path.join(current, part);
    stat = fs.lstatSync(current);

    if (stat.isSymbolicLink()) throw new Error('Untrusted transcript path');
  }

  if (!stat?.isFile()) throw new Error('Transcript is not a regular file');

  return current;
};

// Non-blocking and no final link on POSIX: a file swapped for a FIFO or link after the check is not
// waited on or followed; the descriptor is checked again before reading.
const OPEN = fs.constants.O_RDONLY | (fs.constants.O_NONBLOCK ?? 0) | (fs.constants.O_NOFOLLOW ?? 0);

// fromEnd: the first sight of a transcript starts at its last complete line; earlier history never
// belongs to a live episode (a resumed or long session would otherwise feed it in 1 MiB steps).
export function tailTranscript(file, { roots = [], state = {}, maxBytes = 1024 * 1024, fromEnd = false } = {}) {
  const fd = fs.openSync(trustedFile(file, roots), OPEN);
  let stat;
  let bytes;
  let offset;

  try {
    stat = fs.fstatSync(fd);

    if (!stat.isFile()) throw new Error('Transcript is not a regular file');
    const reset = (state.identity && state.identity !== identityOf(stat)) || stat.size < (state.offset ?? 0);

    const start = fromEnd && !state.identity ? Math.max(0, stat.size - maxBytes) : null;

    offset = start ?? (reset ? 0 : state.offset ?? 0);
    state = start > 0 ? { skip: true } : reset ? {} : state;
    bytes = Buffer.alloc(Math.min(maxBytes, Math.max(0, stat.size - offset)));
    fs.readSync(fd, bytes, 0, bytes.length, offset);
  } finally { fs.closeSync(fd); }

  const identity = identityOf(stat);
  // A line longer than one read would stall the tail for the rest of the session: it is skipped up
  // to its newline, never buffered (in practice a large pasted image or tool result, not usage).
  let from = 0;

  if (state.skip) {
    const end = bytes.indexOf(0x0a);

    if (end < 0) return { records: [], state: { offset: offset + bytes.length, size: stat.size, identity, skip: true } };
    from = end + 1;
  }

  const newline = bytes.lastIndexOf(0x0a);

  if (newline < from) {
    const skip = from === 0 && bytes.length > 0 && bytes.length === maxBytes;

    return { records: [], state: { offset: offset + (skip ? bytes.length : from), size: stat.size, identity, skip } };
  }

  const records = [];

  for (const line of bytes.subarray(from, newline + 1).toString('utf8').split('\n')) {
    if (!line) continue;

    try { records.push(JSON.parse(line)); } catch { /* malformed transcript lines are ignored */ }
  }

  return { records, state: { offset: offset + newline + 1, size: stat.size, identity } };
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
