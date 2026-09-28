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

export function tailTranscript(file, { roots = [], state = {}, maxBytes = 1024 * 1024 } = {}) {
  if (!localAbsolute(file)) throw new Error('Untrusted transcript path');
  const realFile = fs.realpathSync(file);
  const realRoots = roots.filter(localAbsolute).map((root) => fs.realpathSync(root));

  if (!realRoots.some((root) => inside(root, realFile))) throw new Error('Untrusted transcript path');
  const stat = fs.statSync(realFile);

  if (!stat.isFile()) throw new Error('Transcript is not a regular file');
  const identity = identityOf(stat);
  const rotated = state.identity && state.identity !== identity;
  const offset = rotated || stat.size < (state.offset ?? 0) ? 0 : state.offset ?? 0;
  const length = Math.min(maxBytes, Math.max(0, stat.size - offset));
  const bytes = Buffer.alloc(length);
  const fd = fs.openSync(realFile, 'r');

  try { fs.readSync(fd, bytes, 0, length, offset); } finally { fs.closeSync(fd); }

  const newline = bytes.lastIndexOf(0x0a);

  if (newline < 0) return { records: [], state: { offset, size: stat.size, identity } };
  const complete = bytes.subarray(0, newline + 1).toString('utf8');
  const records = [];

  for (const line of complete.split('\n')) {
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
