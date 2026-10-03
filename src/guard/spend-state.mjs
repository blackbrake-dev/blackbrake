import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { guardHome, sessionHash, writePrivate } from './state.mjs';

const readJson = (file) => { try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch { return null; } };

const spendDir = (home) => path.join(home, 'spend');

const safeBaseline = (harness, value) => ({
  harness,
  n: Number.isInteger(value?.n) && value.n >= 0 ? value.n : 0,
  p50: Number.isFinite(value?.p50) && value.p50 >= 0 ? value.p50 : 0,
  p90: Number.isFinite(value?.p90) && value.p90 >= 0 ? value.p90 : 0,
  ready: value?.ready === true,
});

export function getSpendBaseline(harness, home = guardHome()) {
  const value = readJson(path.join(spendDir(home), 'baseline.json'))?.[harness];

  return value ? safeBaseline(harness, value) : null;
}

export function setSpendBaseline(harness, baseline, home = guardHome()) {
  if (!/^[a-z][a-z0-9-]{0,31}$/.test(harness)) throw new TypeError('Invalid harness');

  const file = path.join(spendDir(home), 'baseline.json');
  const baselines = readJson(file) ?? {};

  writePrivate(file, `${JSON.stringify({ ...baselines, [harness]: safeBaseline(harness, baseline) }, null, 2)}\n`);
}

export function appendSpendEpisode(episode, home = guardHome()) {
  // oxlint-disable-next-line anti-slop/no-runtime-typeof -- Public persistence boundary: only an ISO timestamp may cross it.
  const at = typeof episode?.at === 'string' && /^\d{4}-\d{2}-\d{2}T/.test(episode.at) ? episode.at : new Date().toISOString();

  const safe = {
    at,
    harness: /^[a-z][a-z0-9-]{0,31}$/.test(episode?.harness) ? episode.harness : 'unknown',
    cost: Number.isFinite(episode?.cost) && episode.cost >= 0 ? episode.cost : 0,
    responses: Number.isInteger(episode?.responses) && episode.responses >= 0 ? episode.responses : 0,
  };

  if (['valid', 'invalid', 'unrated'].includes(episode?.label)) safe.label = episode.label;
  writePrivate(path.join(spendDir(home), 'episodes.jsonl'), `${JSON.stringify(safe)}\n`, 'a');
}

export function getSpendSecret(home = guardHome()) {
  const file = path.join(spendDir(home), 'key');
  let encoded = null;

  try { encoded = fs.readFileSync(file, 'utf8').trim(); } catch { /* create below */ }

  if (/^[A-Za-z0-9+/]{43}=$/.test(encoded ?? '')) return Buffer.from(encoded, 'base64');

  const secret = crypto.randomBytes(32);

  writePrivate(file, `${secret.toString('base64')}\n`);

  return secret;
}

export const getInventorySnapshot = (home = guardHome()) => {
  const items = readJson(path.join(spendDir(home), 'inventory.json'))?.items;

  return Array.isArray(items) ? items.filter((item) => /^[a-f0-9]{64}$/.test(item?.id) && /^[a-f0-9]{64}$/.test(item?.digest)) : [];
};

export function setInventorySnapshot(items, home = guardHome()) {
  const safe = items.flatMap((item) => /^[a-f0-9]{64}$/.test(item?.id) && /^[a-f0-9]{64}$/.test(item?.digest) ? [{ id: item.id, digest: item.digest }] : []);

  writePrivate(path.join(spendDir(home), 'inventory.json'), `${JSON.stringify({ items: safe }, null, 2)}\n`);
}

const loopFile = (home, id) => path.join(spendDir(home), 'loops', `${sessionHash(id)}.jsonl`);

export function readLoopSnapshot(id, home = guardHome(), now = Date.now()) {
  let text = '';
  let fd;

  try {
    if (!path.isAbsolute(home) || /^[\\/]{2}/.test(home) || fs.lstatSync(home).isSymbolicLink()) return null;
    const root = fs.realpathSync(home);
    const file = loopFile(root, id);
    let current = root;
    let expected;

    for (const part of path.relative(root, file).split(path.sep)) {
      current = path.join(current, part);
      expected = fs.lstatSync(current);

      if (expected.isSymbolicLink()) return null;
    }

    if (!expected.isFile() || expected.nlink > 1) return null;
    const flags = fs.constants.O_RDONLY | (fs.constants.O_NONBLOCK ?? 0) | (fs.constants.O_NOFOLLOW ?? 0);

    fd = fs.openSync(file, flags);
    const stat = fs.fstatSync(fd);

    if (!stat.isFile() || stat.nlink > 1 || stat.dev !== expected.dev || stat.ino !== expected.ino || fs.realpathSync(file) !== file) return null;
    const offset = Math.max(0, stat.size - 65_536);
    const buffer = Buffer.alloc(Math.min(stat.size, 65_536));
    const length = fs.readSync(fd, buffer, 0, buffer.length, offset);

    text = buffer.subarray(0, length).toString('utf8');

    if (offset > 0) {
      const newline = text.indexOf('\n');

      text = newline < 0 ? '' : text.slice(newline + 1);
    }
  } catch { return null; }
  finally { if (fd !== undefined) fs.closeSync(fd); }

  const rows = [];

  for (const line of text.trim().split('\n').slice(-32)) {
    try {
      const row = JSON.parse(line);

      if (Number.isFinite(row?.at) && row.at <= now && now - row.at <= 120_000 && /^[a-f0-9]{64}$/.test(row?.fingerprint)) rows.push(row);
    } catch { /* a partial final line is ignored */ }
  }

  const calls = rows.slice(-8).map(({ at, fingerprint }) => ({ at, fingerprint }));
  const alerted = rows.flatMap((row) => row.alert === true ? [row.fingerprint] : []);

  return { calls, alerted };
}

export function appendLoopCall(id, call, home = guardHome()) {
  const safe = {
    at: Number.isFinite(call?.at) ? call.at : Date.now(),
    fingerprint: /^[a-f0-9]{64}$/.test(call?.fingerprint) ? call.fingerprint : '',
    alert: call?.alert === true,
  };

  if (!safe.fingerprint) throw new TypeError('Invalid loop fingerprint');

  writePrivate(loopFile(home, id), `${JSON.stringify(safe)}\n`, 'a');
}

export function resetLoopCalls(id, home = guardHome()) {
  writePrivate(loopFile(home, id), '');
}
