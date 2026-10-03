import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { readLoopSnapshot } from '../src/guard/spend-state.mjs';
import { sessionHash } from '../src/guard/state.mjs';

const NOW = 1_000_000;

const row = (at = NOW, fingerprint = 'a'.repeat(64)) => JSON.stringify({ at, fingerprint });

const fixture = () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'bb-d5-'));
  const dir = path.join(home, 'spend', 'loops');

  fs.mkdirSync(dir, { recursive: true });

  return { home, dir, file: path.join(dir, `${sessionHash('test-session')}.jsonl`) };
};

test('D5: reads only a bounded tail and drops the first partial row', () => {
  const { home, file } = fixture();
  const tail = `${row(NOW, 'b'.repeat(64))}\n`;
  const prefix = 'x'.repeat(70_000);

  fs.writeFileSync(file, `${prefix}\n${tail}`);
  const originalRead = fs.readFileSync;
  const originalReadSync = fs.readSync;
  let bytes = 0;

  try {
    fs.readFileSync = () => { throw new Error('Unbounded read forbidden'); };

    fs.readSync = (...args) => {
      bytes += args[3];

      return originalReadSync(...args);
    };

    const result = readLoopSnapshot('test-session', home, NOW);

    assert.deepEqual(result?.calls, [{ at: NOW, fingerprint: 'b'.repeat(64) }]);
    assert.ok(bytes > 0 && bytes <= 65_536, `bytes ${bytes}`);
  } finally {
    fs.readFileSync = originalRead;
    fs.readSync = originalReadSync;
  }
});

test('D5: ignores future, expired and malformed records', () => {
  const { home, file } = fixture();

  fs.writeFileSync(file, [row(NOW + 1), row(NOW - 120_001), '{bad', 'null', row(), '{partial'].join('\n'));
  assert.deepEqual(readLoopSnapshot('test-session', home, NOW)?.calls, [{ at: NOW, fingerprint: 'a'.repeat(64) }]);
});

test('D5: refuses linked loop files and directory aliases', (t) => {
  const { home, dir, file } = fixture();
  const outside = fs.mkdtempSync(path.join(os.tmpdir(), 'bb-d5-outside-'));
  const target = path.join(outside, 'target.jsonl');

  fs.writeFileSync(target, `${row()}\n`);
  fs.linkSync(target, file);
  assert.equal(readLoopSnapshot('test-session', home, NOW), null, 'hard link');
  const aliasHome = fs.mkdtempSync(path.join(os.tmpdir(), 'bb-d5-alias-'));

  try { fs.symlinkSync(path.join(home, 'spend'), path.join(aliasHome, 'spend'), process.platform === 'win32' ? 'junction' : 'dir'); }
  catch (error) {
    t.diagnostic(`directory link unavailable: ${error.code}`);

    return;
  }

  fs.writeFileSync(path.join(dir, `${sessionHash('other')}.jsonl`), `${row()}\n`);
  assert.equal(readLoopSnapshot('other', aliasHome, NOW), null, 'directory alias');
});
