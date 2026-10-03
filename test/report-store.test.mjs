// F6.8, the report files (guard-design#6x §5.1, V8): generated names only, nothing through a link,
// one name per file, size checked before reading, 30-day expiry, errors that are codes.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { deleteReport, listReports, readReport, REPORT_DAYS, reportDate, reportsDir, saveReport } from '../src/report/store.mjs';

const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'bb-report-store-'));

const TEXT = '# blackbrake report (product)\nVersion: 0.3.0, Date: 2026-10-01\n\n## Summary\nThe menu froze.\n';

const NOW = new Date('2026-10-01T10:00:00Z');

const fixed = (hex) => () => Buffer.from(hex, 'hex');

const codeOf = (fn) => {
  try { fn(); } catch (e) { return e.code; }

  return null;
};

test('a saved report is read back byte for byte, under a generated name in ~/.blackbrake/reports', () => {
  const home = tmp();
  const name = saveReport('product', TEXT, { home, now: NOW, random: fixed('0123abcd') });
  assert.equal(name, 'product-20261001T100000Z-0123abcd.md');
  assert.equal(readReport(name, { home }).toString('utf8'), TEXT);
  assert.deepEqual(fs.readdirSync(reportsDir(home)), [name]);
  assert.equal(reportDate(name).toISOString(), '2026-10-01T10:00:00.000Z');

  if (process.platform !== 'win32') assert.equal(fs.statSync(path.join(reportsDir(home), name)).mode & 0o777, 0o600);
});

test('only generated names: no separators, drives, dot-dot, other names or other kinds', () => {
  const home = tmp();
  saveReport('product', TEXT, { home, now: NOW, random: fixed('0123abcd') });

  for (const name of ['../state.json', '..\\state.json', 'product-20261001T100000Z-0123abcd.md/../x', 'C:\\x.md', '/etc/passwd', 'product.md', 'other-20261001T100000Z-0123abcd.md', 'product-20261301T100000Z-0123abcd.md', 'PRODUCT-20261001T100000Z-0123abcd.md', '', null]) {
    assert.equal(codeOf(() => readReport(name, { home })), 'bad-name', String(name));
    assert.equal(codeOf(() => deleteReport(name, { home })), 'bad-name', String(name));
  }
});

test('reading refuses a missing file, a folder, a second name (hard link) and a file too large', () => {
  const home = tmp();
  const dir = reportsDir(home);
  assert.equal(codeOf(() => readReport('product-20261001T100000Z-0123abcd.md', { home })), 'not-found');
  fs.mkdirSync(path.join(dir, 'product-20261001T100000Z-0000000a.md'), { recursive: true });
  assert.equal(codeOf(() => readReport('product-20261001T100000Z-0000000a.md', { home })), 'not-regular');
  const name = saveReport('product', TEXT, { home, now: NOW, random: fixed('0000000b') });
  fs.linkSync(path.join(dir, name), path.join(home, 'elsewhere.md'));
  assert.equal(codeOf(() => readReport(name, { home })), 'not-regular', 'a hard link is a second name for the file');
  fs.writeFileSync(path.join(dir, 'product-20261001T100000Z-0000000c.md'), 'x'.repeat(20000));
  assert.equal(codeOf(() => readReport('product-20261001T100000Z-0000000c.md', { home })), 'too-large');
});

test('a reports folder that is a link is neither read nor written', (t) => {
  const home = tmp();
  const target = tmp();

  try { fs.symlinkSync(target, reportsDir(home), 'junction'); } catch {
    t.skip('no link rights here');

    return;
  }

  assert.equal(codeOf(() => saveReport('product', TEXT, { home, now: NOW })), 'linked');
  assert.equal(codeOf(() => readReport('product-20261001T100000Z-0123abcd.md', { home })), 'linked');
  assert.deepEqual(listReports({ home, now: NOW }), []);
  assert.deepEqual(fs.readdirSync(target), [], 'nothing was written through it');
});

test('list: newest first, other files ignored and untouched, expired reports deleted (only when asked)', () => {
  const home = tmp();
  const dir = reportsDir(home);
  const old = saveReport('product', TEXT, { home, now: new Date(NOW - (REPORT_DAYS + 1) * 864e5), random: fixed('00000001') });
  const a = saveReport('security', TEXT, { home, now: new Date(NOW - 864e5), random: fixed('00000002') });
  const b = saveReport('product', TEXT, { home, now: NOW, random: fixed('00000003') });
  fs.writeFileSync(path.join(dir, 'notes.txt'), 'mine');
  assert.deepEqual(listReports({ home, now: NOW, prune: false }).map((r) => r.name), [b, a], 'expired not listed');
  assert.ok(fs.existsSync(path.join(dir, old)), 'prune: false deletes nothing');
  assert.deepEqual(listReports({ home, now: NOW }).map((r) => [r.name, r.kind]), [[b, 'product'], [a, 'security']]);
  assert.equal(fs.existsSync(path.join(dir, old)), false, 'expired one deleted');
  assert.ok(fs.existsSync(path.join(dir, 'notes.txt')), 'a file blackbrake did not write is left alone');
  deleteReport(a, { home });
  assert.deepEqual(listReports({ home, now: NOW }).map((r) => r.name), [b]);
  assert.deepEqual(listReports({ home: tmp(), now: NOW }), [], 'no folder yet');
});
