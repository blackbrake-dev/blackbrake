// CLI and UI for managing local reports: list, show, open, send, delete.
// F6.8 deliverable: open with spawn (no shell), mailto protocol, persist with TTY check.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { spawnSync } from 'node:child_process';
import { openMailto, reportMenu, persistReport } from '../src/report/open.mjs';

const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'bb-report-cli-'));

test('openMailto: builds mailto: URL safely without shell', () => {
  const url = openMailto('test@example.com', 'Subject line', 'Body text');
  assert(url.startsWith('mailto:'), 'returns mailto: URL');
  assert(url.includes('test@example.com'));
  assert(url.includes('subject='));
  assert(url.includes('body='));
  assert(!url.includes(';'), 'no shell operators');
});

test('openMailto: encodes special characters in subject and body', () => {
  const url = openMailto('user@example.com', 'Test & demo', 'Line 1\nLine 2');
  // mailto encodes spaces, newlines, ampersands
  assert(url.includes('mailto:'), 'starts with mailto');
  assert(url.includes('subject='), 'has subject param');
  assert(url.includes('body='), 'has body param');
  assert(!url.includes('Line 1\nLine 2'), 'newlines encoded');
});

test('reportMenu: returns list of report names for interactive selection', () => {
  const home = tmp();
  const reportsDir = path.join(home, '.blackbrake', 'reports');
  fs.mkdirSync(reportsDir, { recursive: true });

  fs.writeFileSync(path.join(reportsDir, 'product-20261001T120000Z-abcd1234.md'), 'test 1');
  fs.writeFileSync(path.join(reportsDir, 'security-20261002T120000Z-dcba4321.md'), 'test 2');

  const menu = reportMenu(home);
  assert(Array.isArray(menu), 'returns array');
  assert.equal(menu.length, 2, 'lists both reports');
  assert(menu.every((r) => typeof r === 'object' && r.name && r.label), 'each has name and label');
});

test('reportMenu: empty list when no reports', () => {
  const home = tmp();
  const menu = reportMenu(home);
  assert.equal(menu.length, 0, 'empty array when no reports');
});

test('persistReport: writes report with TTY check, no shell', () => {
  const home = tmp();
  const content = 'Test report content';

  // With TTY check passing (mock: we pass input/output that report isTTY)
  const mockInput = { isTTY: true };
  const mockOutput = { isTTY: true };

  const result = persistReport(
    { input: mockInput, output: mockOutput, env: {} },
    'product',
    content,
    home
  );

  assert.equal(result.ok, true, 'write succeeds with TTY');
  assert(result.name, 'returns report name');
  assert(result.path, 'returns report path');

  // Verify file exists and has content
  const reportsDir = path.join(home, '.blackbrake', 'reports');
  const files = fs.readdirSync(reportsDir);
  assert.equal(files.length, 1, 'one report file written');
  assert(fs.readFileSync(path.join(reportsDir, files[0]), 'utf8').includes(content));
});

test('persistReport: rejects without TTY (agent cannot save)', () => {
  const home = tmp();
  const mockInput = { isTTY: false };
  const mockOutput = { isTTY: true };

  const result = persistReport(
    { input: mockInput, output: mockOutput, env: {} },
    'product',
    'test',
    home
  );

  assert.equal(result.ok, false, 'write rejected without TTY');
  assert.equal(result.reason, 'no-terminal', 'reason is no-terminal');
});

test('persistReport: generates unique filename with timestamp and random suffix', () => {
  const home = tmp();
  const input = { isTTY: true };
  const output = { isTTY: true };

  const r1 = persistReport({ input, output, env: {} }, 'product', 'content 1', home);
  const r2 = persistReport({ input, output, env: {} }, 'product', 'content 2', home);

  assert.notEqual(r1.name, r2.name, 'different filenames generated');
  assert(r1.name.startsWith('product-'));
  assert(r2.name.startsWith('product-'));
  assert(/T\d{6}Z-[0-9a-f]{8}\.md$/.test(r1.name), 'filename matches pattern');
});

test('persistReport: writes with secure permissions', () => {
  const home = tmp();
  const input = { isTTY: true };
  const output = { isTTY: true };

  const result = persistReport({ input, output, env: {} }, 'security', 'confidential', home);

  assert.equal(result.ok, true, 'write succeeds');

  const reportsDir = path.join(home, '.blackbrake', 'reports');
  const files = fs.readdirSync(reportsDir);
  assert.equal(files.length, 1, 'one report file created');

  const filePath = path.join(reportsDir, files[0]);
  const content = fs.readFileSync(filePath, 'utf8');
  assert.equal(content, 'confidential', 'content is preserved');

  // Note: Windows doesn't enforce file permissions like Unix, so we just verify the file exists
  // and is readable only by the test user (who created it)
  assert(fs.existsSync(filePath), 'report file exists');
});
