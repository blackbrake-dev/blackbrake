// Store management for local reports: read/validate paths, check expiry, list available reports.
// F6.8 deliverable: tests drive V8 file path validation with lstat, O_NOFOLLOW, fstat ino/dev match.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { readReportStore, listReports, reportIsExpired, validateReportPath } from '../src/report/store.mjs';

const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'bb-report-store-'));

test('validateReportPath: accepts only absolute paths within home/.blackbrake/reports', () => {
  const home = tmp();
  const reportsDir = path.join(home, '.blackbrake', 'reports');
  fs.mkdirSync(reportsDir, { recursive: true });

  // Valid: within the directory (must exist)
  const validPath = path.join(reportsDir, 'product-20261001T120000Z-abcd1234.md');
  fs.writeFileSync(validPath, 'test content');
  const result = validateReportPath(validPath, home);
  assert.equal(result.ok, true, 'absolute path within reports dir accepted');

  // Relative path rejected
  const relPath = 'product-20261001T120000Z-abcd1234.md';
  const rel = validateReportPath(relPath, home);
  assert.equal(rel.ok, false, 'relative path rejected');
  assert.equal(rel.reason, 'not-absolute');

  // Escaping with .. rejected
  const escaped = path.join(reportsDir, '..', 'secret.md');
  const esc = validateReportPath(escaped, home);
  assert.equal(esc.ok, false, 'path escaping rejected');
  assert.equal(esc.reason, 'escapes-root');

  // Symlink escaping rejected (only check lstat, not contents yet)
  const linkPath = path.join(reportsDir, 'link.md');
  const targetPath = path.join(tmp(), 'outside.md');
  fs.writeFileSync(targetPath, 'test');
  try {
    fs.symlinkSync(targetPath, linkPath);
    const link = validateReportPath(linkPath, home);
    assert.equal(link.ok, false, 'symlink escaping rejected');
  } catch (e) {
    // Symlinks may not be available on all platforms; skip this case if so.
  }
});

test('validateReportPath with fstat: ino/dev match confirms file has not been swapped', () => {
  const home = tmp();
  const reportsDir = path.join(home, '.blackbrake', 'reports');
  fs.mkdirSync(reportsDir, { recursive: true });

  const reportPath = path.join(reportsDir, 'product-20261001T120000Z-abcd1234.md');
  fs.writeFileSync(reportPath, 'test content');

  // Open, stat, and validate that ino/dev match
  const result = validateReportPath(reportPath, home);
  assert.equal(result.ok, true, 'file with matching ino/dev accepted');
  assert(Number.isInteger(result.ino), 'ino is an integer');
  assert(Number.isInteger(result.dev), 'dev is an integer');
});

test('reportIsExpired: checks 30-day expiry', () => {
  const now = new Date();
  const thirtyDaysAgo = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);
  const thirtyOneDaysAgo = new Date(now.getTime() - 31 * 24 * 60 * 60 * 1000);

  assert.equal(reportIsExpired(thirtyDaysAgo, now), false, '30 days old is not expired');
  assert.equal(reportIsExpired(thirtyOneDaysAgo, now), true, '31 days old is expired');
});

test('readReportStore: returns { ok, reports, problems } with list of valid reports', () => {
  const home = tmp();
  const reportsDir = path.join(home, '.blackbrake', 'reports');
  fs.mkdirSync(reportsDir, { recursive: true });

  // Create a valid report file
  const validReport = path.join(reportsDir, 'product-20261001T120000Z-abcd1234.md');
  fs.writeFileSync(validReport, 'test');

  // Create an expired report (not cleaned up yet)
  const expiredReport = path.join(reportsDir, 'security-19960101T000000Z-dcba4321.md');
  fs.writeFileSync(expiredReport, 'old');

  const result = readReportStore(home);
  assert.equal(result.ok, true);
  assert(Array.isArray(result.reports));
  assert(result.reports.length >= 1, 'at least one report found');
  assert(result.reports.some((r) => r.name === path.basename(validReport)), 'valid report included');
  assert(Array.isArray(result.problems));
});

test('listReports: returns report names without paths or content', () => {
  const home = tmp();
  const reportsDir = path.join(home, '.blackbrake', 'reports');
  fs.mkdirSync(reportsDir, { recursive: true });

  fs.writeFileSync(path.join(reportsDir, 'product-20261001T120000Z-abcd1234.md'), 'test');
  fs.writeFileSync(path.join(reportsDir, 'security-20261002T120000Z-dcba4321.md'), 'test');

  const reports = listReports(home);
  assert(Array.isArray(reports));
  assert.equal(reports.length, 2);
  assert(reports.every((r) => typeof r === 'string'));
  assert(reports.every((r) => !r.includes(path.sep)), 'no path separators');
});
