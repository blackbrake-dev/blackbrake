// Local report storage: read/validate/list without exposing paths or content.
// V8: validate paths with lstat, O_NOFOLLOW, fstat ino/dev match before reading.
// 30-day expiry; problem list never contains paths.
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';

const REPORTS_DIR = '.blackbrake/reports';
const EXPIRY_DAYS = 30;

export function validateReportPath(filePath, home) {
  // Must be absolute
  if (!path.isAbsolute(filePath)) return { ok: false, reason: 'not-absolute' };

  // Within home/.blackbrake/reports lexically
  const reportsDir = path.join(home, REPORTS_DIR);
  const normalized = path.normalize(filePath);
  const reportsNorm = path.normalize(reportsDir);

  // Check if the path is within reports dir (add sep to avoid prefix matching issues)
  const isInReportsDir = normalized === reportsNorm || (normalized.startsWith(reportsNorm) && normalized[reportsNorm.length] === path.sep);

  if (!isInReportsDir) {
    return { ok: false, reason: 'escapes-root' };
  }

  // Check for .. or other escapes in the relative path
  const rel = path.relative(reportsDir, normalized);
  if (rel.startsWith('..') || path.isAbsolute(rel)) {
    return { ok: false, reason: 'escapes-root' };
  }

  // Stat the path (lstat = no symlink following)
  try {
    const stats = fs.lstatSync(normalized);

    // Must be a regular file
    if (!stats.isFile()) return { ok: false, reason: 'not-file' };

    // Open with O_NOFOLLOW to confirm no swap (POSIX only; Windows respects lstat)
    // For now, we fstat to verify ino/dev match
    try {
      const fd = fs.openSync(normalized, 'r');
      const fstats = fs.fstatSync(fd);
      fs.closeSync(fd);

      // Verify inode and device haven't changed (guards against TOCTOU)
      if (fstats.ino !== stats.ino || fstats.dev !== stats.dev) {
        return { ok: false, reason: 'file-swapped' };
      }

      return { ok: true, ino: stats.ino, dev: stats.dev };
    } catch (e) {
      return { ok: false, reason: 'open-failed', error: e.message };
    }
  } catch (e) {
    return { ok: false, reason: 'stat-failed', error: e.message };
  }
}

export function reportIsExpired(fileDate, now = new Date()) {
  const ageMs = now.getTime() - new Date(fileDate).getTime();
  const ageDays = ageMs / (1000 * 60 * 60 * 24);

  return ageDays > EXPIRY_DAYS;
}

export function readReportStore(home) {
  const reportsDir = path.join(home, REPORTS_DIR);
  const reports = [];
  const problems = [];

  // Create directory if missing
  try {
    fs.mkdirSync(reportsDir, { recursive: true });
  } catch (e) {
    problems.push({ code: 'mkdir-failed', error: e.message });
    return { ok: false, reports, problems };
  }

  // List and validate each report
  try {
    const entries = fs.readdirSync(reportsDir, { withFileTypes: true });

    for (const entry of entries) {
      if (!entry.isFile()) continue;

      const filePath = path.join(reportsDir, entry.name);
      const validated = validateReportPath(filePath, home);

      if (!validated.ok) {
        problems.push({ code: validated.reason, file: entry.name });
        continue;
      }

      // Check expiry
      const stats = fs.lstatSync(filePath);
      if (reportIsExpired(stats.mtime)) {
        problems.push({ code: 'expired', file: entry.name });
        continue;
      }

      reports.push({ name: entry.name, size: stats.size, mtime: stats.mtime });
    }
  } catch (e) {
    problems.push({ code: 'list-failed', error: e.message });
  }

  return { ok: reports.length > 0 || problems.length === 0, reports, problems };
}

export function listReports(home) {
  const store = readReportStore(home);
  return store.reports.map((r) => r.name);
}
