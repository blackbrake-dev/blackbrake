// Where reports live: ~/.blackbrake/reports (guard-design#6x §5.1, V8). Only generated names are
// accepted (no separators, drives, `..` or `~` can match), nothing is read or written through a link,
// the size is checked before reading, and the file read is the same one that was checked (O_NOFOLLOW
// where the system has it, then fstat of the same inode). A report expires 30 days after the time in
// its name. Errors carry a short code, never a path or any content.
import fs from 'node:fs';
import path from 'node:path';
import { assertNoLinks } from '../guard/install.mjs';
import { mayChange } from '../guard/safety.mjs';
import { guardHome, writePrivate } from '../guard/state.mjs';
import { reportFileName } from './build.mjs';
import { isReportFileName, LIMITS } from './validate.mjs';

export const REPORT_DAYS = 30;

// A report a person edited may have grown (CRLF, a BOM): read a little past the limit so the
// validator, not the reader, is the one that says it is too large.
const READ_LIMIT = LIMITS.bytes * 2;

export class ReportError extends Error {
  constructor(code) {
    super(`report: ${code}`);
    this.code = code;
  }
}

export const reportsDir = (home = guardHome()) => path.join(home, 'reports');

const fileOf = (name, home) => {
  if (!isReportFileName(name)) throw new ReportError('bad-name');
  const file = path.join(reportsDir(home), name);

  try { assertNoLinks(file); } catch { throw new ReportError('linked'); }

  return file;
};

// When a report was made, from its name (UTC).
export function reportDate(name) {
  const m = /^(?:product|security)-(\d{4})(\d{2})(\d{2})T(\d{2})(\d{2})(\d{2})Z-/.exec(name);

  return m ? new Date(Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +m[6])) : null;
}

export const reportKind = (name) => (isReportFileName(name) ? name.split('-')[0] : null);

// Writes a validated report under a fresh generated name and returns the name.
export function saveReport(kind, text, { home = guardHome(), now = new Date(), random } = {}) {
  const name = reportFileName(kind, now, random);
  const file = fileOf(name, home);

  if (fs.existsSync(file)) throw new ReportError('exists');
  writePrivate(file, text);

  return name;
}

// The bytes of a report (the validator decides whether they are a valid report).
export function readReport(name, { home = guardHome() } = {}) {
  const file = fileOf(name, home);
  let st;

  try { st = fs.lstatSync(file); } catch { throw new ReportError('not-found'); }

  if (!st.isFile() || st.nlink !== 1) throw new ReportError('not-regular');

  if (st.size > READ_LIMIT) throw new ReportError('too-large');
  let fd;

  try { fd = fs.openSync(file, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0)); } catch { throw new ReportError('not-readable'); }

  try {
    const now = fs.fstatSync(fd);

    if (!now.isFile() || now.ino !== st.ino || now.dev !== st.dev || now.size > READ_LIMIT) throw new ReportError('changed');
    const buf = Buffer.alloc(now.size);
    let read = 0;

    while (read < now.size) {
      const n = fs.readSync(fd, buf, read, now.size - read, read);

      if (!n) break;
      read += n;
    }

    return buf.subarray(0, read);
  } finally {
    fs.closeSync(fd);
  }
}

export function deleteReport(name, { home = guardHome() } = {}) {
  const file = fileOf(name, home);
  let st;

  try { st = fs.lstatSync(file); } catch { throw new ReportError('not-found'); }

  if (!st.isFile()) throw new ReportError('not-regular');
  fs.rmSync(mayChange(path.resolve(file)));
}

// Reports newest first, as { name, kind, date }. Anything else in the folder is left alone and not
// listed. Expired reports are deleted on the way (`prune: false` only lists).
export function listReports({ home = guardHome(), now = new Date(), prune = true } = {}) {
  let names = [];

  try {
    assertNoLinks(reportsDir(home));
    names = fs.readdirSync(reportsDir(home));
  } catch { return []; }

  const out = [];

  for (const name of names.filter(isReportFileName)) {
    const date = reportDate(name);

    if (now - date > REPORT_DAYS * 864e5) {
      if (prune) {
        try { deleteReport(name, { home }); } catch { /* listed again next time */ }
      }

      continue;
    }

    out.push({ name, kind: reportKind(name), date });
  }

  return out.sort((a, b) => b.date - a.date || (a.name < b.name ? 1 : -1));
}
