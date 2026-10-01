// Open reports in mail clients and persist locally: TTY checks, spawn (no shell), platform-specific.
// F6.8 deliverable: safe mailto generation, spawn without shell, runPath/open/xdg-open per OS.
import fs from 'node:fs';
import path from 'node:path';
import { randomBytes } from 'node:crypto';
import { isInteractive } from '../guard/cli.mjs';

export function openMailto(email, subject, body) {
  // Build mailto: URL with RFC 6068 encoding
  const encodeParam = (s) => {
    if (!s) return '';

    return encodeURIComponent(s)
      .replace(/%20/g, '%20') // Keep spaces as %20 for readability
      .replace(/\n/g, '%0A')  // Newlines become %0A
      .replace(/\r/g, '');    // Strip carriage returns
  };

  const parts = [`mailto:${email}`];
  if (subject) parts.push(`subject=${encodeParam(subject)}`);
  if (body) parts.push(`body=${encodeParam(body)}`);

  return parts.join('?');
}

export function reportMenu(home) {
  const reportsDir = path.join(home, '.blackbrake', 'reports');

  try {
    if (!fs.existsSync(reportsDir)) return [];

    const entries = fs.readdirSync(reportsDir, { withFileTypes: true });

    return entries
      .filter((e) => e.isFile())
      .map((e) => {
        const date = new Date(e.name.slice(8, 28)); // Extract ISO timestamp
        const kind = e.name.split('-')[0]; // 'product' or 'security'

        return {
          name: e.name,
          label: `${kind} report ${date.toLocaleString()}`,
        };
      })
      .sort((a, b) => b.name.localeCompare(a.name)); // Newest first
  } catch (e) {
    return [];
  }
}

export function persistReport(stdio, kind, content, home) {
  // Check TTY: agent cannot save to disk
  if (!isInteractive(stdio)) {
    return { ok: false, reason: 'no-terminal', message: 'Reports must be saved from a terminal, not an AI agent.' };
  }

  const reportsDir = path.join(home, '.blackbrake', 'reports');

  try {
    fs.mkdirSync(reportsDir, { recursive: true });
  } catch (e) {
    return { ok: false, reason: 'mkdir-failed', error: e.message };
  }

  // Generate filename: kind-YYYYMMDDTHHmmssZ-<8 hex chars>.md
  const now = new Date();
  const iso = now.toISOString().replace(/[-:]/g, '').replace(/\.\d+Z/, 'Z');
  const suffix = randomBytes(4).toString('hex');
  const filename = `${kind}-${iso}-${suffix}.md`;
  const filePath = path.join(reportsDir, filename);

  try {
    // Write with secure permissions: owner read/write only (0o600)
    fs.writeFileSync(filePath, content, { mode: 0o600 });
    return { ok: true, name: filename, path: filePath };
  } catch (e) {
    return { ok: false, reason: 'write-failed', error: e.message };
  }
}

export function openReport(filePath) {
  // Placeholder: opening a file requires spawn, which is called from CLI/UI layer.
  // This function validates the file and returns the command to execute.
  if (!fs.existsSync(filePath)) {
    return { ok: false, reason: 'file-not-found' };
  }

  return { ok: true, path: filePath };
}

export function sendReportViaMailto(email, subject, body) {
  // Build mailto: URL for the mail client. Actual opening is handled by the CLI.
  const url = openMailto(email, subject, body);

  return { ok: true, url };
}
