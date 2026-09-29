// The background watcher (`watch-main.mjs --background`): keeps blackbrake running for every local
// AI harness, including the ones without hooks (Ollama, Hermes, OpenCode…). Every few seconds it
//   - notices which harnesses are running (the operating system's process list),
//   - follows their history and session files as they grow and warns about real secrets in them,
//   - opens the alerts window when a harness starts, if no window is open,
//   - notifies high and maximum alerts from any agent when no alerts window is open to do it,
//   - warns once when a Codex episode goes above the user's own p90 of tokens per episode.
// Local only; it writes nothing but guard's own log and pid file.
import { spawnSync } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { loadRules } from '../secrets/engine.mjs';
import { clean } from '../text.mjs';
import { createPainter } from '../ui/term.mjs';
import { findSecrets } from './policy.mjs';
import { detectedHarnesses, harnessDirs, HARNESSES } from './registry.mjs';
import { SKIP_DIRS, skippedAsOwnCredential } from './scan.mjs';
import { pruneScrubs } from '../fix/scrub.mjs';
import { appendLog, getSetting, guardHome, writePrivate } from './state.mjs';
import { createAlertSink, createTail, isWatchRunning, notify } from './watch.mjs';
import { maybeOpenWindow, systemProgram } from './window.mjs';

// ---------- which harnesses are running ----------

export function processNames({ platform = process.platform, run = spawnSync, find = (n) => systemProgram(n, { platform }) } = {}) {
  const cmd = platform === 'win32' ? { file: find('tasklist.exe'), args: ['/FO', 'CSV', '/NH'] } : { file: find('ps'), args: ['-A', '-o', 'comm='] };

  if (!cmd.file) return [];
  const r = run(cmd.file, cmd.args, { encoding: 'utf8', windowsHide: true, timeout: 10000, maxBuffer: 8 * 1024 * 1024 });

  if (r.status !== 0 || !r.stdout) return [];

  return r.stdout.split(/\r?\n/).map((line) => (platform === 'win32' ? (line.match(/^"([^"]+)"/)?.[1] ?? '') : path.basename(line.trim()))).filter(Boolean).map((n) => n.toLowerCase().replace(/\.exe$/, ''));
}

export function runningHarnesses(names) {
  const set = new Set(names);

  return HARNESSES.filter((h) => h.procs.some((p) => set.has(p))).map((h) => h.id);
}

// ---------- following history files as they grow ----------

// Watch-kind harnesses the user has not switched off in Permissions.
const watchedHarnesses = () => {
  const off = getSetting('watch', {});

  return detectedHarnesses().filter((h) => h.kind === 'watch' && off[h.id] !== false);
};

// Per tick: at most 16 MB read in total (what is left is read on the next ticks), 1 MB per file.
// Each read starts 4 KB before where the last one ended, so a secret written in two halves across
// two ticks is still seen whole.
const TICK_BUDGET = 16 * 1024 * 1024;

const PER_FILE = 1024 * 1024;

const OVERLAP = 4096;

export function createFollower(harnesses = watchedHarnesses(), { maxFiles = 2000, budget = TICK_BUDGET } = {}) {
  let start = -1;
  const sizes = new Map();

  const list = () => {
    const out = [];

    for (const h of harnesses) {
      for (const dir of harnessDirs(h)) {
        const stack = [[dir, 0]];

        while (stack.length && out.length < maxFiles) {
          const [d, depth] = stack.pop();
          let entries = [];

          try { entries = fs.readdirSync(d, { withFileTypes: true }); } catch { continue; }

          for (const e of entries) {
            const full = path.join(d, e.name);

            if (e.isDirectory() && depth < 6 && !SKIP_DIRS.test(e.name)) stack.push([full, depth + 1]);
            else if (e.isFile() && !skippedAsOwnCredential(full)) out.push([h, full]);
          }
        }
      }
    }

    return out;
  };

  // The first pass records where each file ends: only text written from now on is read.
  for (const [, file] of list()) {
    try { sizes.set(file, fs.lstatSync(file).size); } catch { /* gone */ }
  }

  return {
    // New text per harness since the last call (at most 1 MB per file per call).
    read() {
      const fresh = [];
      const listed = list();
      let left = budget;

      // Files that are gone are forgotten (the map would otherwise grow for as long as it runs).
      const present = new Set(listed.map(([, f]) => f));

      for (const f of sizes.keys()) if (!present.has(f)) sizes.delete(f);

      // Start from a different file each tick, so a few very busy files cannot keep the budget from
      // ever reaching the others.
      start = listed.length ? (start + 1) % listed.length : 0;

      for (const [h, file] of [...listed.slice(start), ...listed.slice(0, start)]) {
        if (left <= 0) break;
        let st;

        try { st = fs.lstatSync(file); } catch { continue; }

        if (!st.isFile()) continue;
        const done = sizes.get(file) ?? 0;

        // A file that shrank was rewritten: start again from its beginning.
        if (st.size < done) sizes.set(file, 0);
        const offset = sizes.get(file) ?? 0;
        const from = Math.max(0, offset - Math.min(OVERLAP, Math.floor(left / 2)));
        const end = Math.min(st.size, from + Math.min(PER_FILE, left));

        if (end <= (sizes.get(file) ?? 0)) continue;
        const len = end - from;
        left -= len;
        const before = from;
        const buf = Buffer.alloc(len);
        let fd;

        // Opened without following a link (where the system allows it), then checked to be the same
        // regular file lstat saw: a file swapped for a link or a FIFO in between is skipped.
        try {
          fd = fs.openSync(file, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0) | (fs.constants.O_NONBLOCK ?? 0));
          const fst = fs.fstatSync(fd);

          if (!fst.isFile() || fst.ino !== st.ino || fst.dev !== st.dev) continue;
          fs.readSync(fd, buf, 0, len, before);
          // Marked as read only once it really was read (a failed open is retried next tick).
          sizes.set(file, end);
        } catch { continue; } finally {
          if (fd !== undefined) fs.closeSync(fd);
        }

        if (buf.subarray(0, 4096).includes(0)) continue;
        fresh.push({ harness: h.id, file, text: buf.toString('utf8') });
      }

      return fresh;
    },
  };
}

// ---------- the loop ----------

export async function runBackground({ home = guardHome(), intervalMs = 8000, cli, once = false, notifier = notify } = {}) {
  const pidFile = path.join(home, 'watch-bg.pid');
  fs.mkdirSync(home, { recursive: true, mode: 0o700 });
  writePrivate(pidFile, String(process.pid));
  let rules = null;
  const follower = createFollower();
  const tail = createTail(home);
  const quiet = { write() {} };
  const sink = createAlertSink(createPainter(0), { out: quiet, notifier });
  let running = new Set();
  const beats = new Map();
  const reported = new Map();
  // Loaded here, never on the hook's path; without it the rest of the watcher still runs.
  let codex = null;

  try { codex = (await import('../cost/codex.mjs')).createCodexSpend({ home, notifier }); } catch { /* Codex spend is optional */ }

  const tick = () => {
    try { fs.utimesSync(pidFile, new Date(), new Date()); } catch { /* hint only */ }

    // A harness that just started: note it and open the alerts window. While it keeps running, a
    // heartbeat every 5 minutes keeps it listed as running.
    const now = new Set(runningHarnesses(processNames()));

    for (const id of now) {
      if (!running.has(id)) {
        try { maybeOpenWindow(`process:${id}:${new Date().toISOString().slice(0, 13)}`, { home, cli }); } catch { /* optional */ }
      }

      if (!running.has(id) || Date.now() - (beats.get(id) ?? 0) > 5 * 60e3) {
        appendLog([{ ev: 'Process', kind: 'session', action: running.has(id) ? 'running' : 'start', harness: id }], `process:${id}`, home);
        beats.set(id, Date.now());
      }
    }

    running = now;

    // Clean-up backups (they hold removed secrets) are deleted when their days are up.
    try { pruneScrubs(home); } catch { /* nothing to prune */ }

    // Secrets written into the history of a harness without hooks.
    // Reads overlap a little, so the same value can be seen twice: each is reported once per file
    // (remembered by a hash, never by value, for a day).
    for (const { harness, file, text } of follower.read()) {
      rules ??= loadRules();

      for (const f of findSecrets(rules, text)) {
        const key = crypto.createHash('sha256').update(`${file}\0${f.secret}`).digest('hex');

        if (reported.has(key)) continue;
        reported.set(key, Date.now());
        appendLog([{ ev: 'History', kind: 'secret-in-history', action: 'seen', harness, rule: f.ruleId, tool: clean(path.basename(file), 60) }], `history:${harness}`, home);
      }
    }

    for (const [k, at] of reported) if (Date.now() - at > 864e5) reported.delete(k);

    try { codex?.tick(); } catch { /* a Codex spend failure never stops the watcher */ }

    // The open alerts window notifies on its own; otherwise this does.
    const fresh = tail.read();

    if (!isWatchRunning(home)) sink(fresh);
  };

  try { tick(); } catch { /* keep watching */ }

  if (once) return;

  await new Promise((resolve) => {
    const timer = setInterval(() => {
      try { tick(); } catch { /* keep watching */ }
    }, intervalMs);

    const stop = () => {
      clearInterval(timer);

      try { if (fs.readFileSync(pidFile, 'utf8') === String(process.pid)) fs.rmSync(pidFile); } catch { /* gone */ }

      resolve();
    };

    process.once('SIGINT', stop);
    process.once('SIGTERM', stop);
  });
}

export function isBackgroundRunning(home = guardHome()) {
  const pidFile = path.join(home, 'watch-bg.pid');

  try {
    if (Date.now() - fs.statSync(pidFile).mtimeMs > 60e3) return false;
    process.kill(Number.parseInt(fs.readFileSync(pidFile, 'utf8'), 10), 0);

    return true;
  } catch (e) {
    return e?.code === 'EPERM';
  }
}
