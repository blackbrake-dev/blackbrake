// `blackbrake watch`: live alerts from every agent guard runs in. It reads guard's own log (types and
// counts, never content) as it grows, grades each event from low to maximum, lists the agents running
// right now, and raises a system notification for high and maximum alerts. Local only: the
// notification is the operating system's own (PowerShell toast, osascript, notify-send).
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import readline from 'node:readline';
import { t } from '../i18n.mjs';
import { clean } from '../text.mjs';
import { mini, motionAllowed, padEnd, screen } from '../ui/term.mjs';
import { getSetting, guardHome, logDir, writePrivate } from './state.mjs';
import { HARNESSES } from './registry.mjs';
import { systemProgram } from './window.mjs';

export const LEVELS = ['low', 'medium', 'high', 'critical'];

// What each event means for security. A secret that still went out (observe) is worse than one
// guard stopped; an attempt to switch guard off is the maximum either way.
export function severity(e) {
  const stopped = /^(blocked|denied|redacted|asked)$/.test(String(e.action));

  switch (e.kind) {
    case 'tamper': return 'critical';
    case 'secret-in-prompt':
    case 'secret-in-output':
    case 'secret-in-request':
    case 'secret-in-command': return stopped ? 'high' : 'critical';
    case 'secret-in-write':
    case 'secret-dump':
    case 'destructive-after-compaction': return stopped ? 'medium' : 'high';
    case 'secret-in-history': return 'high';
    case 'sensitive-read':
    case 'opaque-command': return stopped ? 'low' : 'medium';
    case 'error': return 'low';
    default: return null;
  }
}

export const AGENT_NAMES = Object.fromEntries(HARNESSES.map((h) => [h.id, h.name.replace('GitHub ', '')]));

const KIND_TEXT = {
  'secret-in-prompt': 'secret in your message',
  'secret-in-output': 'secret in tool output',
  'secret-in-write': 'secret written to a file',
  'secret-in-command': 'secret inside a command',
  'secret-in-request': 'secret sent in a request',
  'sensitive-read': 'read of a credential file',
  'secret-dump': 'command that prints secrets',
  'opaque-command': 'command that cannot be checked',
  'destructive-after-compaction': 'destructive command after compaction',
  tamper: 'attempt to switch guard off',
  error: 'guard could not check a step',
  'secret-in-history': 'secret written in an agent\'s history',
};

const BADGE = {
  critical: (p) => p.onCoral(p.ink(p.bold(` ${t('MAXIMUM')} `))),
  high: (p) => p.onAmber(p.ink(p.bold(` ${t('HIGH')} `))),
  medium: (p) => p.onBrown(p.cream(` ${t('MEDIUM')} `)),
  low: (p) => p.faint(` ${t('LOW')} `),
};

export function eventLine(p, e) {
  const level = severity(e);
  const time = clean(e.ts, 30).slice(11, 19);
  const agent = AGENT_NAMES[e.harness ?? 'claude'] ?? clean(e.harness, 20);
  const detail = [e.tool, e.rule].filter(Boolean).map((x) => clean(x, 50)).join(' · ');

  // Brakey's face for the level: calm, worried, alarmed.
  const face = mini(p, { low: 'idle', medium: 'worried', high: 'alert', critical: 'alert' }[level]);

  return `  ${p.faint(time)} ${face} ${padEnd(BADGE[level](p), 10)} ${padEnd(p.cream(agent), 13)} ${t(KIND_TEXT[e.kind])} ${p.faint(`· ${t(clean(e.action, 12))}${detail ? ` · ${detail}` : ''}`)}`;
}

// Agents with guard activity in the last few minutes, by agent and session.
export function runningAgents(events, now = Date.now(), windowMs = 15 * 60e3) {
  const seen = new Map();

  for (const e of events) {
    const at = Date.parse(e.ts);

    // A time in the future is a forged or broken line: it would stay "running" forever.
    if (!Number.isFinite(at) || now - at > windowMs || at - now > 5 * 60e3) continue;
    const id = e.harness ?? 'claude';
    const a = seen.get(id) ?? { id, name: AGENT_NAMES[id] ?? clean(id, 20), sessions: new Set(), last: e.ts };
    a.sessions.add(e.s);
    a.last = e.ts > a.last ? e.ts : a.last;
    seen.set(id, a);
  }

  return [...seen.values()];
}

// ---------- reading the log as it grows ----------

export function createTail(home = guardHome()) {
  const offsets = new Map();

  return {
    // Everything appended since the last call (the first call starts at the end of each file).
    read(fromStart = false) {
      const dir = logDir(home);
      const out = [];
      let files = [];

      try { files = fs.readdirSync(dir).filter((f) => /^\d{4}-\d{2}\.jsonl$/.test(f)).sort(); } catch { return out; }

      for (const name of files) {
        const file = path.join(dir, name);
        let size = 0;

        try {
          const st = fs.lstatSync(file);

          if (!st.isFile()) continue;
          size = st.size;
        } catch { continue; }

        const from = offsets.get(file) ?? (fromStart ? 0 : size);

        if (size <= from) {
          offsets.set(file, size);
          continue;
        }

        // Read only the new bytes, at most 4 MB at a time.
        const len = Math.min(size - from, 4 * 1024 * 1024);
        const buf = Buffer.alloc(len);
        // A log removed or swapped for a link in between is skipped, never followed or crashed on.
        let fd;

        try {
          fd = fs.openSync(file, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0));

          if (!fs.fstatSync(fd).isFile()) continue;
          fs.readSync(fd, buf, 0, len, from);
        } catch { continue; } finally {
          if (fd !== undefined) fs.closeSync(fd);
        }

        const text = buf.toString('utf8');
        const end = text.lastIndexOf('\n') + 1;
        offsets.set(file, from + Buffer.byteLength(text.slice(0, end)));

        for (const line of text.slice(0, end).split('\n')) {
          if (!line) continue;

          try { out.push(JSON.parse(line)); } catch { /* partial or foreign line */ }
        }
      }

      return out;
    },
  };
}

// ---------- system notifications ----------

// The text travels in environment variables or arguments, never inside a script or a shell line.
const TOAST = [
  '$ErrorActionPreference="Stop"',
  '[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] > $null',
  '[Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime] > $null',
  '$t=[Security.SecurityElement]::Escape($env:BB_TITLE); $b=[Security.SecurityElement]::Escape($env:BB_TEXT)',
  '$x=New-Object Windows.Data.Xml.Dom.XmlDocument',
  '$x.LoadXml("<toast><visual><binding template=`"ToastGeneric`"><text>$t</text><text>$b</text></binding></visual></toast>")',
  '$id="{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\\WindowsPowerShell\\v1.0\\powershell.exe"',
  '[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($id).Show([Windows.UI.Notifications.ToastNotification]::new($x))',
].join('; ');

// Programs come from fixed system folders (see systemProgram), never from PATH.
export function notificationCommand(title, text, platform = process.platform, find = (n) => systemProgram(n, { platform })) {
  if (platform === 'win32') return { file: find('powershell.exe'), args: ['-NoProfile', '-NonInteractive', '-WindowStyle', 'Hidden', '-Command', TOAST], env: { BB_TITLE: title, BB_TEXT: text } };

  if (platform === 'darwin') return { file: find('osascript'), args: ['-e', 'on run argv', '-e', 'display notification (item 2 of argv) with title (item 1 of argv)', '-e', 'end run', title, text], env: {} };

  return { file: find('notify-send'), args: ['--app-name=blackbrake', '--urgency=critical', title, text], env: {} };
}

export function notify(title, text) {
  // Switched off in Permissions: the alerts still show in the window and the log.
  if (!getSetting('notify', true)) return;
  const c = notificationCommand(clean(title, 80), clean(text, 200));

  if (!c.file) return;

  try {
    const child = spawn(c.file, c.args, { env: { ...process.env, ...c.env }, stdio: 'ignore', windowsHide: true, detached: false });
    child.on('error', () => { /* no notifier on this system: the bell and the screen still show it */ });
  } catch { /* same */ }
}

// ---------- the watcher itself ----------

const lockFile = (home) => path.join(home, 'watch.pid');

export function isWatchRunning(home = guardHome()) {
  let pid = null;

  try { pid = Number.parseInt(fs.readFileSync(lockFile(home), 'utf8'), 10); } catch { return false; }

  if (!Number.isInteger(pid) || pid <= 0) return false;

  // A running watcher touches its pid file every tick; an old one belongs to a dead watcher whose
  // pid may have been reused by another process.
  try {
    if (Date.now() - fs.statSync(lockFile(home)).mtimeMs > 120e3) return false;
  } catch { return false; }

  try {
    process.kill(pid, 0);

    return true;
  } catch (e) {
    return e.code === 'EPERM';
  }
}

// The last hour, and nothing dated in the future (a forged line would otherwise stay forever).
const recentEvent = (e) => { const d = Date.now() - Date.parse(e.ts);

 return d < 3600e3 && d > -5 * 60e3; };

export function watchHeader(p, running, backHint = null) {
  const agents = running.length ? running.map((a) => `${a.name}${a.sessions.size > 1 ? ` ×${a.sessions.size}` : ''}`).join(' · ') : t('none right now');
  // Brakey keeps an eye out while agents run, and dozes when none does.
  const header = screen(p, t('LIVE ALERTS'), t('every agent guard runs in, as it happens'), undefined, running.length ? { pose: 'right', line: t('watching {n} agent(s).', { n: running.length }) } : { pose: 'sleep', line: t('no agent is running; I will wake up when one starts.') });

  return [...header, `  ${padEnd(p.faint(t('Agents running')), 18)}${p.cream(agents)}`, `  ${p.faint(t('High and maximum alerts also raise a system notification.'))} ${p.orange(backHint ?? t('q or Esc: back'))}`, ''];
}

// Shows new events and notifies high and maximum ones, at most one notification every 5 seconds
// (a burst reads as one alert).
export function createAlertSink(p, { out = process.stdout, notifier = notify, now = Date.now } = {}) {
  let lastNotice = 0;

  return (events) => {
    for (const e of events) {
      const level = severity(e);

      if (!level) continue;
      out.write(`${eventLine(p, e)}\n`);

      if (level !== 'high' && level !== 'critical') continue;

      // The terminal bell, unless switched off in Permissions.
      if (getSetting('sound', true)) out.write('\x07');

      if (now() - lastNotice > 5000) {
        lastNotice = now();
        notifier(`blackbrake · ${t(level === 'critical' ? 'MAXIMUM' : 'HIGH')}`, `${AGENT_NAMES[e.harness ?? 'claude'] ?? 'agent'}: ${t(KIND_TEXT[e.kind])}`);
      }
    }
  };
}

// The live line at the bottom of the alerts; `out` writes above it.
function liveFooter(p, out, count, motion) {
  if (!motion) return { out, stop() {} };
  const DOTS = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];
  const LOOK = ['left', 'left', 'idle', 'right', 'right', 'idle'];
  let f = 0;

  const draw = () => {
    const n = count();
    const dot = f % 10 < 6 ? '●' : '○';
    const time = new Date().toTimeString().slice(0, 8);
    out.write(`\r\x1b[2K  ${mini(p, n ? LOOK[Math.floor(f / 4) % LOOK.length] : 'sleep')} ${p.orange(DOTS[f % DOTS.length])} ${p.onCoral(p.ink(p.bold(` ${dot} ${t('LIVE')} `)))} ${p.cream(n ? t('watching {n} agent(s).', { n }) : t('waiting for an agent to start'))} ${p.faint(time)}`);
    f++;
  };

  out.write('\x1b[?25l');
  // The cursor comes back even if the process ends without stop().
  const restore = () => out.write('\x1b[?25h');
  process.once('exit', restore);
  draw();
  const timer = setInterval(draw, 100);
  timer.unref?.();

  return {
    out: { isTTY: out.isTTY, columns: out.columns, write(s) { out.write('\r\x1b[2K'); out.write(s); draw(); } },
    stop() {
      clearInterval(timer);
      process.off('exit', restore);
      out.write('\r\x1b[2K\x1b[?25h');
    },
  };
}

// Runs until interrupted. `io` is injectable for tests.
export async function watch(p, { home = guardHome(), out = process.stdout, intervalMs = 700, once = false, notifier = notify, keys = false, backHint = null } = {}) {
  fs.mkdirSync(home, { recursive: true, mode: 0o700 });
  writePrivate(lockFile(home), String(process.pid));
  const tail = createTail(home);
  // The last hour, for context; then only what is new.
  const history = tail.read(true).filter(recentEvent);
  let recent = history;
  out.write(`${watchHeader(p, runningAgents(recent), backHint).join('\n')}\n`);
  const shown = history.filter((e) => severity(e));

  for (const e of shown.slice(-15)) out.write(`${eventLine(p, e)}\n`);

  if (!shown.length) out.write(`  ${p.faint(t('No alerts in the last hour. New ones appear here as they happen.'))}\n`);
  let lastAgents = runningAgents(recent).map((a) => a.id).join(',');
  // While it listens, a live line stays at the bottom: Brakey looking around, a spinner, the LIVE
  // badge beating, what is being watched and the time. New lines are written above it.
  const live = liveFooter(p, out, () => runningAgents(recent).length, !once && motionAllowed(out));
  const sink = createAlertSink(p, { out: live.out, notifier });

  const tick = () => {
    try { fs.utimesSync(lockFile(home), new Date(), new Date()); } catch { /* the pid file is only a hint */ }

    const fresh = tail.read();
    recent = [...recent, ...fresh].filter(recentEvent);
    const agents = runningAgents(recent);
    const ids = agents.map((a) => a.id).join(',');

    if (ids !== lastAgents) {
      live.out.write(`  ${p.faint(`${t('Agents running')}: ${agents.map((a) => a.name).join(' · ') || t('none right now')}`)}\n`);
      lastAgents = ids;
    }

    sink(fresh);
  };

  if (once) {
    tick();

    return;
  }

  await new Promise((resolve) => {
    const timer = setInterval(tick, intervalMs);
    const input = process.stdin;
    const useKeys = keys && input.isTTY;

    function onKey(_s, key = {}) {
      if (key.name === 'q' || key.name === 'escape' || (key.ctrl && key.name === 'c')) stop();
    }

    function stop() {
      clearInterval(timer);
      live.stop();
      process.off('SIGINT', stop);
      process.off('SIGTERM', stop);

      if (useKeys) {
        input.off('keypress', onKey);
        input.setRawMode(false);
        input.pause();
      }

      try { if (fs.readFileSync(lockFile(home), 'utf8') === String(process.pid)) fs.rmSync(lockFile(home)); } catch { /* already gone */ }

      resolve();
    }

    // q or Esc closes the alerts (back to the menu when opened from it).
    if (useKeys) {
      readline.emitKeypressEvents(input);
      input.setRawMode(true);
      input.resume();
      input.on('keypress', onKey);
    }

    process.once('SIGINT', stop);
    process.once('SIGTERM', stop);
  });
}
