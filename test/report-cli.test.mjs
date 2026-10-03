// F6.8, the report wizard and commands (guard-design#6x §5.2, §5.3, §5.5): a person at a terminal
// only; nothing personal or secret gets in; every box of automatic data starts off; the file is shown
// whole; the mail app opens only after the whole message was shown and the person said yes; send
// checks the file again (V9). The terminal is a fake one and the menus answer from a script.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { PassThrough } from 'node:stream';
import { afterEach, test } from 'node:test';
import { gatherData, runReport, runWizard } from '../src/cli/features/report.mjs';
import { setLang } from '../src/i18n.mjs';
import { assertSafeMailto, MAX_URL } from '../src/report/mailto.mjs';
import { mailtoCommand, openMailto } from '../src/report/open.mjs';
import { reportsDir, saveReport } from '../src/report/store.mjs';
import { loadRules } from '../src/secrets/engine.mjs';
import { createPainter, strip } from '../src/ui/term.mjs';

const p = createPainter(0);

const RULES = loadRules();

const VERSION = '0.3.0';

const NOW = new Date('2026-10-01T10:00:00Z');

afterEach(() => setLang('en'));

const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'bb-report-cli-'));

// Synthetic, built at run time so the repository holds no credential-shaped literal.
const token = (seed, n) => {
  const a = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let x = seed;
  let s = '';

  for (let i = 0; i < n; i++) {
    x = (x * 1103515245 + 12345) % 2147483648;
    s += a[x % 62];
  }

  return s;
};

const GITHUB = `ghp_${token(11, 36)}`;

// A terminal where the person types `lines`, one after another.
function terminal({ lines = [], tty = true, env = {} } = {}) {
  const input = new PassThrough();
  const output = new PassThrough();
  input.isTTY = tty;
  output.isTTY = tty;
  output.on('data', () => {});
  input.write(lines.map((l) => `${l}\n`).join(''));

  return { input, output, env };
}

const DATA = {
  setup: { version: VERSION, os: 'linux', arch: 'x64', nodeMajor: 24, lang: 'en', harnessesDetected: ['claude', 'codex'], harnessesProtected: ['claude'], mode: 'protect', watcher: true, window: true, paused: false },
  kinds: { 'secret-in-command': 2, tamper: 1 },
  actions: { denied: 3 },
  byRule: { 'github-pat': 2, 'not-a-rule-we-have': 4 },
  problems: { error: 0, tamper: 1 },
};

// The machine and the person's answers to the menus.
function machine({ home = tmp(), picks = [], boxes = { setup: false, activity: false, secrets: false, problems: false }, opens = true } = {}) {
  const calls = { opened: [], select: [], checklist: [] };
  const queue = [...picks];

  return {
    home,
    calls,
    deps: {
      home,
      now: () => NOW,
      rules: () => RULES,
      gather: () => DATA,
      identity: { home: '/home/someone-else', user: 'zzqx', host: 'yyqv' },
      select: async (_p, items) => {
        calls.select.push(items.map((i) => i.value));

        return queue.length ? queue.shift() : null;
      },
      checklist: async (_p, items) => {
        calls.checklist.push(items.map((i) => [i.value, i.on]));

        return boxes;
      },
      open: (url) => {
        calls.opened.push(url);

        return opens;
      },
    },
  };
}

const run = async (fn) => {
  const out = [];
  const code = await fn((lines) => out.push(...lines));

  return { code, out: strip(out.join('\n')) };
};

const wizard = (m, kind, io) => run((print) => runWizard(p, kind, { version: VERSION, io, deps: m.deps, print }));

const report = (m, rest, io, opts = {}) => run((print) => runReport({ p, opts: { rest, ...opts }, print, pkg: { version: VERSION } }, { io, deps: m.deps }));

const saved = (m) => (fs.existsSync(reportsDir(m.home)) ? fs.readdirSync(reportsDir(m.home)) : []);

const PRODUCT_LINES = ['The menu froze after a scan', 'I opened the menu.', 'It stopped answering.', '', 'It should go back to the menu.', ''];

// ---------- who may use it ----------

test('without a terminal, or inside an AI agent: nothing is written, exit 1', async () => {
  for (const io of [terminal({ tty: false, lines: PRODUCT_LINES }), terminal({ lines: PRODUCT_LINES, env: { CLAUDECODE: '1' } })]) {
    const m = machine({ picks: ['done'] });
    const { code, out } = await wizard(m, 'product', io);
    assert.equal(code, 1);
    assert.match(out, /Reports are prepared in an interactive terminal/);
    assert.deepEqual(saved(m), []);
  }

  const m = machine();
  saveReport('product', '# blackbrake report (product)\nVersion: 0.3.0, Date: 2026-10-01\n\n## Summary\nx y\n', { home: m.home, now: NOW });

  for (const rest of [['send', saved(m)[0]], ['delete', saved(m)[0]]]) {
    assert.equal((await report(m, rest, terminal({ tty: false }))).code, 1, rest[0]);
  }

  assert.equal(saved(m).length, 1, 'nothing deleted');
  assert.deepEqual(m.calls.opened, [], 'nothing opened');
});

// ---------- the wizard ----------

test('product report: the typed fields, every box off by default, the file written and shown whole', async () => {
  const m = machine({ picks: ['done'] });
  const { code, out } = await wizard(m, 'product', terminal({ lines: PRODUCT_LINES }));
  assert.equal(code, 0);
  assert.deepEqual(m.calls.checklist[0], [['setup', false], ['activity', false], ['secrets', false], ['problems', false]], 'all off');
  const [name] = saved(m);
  assert.match(name, /^product-20261001T100000Z-[0-9a-f]{8}\.md$/);
  const text = fs.readFileSync(path.join(reportsDir(m.home), name), 'utf8');
  assert.equal(text, '# blackbrake report (product)\nVersion: 0.3.0, Date: 2026-10-01\n\n## Summary\nThe menu froze after a scan\n\n## What happened\nI opened the menu.\nIt stopped answering.\n\n## What you expected\nIt should go back to the menu.\n');
  assert.match(out, /Nothing is sent\. I write a file on this computer/);

  for (const line of text.trim().split('\n').filter(Boolean)) assert.ok(out.includes(line), `shown: ${line}`);
});

test('the preview shows exactly what each box adds; only ticked boxes go in, and unknown keys never', async () => {
  const m = machine({ picks: ['done'], boxes: { setup: true, activity: false, secrets: true, problems: false } });
  const { out } = await wizard(m, 'product', terminal({ lines: PRODUCT_LINES }));
  assert.match(out, /- harnesses_protected: claude/);
  assert.match(out, /- kind tamper: 1/, 'the activity box is previewed');
  const text = fs.readFileSync(path.join(reportsDir(m.home), saved(m)[0]), 'utf8');
  assert.match(text, /## Setup\n- blackbrake_version: 0\.3\.0\n/);
  assert.match(text, /## Kinds of secrets involved\n- rule github-pat: 2\n/);
  assert.doesNotMatch(text, /Guard activity|kind tamper/, 'unticked box left out');
  assert.doesNotMatch(text + out, /not-a-rule-we-have/, 'a rule id outside the loaded rules is never shown');
});

test('a secret, a path or a link typed in a field is refused with a reason, never echoed; three strikes end it', async () => {
  const typed = [`deploy with ${GITHUB}`, 'see /home/ana/project/x', 'look at https://example.com'];
  const m = machine({ picks: ['done'] });
  const { code, out } = await wizard(m, 'product', terminal({ lines: typed }));
  assert.equal(code, 0);
  assert.match(out, /looks like a secret/);
  assert.match(out, /file path/);
  assert.match(out, /links and web or mail addresses are not allowed/);
  assert.match(out, /Nothing was written/);

  for (const bad of [GITHUB, '/home/ana', 'example.com']) assert.ok(!out.includes(bad), `never echoed: ${bad}`);
  assert.deepEqual(saved(m), []);
});

test('security report: the closed "affected part" list, the warning, and its own headings', async () => {
  const m = machine({ picks: ['watcher', 'done'] });
  const { code, out } = await wizard(m, 'security', terminal({ lines: ['The watcher can be stopped', 'Start it.', 'Stop it.', '', 'Alerts stop.', ''] }));
  assert.equal(code, 0);
  assert.match(out, /Email is not end-to-end encrypted/);
  assert.deepEqual(m.calls.select[0], ['guard or hook', 'watcher', 'login item', 'reports', 'site', 'other']);
  const text = fs.readFileSync(path.join(reportsDir(m.home), saved(m)[0]), 'utf8');
  assert.match(text, /^# blackbrake report \(security\)\n/);
  assert.match(text, /## Affected part\nwatcher\n/);
  assert.match(text, /## Impact\nAlerts stop\.\n/);
});

test('Esc on the checklist or the list writes nothing', async () => {
  const m = machine({ boxes: null });
  assert.match((await wizard(m, 'product', terminal({ lines: PRODUCT_LINES }))).out, /Nothing was written/);
  const s = machine({ picks: [null] });
  assert.match((await wizard(s, 'security', terminal({ lines: [] }))).out, /Nothing was written/);
  assert.deepEqual([...saved(m), ...saved(s)], []);
});

// ---------- after saving, and sending ----------

test('send: address only by default; the mail app only after the whole message is shown and a yes', async () => {
  const m = machine({ picks: ['send', 'address', 'send', 'open', false, 'send', 'open', true, 'done'] });
  const { out } = await wizard(m, 'product', terminal({ lines: PRODUCT_LINES }));
  assert.match(out, /To\s+hello@blackbrake\.dev/);
  assert.match(out, /Subject\s+blackbrake report \(product\) v0\.3\.0/);
  assert.match(out, /The message, exactly as it will appear/);
  assert.equal(m.calls.opened.length, 1, 'opened once: after the yes, not after the no');
  const url = m.calls.opened[0];
  assert.ok(assertSafeMailto(url));
  assert.ok(url.length <= MAX_URL);
  assert.match(url, /^mailto:hello@blackbrake\.dev\?subject=blackbrake%20report%20%28product%29%20v0\.3\.0&body=/);
  assert.match(out, /I cannot tell whether you sent it/);
});

test('send checks the file again (V9): a report edited into something unsafe is not sent', async () => {
  const m = machine({ picks: ['open', true] });
  const name = saveReport('product', '# blackbrake report (product)\nVersion: 0.3.0, Date: 2026-10-01\n\n## Summary\nfine\n', { home: m.home, now: NOW });
  fs.appendFileSync(path.join(reportsDir(m.home), name), `\nsee <b>${GITHUB}</b>\n`);
  const { code, out } = await report(m, ['send', name], terminal());
  assert.equal(code, 1);
  assert.match(out, /not valid any more/);
  assert.deepEqual(m.calls.opened, []);
  assert.ok(!out.includes(GITHUB));
});

test('a report too long for a mail link sends only the subject and says how to add the text', async () => {
  const m = machine({ picks: ['open', true] });
  const long = Array.from({ length: 40 }, (_, i) => `Line number ${i} of a long description of what happened in the menu`).join('\n');
  const name = saveReport('product', `# blackbrake report (product)\nVersion: 0.3.0, Date: 2026-10-01\n\n## What happened\n${long}\n`, { home: m.home, now: NOW });
  const { out } = await report(m, ['send', name], terminal());
  assert.match(out, /too long for a mail link/);
  assert.match(m.calls.opened[0], /^mailto:hello@blackbrake\.dev\?subject=[^&]+$/);
});

// ---------- the other subcommands ----------

test('list, show and check work in a pipe; delete needs a terminal; delete --all needs the word', async () => {
  const m = machine();
  const good = saveReport('product', '# blackbrake report (product)\nVersion: 0.3.0, Date: 2026-10-01\n\n## Summary\nfine\n', { home: m.home, now: NOW, random: () => Buffer.from('00000001', 'hex') });
  const bad = saveReport('product', '# blackbrake report (product)\nVersion: 0.3.0, Date: 2026-10-01\n\n## Summary\nfine\n', { home: m.home, now: NOW, random: () => Buffer.from('00000002', 'hex') });
  fs.appendFileSync(path.join(reportsDir(m.home), bad), 'trailing \n');
  const pipe = terminal({ tty: false });
  assert.match((await report(m, ['list'], pipe)).out, new RegExp(good));
  assert.match((await report(m, ['show', good], pipe)).out, /1 {2}# blackbrake report \(product\)/);
  assert.equal((await report(m, ['check', good], pipe)).code, 0);
  const checked = await report(m, ['check', bad], pipe);
  assert.equal(checked.code, 1);
  assert.match(checked.out, /a line ends with spaces \(line 6\)/);
  assert.equal((await report(m, ['show', '../state.json'], pipe)).code, 2, 'only generated names');
  assert.equal((await report(m, ['delete', good], terminal({ lines: [] }))).code, 0);
  assert.equal((await report(m, ['delete'], terminal({ lines: ['no'] }), { all: true })).code, 0);
  assert.equal(saved(m).length, 1, 'a wrong word deletes nothing');
  assert.match((await report(m, ['delete'], terminal({ lines: ['delete'] }), { all: true })).out, /1 report\(s\) deleted/);
  assert.deepEqual(saved(m), []);
});

// Review B (2026-10-01): an edited file is never shown as if it were valid; a log line with a made-up
// action never reaches the activity section; invisible characters are cleaned from the screen.
test('review B: show warns about an invalid file; only real actions are counted; invisibles are cleaned', async () => {
  const m = machine();
  const name = saveReport('product', '# blackbrake report (product)\nVersion: 0.3.0, Date: 2026-10-01\n\n## Summary\nfine\n', { home: m.home, now: NOW });
  fs.appendFileSync(path.join(reportsDir(m.home), name), 'a͏b️c⁥d￹e\n');
  const shown = await report(m, ['show', name], terminal({ tty: false }));
  assert.equal(shown.code, 1);
  assert.match(shown.out, /not a valid report any more/);
  assert.match(shown.out, /abcde/, 'the invisible characters are gone from the screen');

  const home = tmp();
  fs.mkdirSync(path.join(home, 'log'), { recursive: true });
  const ts = new Date().toISOString();
  fs.writeFileSync(path.join(home, 'log', `${ts.slice(0, 7)}.jsonl`), [{ kind: 'tamper', action: 'denied' }, { kind: 'tamper', action: 'my-client-name-x' }].map((e) => JSON.stringify({ ts, s: 'x', ...e })).join('\n') + '\n');
  const data = gatherData({ home, version: VERSION });
  assert.deepEqual(data.actions, { denied: 1 });
  assert.equal(data.kinds.tamper, 2);
});

// ---------- opening the mail app ----------

test('the mail app is opened by a system program with the link as one argument, never a shell', () => {
  const url = 'mailto:hello@blackbrake.dev?subject=blackbrake%20report%20%28product%29%20v0.3.0';
  const find = (n) => `/sys/${n}`;
  assert.deepEqual(mailtoCommand(url, { platform: 'win32', find }), { file: '/sys/rundll32.exe', args: ['url.dll,FileProtocolHandler', url] });
  assert.deepEqual(mailtoCommand(url, { platform: 'darwin', find }), { file: '/sys/open', args: [url] });
  assert.deepEqual(mailtoCommand(url, { platform: 'linux', find }), { file: '/sys/xdg-open', args: [url] });
  assert.equal(mailtoCommand(url, { platform: 'linux', find: () => null }), null);
  assert.throws(() => mailtoCommand('mailto:someone@else.example?subject=x', { platform: 'linux', find }), /unsafe mailto/);
  assert.throws(() => mailtoCommand(`${url}&bcc=x`, { platform: 'linux', find }), /unsafe mailto/);
  const spawned = [];

  const run = (file, args, o) => {
    spawned.push([file, args, o.shell]);

    return { on() {}, unref() {} };
  };

  assert.equal(openMailto(url, { platform: 'linux', find, run }), true);
  assert.deepEqual(spawned, [['/sys/xdg-open', [url], false]]);
});
