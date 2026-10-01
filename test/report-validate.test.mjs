// Report core (guard-design#6x §5.4): the validator, the builder and the aggregates. Everything here
// is pure. Secrets and identities are synthetic and assembled at run time.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { loadRules } from '../src/secrets/engine.mjs';
import { isSafeReportChar } from '../src/text.mjs';
import { aggregateReport, countLines, SAFE_KEY, setupLines } from '../src/report/aggregate.mjs';
import { buildReport, reportFileName } from '../src/report/build.mjs';
import { HEADINGS, isReportFileName, LIMITS, TITLES, validateFreeText, validateReport } from '../src/report/validate.mjs';

const FIXTURES = path.resolve(path.dirname(fileURLToPath(import.meta.url)), 'fixtures/report');
const rules = loadRules();
const identity = { home: 'C:/Users/zzuser-q7', user: 'zzuser-q7', host: 'zzhost-k9' };
const opts = (extra = {}) => ({ kind: 'product', rules, identity, ...extra });

const HEAD = ['# blackbrake report (product)', 'Version: 0.3.0, Date: 2026-09-30', '', '## Summary', 'The guard denied a harmless command.', '', '## What happened'];
const doc = (...body) => [...HEAD, ...body].join('\n') + '\n';
const check = (text, extra) => validateReport(text, opts(extra));
const codes = (r) => r.problems.map((p) => p.code);
const only = (text, code, extra) => {
  const r = check(text, extra);
  assert.equal(r.ok, false, `expected ${code}`);
  assert.ok(codes(r).includes(code), `expected ${code}, got ${codes(r)}`);

  return r;
};
const valid = (text, extra) => {
  const r = check(text, extra);
  assert.equal(r.ok, true, JSON.stringify(r.problems));

  return r;
};

function token(seed, len) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let x = seed, s = '';

  for (let i = 0; i < len; i++) { x = (x * 1103515245 + 12345) % 2147483648; s += alphabet[x % 62]; }

  return s;
}

// A line of exactly `n` characters made of short words (no long token, no trailing space).
function wordy(n) {
  const s = 'ab '.repeat(n).slice(0, n);

  return s.endsWith(' ') ? s.slice(0, -1) + 'a' : s;
}

test('the shipped fixtures are valid reports', () => {
  for (const [file, kind] of [['valid-product.md', 'product'], ['valid-security.md', 'security'], ['valid-minimal.md', 'product']]) {
    const r = validateReport(fs.readFileSync(path.join(FIXTURES, file)), opts({ kind }));
    assert.equal(r.ok, true, `${file}: ${JSON.stringify(r.problems)}`);
  }
});

test('isSafeReportChar: the closed alphabet', () => {
  const ok = (s) => [...s].every((c) => isSafeReportChar(c.codePointAt(0)));
  const no = (s) => [...s].every((c) => !isSafeReportChar(c.codePointAt(0)));
  assert.ok(ok(' abcXYZ0189.,:;!?"\'()/-+=%#_'));
  assert.ok(ok('ÀÉÑÜßàéñüÿ¿¡ªºĀāŐőŸſ'));
  assert.ok(no('<>[]{}\\`*~|&@^$'));
  assert.ok(no('×÷\n\t\r\u0000\u001b\u007f\u0085'));
  assert.ok(no('\u202e\u200b\u2066\u061c\u200f\ufeff\u{e0041}\u{1f600}\u0430\u03b1\u0301\ufe0f\u3164\u0180\u00b7'));
});

test('V1 size: bytes, lines, line length', () => {
  let exact = doc();
  let remaining = LIMITS.bytes - Buffer.byteLength(exact);

  while (remaining > 0) {
    const n = Math.min(remaining, 100);
    exact += (n > 1 ? wordy(n - 1) : '') + '\n';
    remaining -= n;
  }

  assert.equal(Buffer.byteLength(exact), LIMITS.bytes);
  valid(exact);
  only(exact + '\n', 'size');
  assert.equal(check(Buffer.alloc(LIMITS.bytes + 1, 97)).problems[0].code, 'size');
  only(doc(...Array.from({ length: 130 }, () => 'ab')), 'lines');
  only(doc(wordy(201)), 'line-length');
  valid(doc(wordy(200)));
});

test('V2 encoding: UTF-8, NUL, BOM and CRLF accepted, lone CR refused', () => {
  const text = doc('Fine text.');
  const crlf = text.replace(/\n/g, '\r\n');
  const bom = Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from(crlf)]);
  assert.equal(valid(bom).text, text);
  assert.equal(valid(crlf).text, text);
  only(Buffer.concat([Buffer.from(text), Buffer.from([0xff, 0xfe])]), 'encoding');
  only(text + '\u0000', 'encoding');
  only(doc('one\rtwo'), 'encoding');
  only(doc('bad surrogate \ud800 here'), 'char-other');
  only(42, 'encoding');
});

test('V3 NFC: a decomposed accent is refused', () => {
  valid(doc('Caf\u00e9 \u00f1.'));
  only(doc('Cafe\u0301'), 'nfc');
});

test('V4 alphabet: controls, bidi, zero width, markup, look-alikes', () => {
  valid(doc('Acentos: á é í ó ú ñ ü ¿Qué? ¡Hola! 1ª 2º Łódź Őrség.'));
  only(doc('osc \u001b]52;c;eA==\u0007 here'), 'char-control');
  only(doc('trojan \u202e text'), 'char-control');
  only(doc('zero\u200bwidth'), 'char-control');
  only(doc('tag \u{e0041}'), 'char-control');
  only(doc('cyrillic \u0430pple'), 'char-other');
  only(doc('emoji \u{1f600}'), 'char-other');
  only(doc('combining a\u0308'), 'char-other');

  for (const c of '<>[]{}\\`*~|&@^$') only(doc(`bad ${c} char`), 'char-markup');

  only(doc('a <script> b'), 'char-markup');
  only(doc('mail a@b'), 'char-markup');
  only(doc('image ![x](y)'), 'char-markup');
  valid(doc('snake_case and a_b_c are fine'));

  for (const bad of ['_lead', 'trail_', 'a _ b', 'a__b']) only(doc(`x ${bad}`), 'char-underscore');

  only(doc('issue #12'), 'char-hash');
});

test('V5 grammar: headings, bullets, paragraphs', () => {
  valid(doc('Text.', '', '- first', '- second item'));
  valid(doc('Text.', '- bullet right after a line'));
  only(doc('## Not a listed heading'), 'heading');
  only(doc('### Three hashes'), 'grammar');
  only(doc('#nospace'), 'grammar');
  only(doc('# A second title'), 'heading');
  only(doc(' indented'), 'indent');
  only(doc('    code block'), 'indent');
  only(doc('trailing '), 'trailing-space');
  only(doc('  - nested'), 'indent');
  only(doc('-'), 'grammar');
  only(doc('- - -'), 'grammar');
  only(doc('- 1. nested ordered'), 'grammar');
  only(doc('1. ordered'), 'grammar');
  only(doc('2) ordered'), 'grammar');
  only(doc('+ plus bullet'), 'grammar');
  only(doc('= setext'), 'grammar');
  only(doc('-----'), 'grammar');
  only(doc('======'), 'grammar');
  only(doc('3.'), 'grammar');
  valid(doc('2026-09-30 is a date', '3.5 is a number', 'a - dash b'));

  const noTitle = doc('x').split('\n').slice(1).join('\n');
  only(noTitle, 'title');
  only(doc('x').replace('Version: 0.3.0, Date: 2026-09-30', 'Hello there'), 'meta');
  only(doc('x').replace('(product)', '(security)'), 'title');
  only(doc('x').replace('## What happened', '## Summary'), 'heading-duplicate');
  valid(['# blackbrake report (security)', 'Version: 0.3.0, Date: 2026-09-30', '', '## Steps', 'Do the thing.', '', '## Impact', 'It matters.', ''].join('\n'), { kind: 'security' });
  only(doc('x'), 'title', { kind: 'security' });
  assert.throws(() => check(doc('x'), { kind: 'other' }), TypeError);
});

test('V6 links and HTML: schemes and autolinks', () => {
  for (const bad of ['see https://example.test/x', 'go to www.example.test', 'WWW.EXAMPLE.TEST', 'mailto:someone', 'javascript:run', 'data:text', 'file:thing', 'ftp://x', 'x ://']) only(doc(bad), 'link');

  valid(doc('install.sh and README.md are bare names', 'metadata: fine, profile: fine'));
});

test('V7 privacy: paths, identity, ids, addresses, tokens, secrets', () => {
  for (const bad of ['open C:/Users/someone/file', 'in /Users/x', 'in /home/x/y', 'at /etc/hosts', 'at ./here', 'at ../up', 'file=/tmp/x', 'in (/opt/app)', 'a/b/c', 'D:/x', '//host/share']) only(doc(bad), 'privacy-path');

  only(doc('my home is C:/Users/zzuser-q7'), 'privacy-identity');
  only(doc('user ZZUSER-Q7 here'), 'privacy-identity');
  only(doc('machine zzhost-k9'), 'privacy-identity');
  only(doc('machine ZzHost-K9'), 'privacy-identity');
  only(doc('c:/users/zzuser-q7'), 'privacy-identity');
  valid(doc('the machine has a short name'), { identity: { home: 'C:/x', user: 'ab', host: 'h' } });
  only(doc('hex deadbeefcafe0123'), 'privacy-hex');
  only(doc('hex 0xdeadbeefcafe'), 'privacy-hex');
  only(doc('id 123456789012'), 'privacy-hex');
  only(doc('uuid 123e4567-e89b-12d3-a456-426614174000'), 'privacy-hex');
  only(doc('host 192.168.1.20'), 'privacy-ip');
  only(doc('host 10.0.0.1.'), 'privacy-ip');

  for (const v6 of ['fe80::1', '2001:db8::8a2e:370:7334', '2001:0db8:85a3:0000:0000:8a2e:0370:7334', '::1']) only(doc(`addr ${v6}`), 'privacy-ip');

  only(doc('token ' + token(11, 30)), 'privacy-token');
  only(doc('token ' + token(12, 40) + '-' + token(13, 10)), 'privacy-token');
  const gh = 'gh' + 'p_' + token(7, 36);
  const r = only(doc(`key ${gh}`), 'privacy-secret');
  assert.equal(r.problems.find((p) => p.code === 'privacy-secret').line, HEAD.length + 1);
  const aws = 'AK' + 'IA' + token(5, 16).toUpperCase().replace(/[0189]/g, 'Q');
  only(doc(`key ${aws}`), 'privacy-secret');
  const key = ['-----BEGIN ' + 'PRIVATE KEY-----', token(2, 60), token(3, 60), '-----END ' + 'PRIVATE KEY-----'];
  only(doc(...key), 'privacy-secret');

  valid(doc('blackbrake 0.3.0 on Node 22.11.0, read/write, N/A, 24/7', 'at 12:30:45 on 2026-09-30', 'std:: is not an address', 'well-known-pre-existing-condition-of-things'));
  valid(doc('- 1password-service-account-token: 2'));
});

test('V8 file names: generated form only', () => {
  assert.ok(isReportFileName('product-20260930T081500Z-0a1b2c3d.md'));
  assert.ok(isReportFileName('security-20261231T235959Z-ffffffff.md'));

  for (const bad of ['product-20260930T081500Z-0a1b2c3d.md.exe', '../product-20260930T081500Z-0a1b2c3d.md', 'product-20260930T081500Z-0A1B2C3D.md', 'other-20260930T081500Z-0a1b2c3d.md',
    'product-20261330T081500Z-0a1b2c3d.md', 'product-20260930T251500Z-0a1b2c3d.md', 'C:product-20260930T081500Z-0a1b2c3d.md', '~product-20260930T081500Z-0a1b2c3d.md',
    'product-20260930T081500Z-0a1b2c3d.md\n', '', null, undefined, 7, 'sub/product-20260930T081500Z-0a1b2c3d.md', 'product-20260930T081500Z-0a1b2c3d.MD']) assert.equal(isReportFileName(bad), false, String(bad));
});

test('the validator never echoes what it was given', () => {
  const marks = ['SENTINELALPHA', 'zzuser-q7', 'C:/Users/SENTINELBETA', 'SENTINELGAMMA@host', 'https://sentinel-delta.test'];
  const gh = 'gh' + 'p_' + token(9, 36);
  const text = doc(...marks, gh, '\u202eSENTINELOMEGA', '<b>SENTINELPHI</b>');
  const r = check(text);
  assert.equal(r.ok, false);
  const out = JSON.stringify(r);

  for (const frag of [...marks, gh, 'SENTINELOMEGA', 'SENTINELPHI', 'ghp_']) assert.equal(out.includes(frag), false, frag);

  for (const p of r.problems) assert.deepEqual(Object.keys(p).filter((k) => !['rule', 'code', 'line', 'column'].includes(k)), []);

  assert.equal(r.text, undefined);
});

test('validateFreeText: one typed field, generic reason plus column', () => {
  assert.equal(validateFreeText('The guard said no.', { rules, identity, maxChars: 120 }).ok, true);
  const r = validateFreeText('bad < char', { rules, identity, maxChars: 120 });
  assert.deepEqual(r.problems.map((p) => [p.code, p.line, p.column]), [['char-markup', 1, 5]]);
  assert.equal(validateFreeText('x'.repeat(121), { rules, identity, maxChars: 120 }).problems[0].code, 'size');
  assert.equal(validateFreeText('two\nlines', { rules, identity, maxChars: 120, multiline: false }).problems[0].code, 'multiline');
  assert.equal(validateFreeText('two\nlines', { rules, identity, maxChars: 120, multiline: true }).ok, true);
  assert.equal(validateFreeText('## A heading', { rules, identity, maxChars: 120, multiline: true }).problems[0].code, 'grammar');
  assert.equal(validateFreeText('see C:/Users/x', { rules, identity, maxChars: 120 }).problems[0].code, 'privacy-path');
  assert.equal(validateFreeText('', { rules, identity, maxChars: 120 }).ok, true);
});

// Deterministic PRNG so a failure is reproducible.
function prng(seed) {
  let a = seed >>> 0;

  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);

    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

test('property: 10000 random documents never validate with markup, ESC, bidi or 8 KiB', () => {
  const rand = prng(20260930);
  const pieces = ['the', 'guard', 'denied', 'a', 'command', 'x', '1', '2026-09-30', 'é', 'ñ', '¿', '-', '- ', '+ ', '= ', '# ', '## ', '1. ', '3) ', '_', 'a_b', '.', ',', ':', '(', ')', '"', '!', '?', '/', '%', ' ', '  ',
    '<', '>', '&', '[', ']', '`', '*', '~', '|', '@', '\\', '{', '}', '^', '$', '\u001b', '\u202e', '\u200b', '\u2066', '\ufeff', '\u0000', '\r', '\t', '\u{1f600}', '\u0430', 'http://', 'www.', 'mailto:', '&amp;', '<a href=x>', '![i](u)', '\n'];
  // oxlint-disable-next-line no-control-regex -- the control characters are the point of this check
  const forbidden = /[<>&[\]`*~|@\\{}^$\u0000-\u0009\u000b-\u001f\u007f-\u009f\u202a-\u202e\u2066-\u2069\u200b-\u200f\u061c\ufeff]/u;
  let accepted = 0;

  for (let i = 0; i < 10000; i++) {
    const n = Math.floor(rand() * 14);
    let junk = '';

    for (let j = 0; j < n; j++) junk += pieces[Math.floor(rand() * pieces.length)];

    const whole = rand() < 0.15;
    const text = whole ? junk.repeat(1 + Math.floor(rand() * 400)) : doc(junk, `line ${i}`);
    const r = check(text);

    if (!r.ok) continue;
    accepted++;
    assert.equal(forbidden.test(r.text), false, JSON.stringify(text));
    assert.ok(Buffer.byteLength(r.text) <= LIMITS.bytes);
  }

  assert.ok(accepted > 100, `only ${accepted} documents were valid: the generator is too hostile to test anything`);
});

test('buildReport lays out a report the validator accepts', () => {
  const r = buildReport({
    kind: 'product', version: '0.3.0', now: new Date('2026-09-30T08:15:00Z'), rules, identity,
    fields: { Summary: 'Guard blocked a harmless command', 'What happened': 'I ran a build.\r\nThe guard said no.  ', 'What you expected': '- it runs\n- no alert' },
    sections: { Setup: ['- blackbrake_version: 0.3.0', '- os: linux'] },
  });
  assert.equal(r.ok, true, JSON.stringify(r.problems));
  assert.ok(r.text.startsWith('# blackbrake report (product)\nVersion: 0.3.0, Date: 2026-09-30\n\n## Summary\nGuard blocked a harmless command\n'));
  assert.ok(r.text.endsWith('## Setup\n- blackbrake_version: 0.3.0\n- os: linux\n'));
  assert.equal(r.text.includes('\r'), false);
  assert.equal(r.text.includes('  \n'), false);
  assert.equal(validateReport(r.text, opts()).ok, true);
  // The date is the UTC date, never a time.
  const late = buildReport({ kind: 'product', version: '0.3.0', now: new Date('2026-09-30T23:59:59-05:00'), rules, identity, fields: { Summary: 'x' } });
  assert.ok(late.text.includes('Date: 2026-10-01'));
});

test('buildReport refuses what the validator refuses, and unknown sections or kinds', () => {
  const base = { kind: 'product', version: '0.3.0', now: new Date(0), rules, identity };
  const bad = buildReport({ ...base, fields: { Summary: 'has <b> in it' } });
  assert.equal(bad.ok, false);
  assert.equal(bad.text, undefined);
  assert.equal(JSON.stringify(bad).includes('<b>'), false);
  assert.throws(() => buildReport({ ...base, kind: 'nope', fields: {} }), TypeError);
  assert.throws(() => buildReport({ ...base, version: '0.3', fields: {} }), TypeError);
  assert.throws(() => buildReport({ ...base, fields: { Steps: 'x' } }), TypeError);
  assert.throws(() => buildReport({ ...base, fields: { Setup: 'x' }, sections: { Setup: ['- os: linux'] } }), TypeError);
  // A typed field cannot smuggle in a heading of its own.
  const injected = buildReport({ ...base, fields: { Summary: 'x\n## What happened\ninjected' } });
  assert.equal(injected.ok, false);
  assert.ok(injected.problems.some((p) => p.code === 'heading-in-field' && p.field === 'Summary'));
  assert.ok(Object.keys(HEADINGS).every((k) => TITLES[k]));
});

test('reportFileName is generated and always passes V8', () => {
  const name = reportFileName('security', new Date('2026-09-30T08:15:00Z'), () => Buffer.from([0x0a, 0x1b, 0x2c, 0x3d]));
  assert.equal(name, 'security-20260930T081500Z-0a1b2c3d.md');
  assert.equal(isReportFileName(reportFileName('product', new Date())), true);
  assert.throws(() => reportFileName('x', new Date()), TypeError);
});

test('aggregates keep only safe keys and integer counts, and never echo a rejected key', () => {
  assert.ok(SAFE_KEY.test('aws-access-token'));

  for (const bad of ['', 'a', '-ab', 'A1', '../x', 'a b', '__proto__', 'x'.repeat(62), 'é1', 'a.b']) assert.equal(SAFE_KEY.test(bad), false, bad);

  const secret = 'gh' + 'p_' + token(3, 36);
  const input = { 'aws-access-token': 2, 'private-key': 1, [secret]: 4, '../etc': 1, bad: -1, 'generic-api-key': 1.5, 'github-pat': '3', constructor: 1 };
  const r = countLines('rule', input, { allowed: new Set(['aws-access-token', 'private-key', 'github-pat', 'generic-api-key']) });
  assert.deepEqual(r.lines, ['- rule aws-access-token: 2', '- rule private-key: 1']);
  assert.equal(r.rejected, 6);
  assert.equal(JSON.stringify(r).includes(secret), false);
  assert.equal(JSON.stringify(r).includes('etc'), false);
  assert.deepEqual(countLines('kind', { 'secret-in-prompt': 3 }).lines, ['- kind secret-in-prompt: 3']);
  assert.deepEqual(countLines('kind', { 'secret-in-prompt': 10 ** 9 }).lines, ['- kind secret-in-prompt: 999999']);
  assert.deepEqual(countLines('kind', null), { lines: [], rejected: 0 });
});

test('setupLines: closed values only', () => {
  const r = setupLines({ version: '0.3.0', os: 'win32', arch: 'x64', nodeMajor: 22, lang: 'es', harnessesDetected: ['claude', 'codex', '../x'], harnessesProtected: ['claude'], mode: 'protect', watcher: true, window: false, paused: false });
  assert.deepEqual(r.lines, ['- blackbrake_version: 0.3.0', '- os: win32', '- arch: x64', '- node_major: 22', '- lang: es', '- harnesses_detected: claude, codex', '- harnesses_protected: claude', '- mode: protect', '- watcher: on', '- window: off', '- paused: no']);
  assert.equal(r.rejected, 1);
  const odd = setupLines({ version: 'v1; drop', os: 'Plan9 on zzhost', arch: 'riscv', nodeMajor: 'twenty', lang: 'fr', mode: 'YOLO', watcher: 'maybe' });
  assert.equal(odd.lines.some((l) => /zzhost|drop|twenty|YOLO|maybe/.test(l)), false);
  assert.ok(odd.lines.includes('- os: other'));
  assert.equal(setupLines({}).lines.length, 0);
});

test('aggregateReport: nothing is included unless its box was ticked', () => {
  const data = { setup: { version: '0.3.0', os: 'linux', mode: 'observe' }, kinds: { 'secret-in-prompt': 2 }, actions: { deny: 1 }, byRule: { 'aws-access-token': 1 }, byClass: { 'likely-real': 1 }, problems: { error: 1, tamper: 0, integrity: 2 } };
  const none = aggregateReport(data, {});
  assert.deepEqual(none.sections, {});
  const all = aggregateReport(data, { selected: { setup: true, activity: true, secrets: true, problems: true }, ruleIds: new Set(['aws-access-token']), kindIds: new Set(['secret-in-prompt']) });
  assert.deepEqual(Object.keys(all.sections), ['Setup', 'Guard activity in the last 7 days', 'Kinds of secrets involved', 'Problems blackbrake had']);
  assert.ok(all.sections['Guard activity in the last 7 days'].includes('- kind secret-in-prompt: 2'));
  assert.ok(all.sections['Kinds of secrets involved'].includes('- class likely-real: 1'));
  assert.deepEqual(all.sections['Problems blackbrake had'], ['- error: 1', '- tamper: 0', '- integrity: 2']);
  const one = aggregateReport(data, { selected: { activity: true } });
  assert.deepEqual(Object.keys(one.sections), ['Guard activity in the last 7 days']);

  // The aggregates pass through the real builder and validator.
  const built = buildReport({ kind: 'product', version: '0.3.0', now: new Date('2026-09-30T00:00:00Z'), rules, identity, fields: { Summary: 'x' }, sections: all.sections });
  assert.equal(built.ok, true, JSON.stringify(built.problems));
});
