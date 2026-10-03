// The "safe text" subset a report must stay inside (guard-design#6x §5.4, rules V1 to V7 and V9).
// A report is a .md file that any reader treats as plain text: a closed alphabet, a closed line
// grammar, no links, no paths, no identity, no secrets. The validator answers { ok, problems }, where
// a problem is only { rule, code, line, column }: it never repeats what it was given, not even a
// fragment, so its output can go to a terminal or a log without washing the content through it.
//
// Pure: no file I/O (the rules file is read once by loadRules, and only when the caller gives none).
import os from 'node:os';
import { builtinModules } from 'node:module';
import { loadRules, scanText } from '../secrets/engine.mjs';
import { isSafeReportChar } from '../text.mjs';
import { isText } from '../kinds.mjs';

export const LIMITS = Object.freeze({ bytes: 8192, lines: 120, lineChars: 200, problems: 40 });

export const KINDS = Object.freeze(['product', 'security']);

export const TITLES = Object.freeze({ product: 'blackbrake report (product)', security: 'blackbrake report (security)' });

// The sections the automatic data can add, one per box the person ticks (all off by default).
export const AUTO_SECTIONS = Object.freeze({
  setup: 'Setup',
  activity: 'Guard activity in the last 7 days',
  secrets: 'Kinds of secrets involved',
  problems: 'Problems blackbrake had',
});

const AUTO = Object.values(AUTO_SECTIONS);

// The only "## " headings a report may have, in the order the builder writes them.
export const HEADINGS = Object.freeze({
  product: Object.freeze(['Summary', 'What happened', 'What you expected', ...AUTO]),
  security: Object.freeze(['Summary', 'Affected part', 'Steps', 'Impact', ...AUTO]),
});

// Line 2 of every report. (The design example used a middle dot, which is outside the alphabet.)
export const META_LINE = /^Version: (\d{1,3}\.\d{1,3}\.\d{1,3}), Date: \d{4}-\d{2}-\d{2}$/;

const FILE_NAME = /^(product|security)-(\d{4})(\d{2})(\d{2})T(\d{2})(\d{2})(\d{2})Z-[0-9a-f]{8}\.md$/;

export function assertKind(kind) {
  if (!KINDS.includes(kind)) throw new TypeError('report kind must be "product" or "security"');
}

// V8 (name part): the only file name a command accepts. No separators, drives, `..` or `~` can match.
export function isReportFileName(name) {
  const m = isText(name) ? FILE_NAME.exec(name) : null;

  if (!m) return false;
  const [, , , month, day, hour, minute, second] = m;

  return month >= '01' && month <= '12' && day >= '01' && day <= '31' && hour <= '23' && minute <= '59' && second <= '59';
}

let cachedRules = null;

const defaultRules = () => (cachedRules ??= loadRules());

// Names that would identify the person or the machine. Shorter than 3 characters are ignored (they
// would match half of any text).
function defaultIdentity() {
  const get = (f) => { try { return f(); } catch { return ''; } };

  return { home: get(() => os.homedir()), user: get(() => os.userInfo().username) || process.env.USERNAME || process.env.USER || '', host: get(() => os.hostname()) };
}

const identityFold = (value) => String(value ?? '').normalize('NFD').replace(/\p{M}/gu, '').toLowerCase();

function prepareIdentity(identity) {
  const id = identity ?? defaultIdentity();

  const pick = (v) => {
    const s = identityFold(v).replaceAll('\\', '/');

    return s.length >= 3 ? s : null;
  };

  // The host name whole and its first label too (review B: "Studio-Mac-7" of "Studio-Mac-7.local"
  // got through), and, on Windows, COMPUTERNAME.
  const host = String(id.host ?? '');
  const hosts = [host, host.split('.')[0], identity ? '' : process.env.COMPUTERNAME].flatMap((h) => pick(h) ?? []);

  return { home: pick(id.home), user: pick(id.user), host: pick(id.host), hosts: [...new Set(hosts)] };
}

function collector() {
  const list = [];
  const seen = new Set();

  return {
    list,
    add(rule, code, line = 0, column = 0) {
      const key = `${line}:${code}`;

      if (seen.has(key) || list.length >= LIMITS.problems) return;
      seen.add(key);
      list.push(column > 0 ? { rule, code, line, column } : { rule, code, line });
    },
  };
}

// V4 classes. Only the class is reported (and the column), never the character.
function charClass(cp) {
  if (cp < 0x20 || (cp >= 0x7f && cp <= 0x9f) || cp === 0xad || cp === 0x61c || cp === 0x115f || cp === 0x1160 || cp === 0x180e || (cp >= 0x200b && cp <= 0x200f)
    || (cp >= 0x2028 && cp <= 0x202e) || (cp >= 0x2060 && cp <= 0x206f) || cp === 0x3164 || (cp >= 0xfe00 && cp <= 0xfe0f) || cp === 0xfeff || cp === 0xffa0 || (cp >= 0xe0000 && cp <= 0xe007f)) return 'char-control';

  return cp > 0x20 && cp < 0x7f ? 'char-markup' : 'char-other';
}

const ALNUM = /[\p{L}\p{N}]/u;

// V4 (alphabet) plus the two position rules: `#` only as the leading run of a heading, `_` only
// between letters or digits.
function checkAlphabet(line, n, p) {
  const lead = /^#+/.exec(line)?.[0].length ?? 0;
  let col = 0;
  let idx = 0;
  let prev = '';

  for (const ch of line) {
    const cp = ch.codePointAt(0);
    col++;
    idx += ch.length;

    if (!isSafeReportChar(cp)) p.add('V4', charClass(cp), n, col);
    else if (ch === '#' && col > lead) p.add('V4', 'char-hash', n, col);
    else if (ch === '_' && !(ALNUM.test(prev) && ALNUM.test(line[idx] ?? ''))) p.add('V4', 'char-underscore', n, col);

    prev = ch;
  }
}

// V6: nothing that a Markdown or mail reader turns into a link. `<`, `>`, `[`, `]`, `&` and `@` are
// already outside the alphabet; this is the rest.
// Any URI scheme stuck to its value (tel:, sms:, ms-msdt:, search-ms: … not just a fixed list; review
// B). "Note: text" (a space after the colon) is prose, and so are the generated "Version: x" lines.
const LINK = /:\/\/|www\.|(?<![a-z0-9+.-])[a-z][a-z0-9+.-]{0,30}:(?=[^\s:])/i;

const NODE_MODULES = new Set(builtinModules.map((name) => name.replace(/^node:/, '')));

// Bare domains are links too; source-file extensions remain ordinary filenames.
const DOMAIN = /\b(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+(?!(?:md|sh|mjs|js|json|ts|txt|yaml|yml|css|html)\b)[a-z]{2,63}\b/i;

// V7 (shape part). A path, a long hexadecimal or base64-looking run, or an address identifies
// something the person did not mean to share.
const PATH_DRIVE = /(?<![A-Za-z0-9])[A-Za-z]:[\\/]/;

const PATH_LEAD = /(?:^|[\s"'(=,;:])(?:~|(?:\.{1,2})?\/\S)/;

const PATH_SLASHES = /\S*\/\S*\//;

const HEX = /(?<![0-9a-z])(?:0x)?[0-9a-f]{11,}(?![0-9a-z])/i;

const UUID = /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/i;

const IPV4 = /(?<![0-9.])(?:\d{1,3}\.){3}\d{1,3}(?![0-9])/;

// Two-component addresses with a first component >= 10 avoid treating ordinary decimal numbers
// such as 3.5 as an address. Ambiguous shorter decimal shapes remain a documented text limit.
const IPV4_SHORT = /(?<![0-9.])(?:[1-9]\d|1\d{2}|2[0-4]\d|25[0-5])\.\d{1,8}(?![0-9.])/;

const IPV4_INTEGER = /(?<![0-9])\d{10}(?![0-9])/g;

const IPV6_FULL = /(?<![0-9a-z:])(?:[0-9a-f]{1,4}:){7}[0-9a-f]{1,4}(?![0-9a-z:])/i;

const IPV6_SHORT = /(?<![0-9a-z:])(?:[0-9a-f]{1,4}(?::[0-9a-f]{1,4}){0,6})?::(?:[0-9a-f]{1,4}(?::[0-9a-f]{1,4}){0,6})?(?![0-9a-z:])/gi;

// Dots do not split a token (review B: "<20>.<20>" got through as two short runs).
const LONG_RUN = /[A-Za-z0-9+/_.-]{24,}/g;

// Plain hyphenated words ("well-known-pre-existing-condition") are prose, not tokens. The same shape
// covers rule ids such as 1password-service-account-token. The first part must be word-sized
// (review B: "<30 random characters>-aa-bb" passed as a kebab word).
const KEBAB = /^(?:[a-z]{1,15}|1password)(?:-[a-z]{1,15}){2,}$/;

function identityMention(text, name) {
  if (!name) return false;
  let at = text.indexOf(name);

  while (at !== -1) {
    if (name.length >= 6 || (!ALNUM.test(text[at - 1] ?? '') && !ALNUM.test(text[at + name.length] ?? ''))) return true;
    at = text.indexOf(name, at + 1);
  }

  return false;
}

function checkPrivacy(line, n, ident, p) {
  const lower = identityFold(line);
  const slashed = lower.replaceAll('\\', '/');

  if (PATH_DRIVE.test(line) || PATH_LEAD.test(line) || PATH_SLASHES.test(line.replace(/\bread\/write\/execute\b/g, 'permissions'))) p.add('V7', 'privacy-path', n);

  if ((ident.home && slashed.includes(ident.home)) || identityMention(lower, ident.user) || ident.hosts.some((h) => identityMention(lower, h))) p.add('V7', 'privacy-identity', n);

  if (HEX.test(line) || UUID.test(line)) p.add('V7', 'privacy-hex', n);

  if (IPV4.test(line) || IPV4_SHORT.test(line) || [...line.matchAll(IPV4_INTEGER)].some((m) => Number(m[0]) <= 0xffffffff) || IPV6_FULL.test(line) || [...line.matchAll(IPV6_SHORT)].some((m) => /[0-9a-f]/i.test(m[0]))) p.add('V7', 'privacy-ip', n);

  if ((line.match(LONG_RUN) ?? []).some((run) => !KEBAB.test(run))) p.add('V7', 'privacy-token', n);
}

// Everything every line has to satisfy, in a report or in one typed field.
function checkLine(line, n, ident, p) {
  if (line.length > LIMITS.lineChars) p.add('V1', 'line-length', n, LIMITS.lineChars + 1);

  if (line.normalize('NFC') !== line) p.add('V3', 'nfc', n);
  checkAlphabet(line, n, p);

  const linkText = line.replace(/\bnode:([a-z][a-z0-9_/]*)\b/g, (match, name) => NODE_MODULES.has(name) ? 'local technical name' : match)
    .replace(/\blocalhost:\d{1,5}\b|\b[A-Za-z]:[\\/]\S*/g, 'local technical name');

  if (LINK.test(linkText) || DOMAIN.test(line)) p.add('V6', 'link', n);
  checkPrivacy(line, n, ident, p);
}

// Line number of every secret the engine finds (the engine sees the whole text so a multi-line key
// is found; the value itself never leaves this function).
function secretLines(text, rules) {
  const starts = [0];

  for (let i = text.indexOf('\n'); i !== -1; i = text.indexOf('\n', i + 1)) starts.push(i + 1);

  return scanText(rules ?? defaultRules(), text).map((f) => {
    let lo = 0;
    let hi = starts.length - 1;

    while (lo < hi) {
      const mid = (lo + hi + 1) >> 1;

      if (starts[mid] <= f.index) lo = mid;
      else hi = mid - 1;
    }

    return lo + 1;
  });
}

// What may begin a paragraph or a bullet: nothing Markdown reads as a list, a setext underline, a
// heading or a rule.
const STARTS_BLOCK = /^(?:[-+=#]|\d+[.)](?:\s|$))/;

function grammarCode(line) {
  if (line.startsWith(' ')) return 'indent';

  if (line.endsWith(' ')) return 'trailing-space';
  const text = line.startsWith('- ') ? line.slice(2) : line;

  return text === '' || text.startsWith(' ') || STARTS_BLOCK.test(text) ? 'grammar' : null;
}

function checkStructure(lines, kind, p) {
  const seen = new Set();

  lines.forEach((line, i) => {
    const n = i + 1;

    if (i === 0) {
      if (line !== `# ${TITLES[kind]}`) p.add('V5', 'title', n);

      return;
    }

    if (i === 1) {
      if (!META_LINE.test(line)) p.add('V5', 'meta', n);

      return;
    }

    if (line === '') return;

    if (line.startsWith('#')) {
      if (line.startsWith('## ') && !line.startsWith('### ')) {
        const name = line.slice(3);

        if (!HEADINGS[kind].includes(name)) p.add('V5', 'heading', n);
        else if (seen.has(name)) p.add('V5', 'heading-duplicate', n);
        else seen.add(name);
      } else if (line.startsWith('# ')) p.add('V5', 'heading', n);
      else p.add('V5', 'grammar', n);

      if (line.endsWith(' ')) p.add('V5', 'trailing-space', n);

      return;
    }

    const code = grammarCode(line);

    if (code) p.add('V5', code, n);
  });
}

const toBytes = (input) => (isText(input) ? Buffer.from(input, 'utf8') : input instanceof Uint8Array ? input : null);

// Decode (V2) and split into lines. A BOM and CRLF are accepted (Notepad adds both) and normalized.
function readLines(input, p) {
  const bytes = toBytes(input);

  if (!bytes) { p.add('V2', 'encoding');

 return null; }

  if (bytes.length > LIMITS.bytes) { p.add('V1', 'size');

 return null; }

  let text;

  try {
    text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
  } catch {
    p.add('V2', 'encoding');

    return null;
  }

  if (text.charCodeAt(0) === 0xfeff) text = text.slice(1);

  if (text.includes('\u0000')) { p.add('V2', 'encoding');

 return null; }

  text = text.replace(/\r\n/g, '\n');
  const lines = text.split('\n');

  if (lines.at(-1) === '') lines.pop();

  lines.forEach((l, i) => { if (l.includes('\r')) p.add('V2', 'encoding', i + 1); });

  if (lines.length > LIMITS.lines) p.add('V1', 'lines');

  return { text, lines };
}

// V1 to V7 over a whole report. `input` is a string or bytes (a file read as bytes keeps V2 honest).
// On success the result carries `text`, the normalized string: the one to write or to send (V9).
export function validateReport(input, { kind, rules, identity } = {}) {
  assertKind(kind);
  const p = collector();
  const read = readLines(input, p);

  if (!read) return { ok: false, problems: p.list };
  const ident = prepareIdentity(identity);

  read.lines.forEach((line, i) => checkLine(line, i + 1, ident, p));
  checkStructure(read.lines, kind, p);

  for (const line of secretLines(read.text, rules)) p.add('V7', 'privacy-secret', line);

  return p.list.length ? { ok: false, problems: p.list } : { ok: true, problems: [], text: read.text };
}

// The same rules for one field typed in the wizard (the error is a generic reason plus a column).
// Headings cannot be typed into a field: only the builder writes them.
export function validateFreeText(input, { rules, identity, maxChars, multiline = false } = {}) {
  const p = collector();

  if (!isText(input)) { p.add('V2', 'encoding');

 return { ok: false, problems: p.list }; }

  if (input.length > maxChars) { p.add('V1', 'size');

 return { ok: false, problems: p.list }; }

  const text = input.replace(/\r\n/g, '\n');
  const lines = text === '' ? [] : text.split('\n');

  if (!multiline && lines.length > 1) { p.add('V5', 'multiline');

 return { ok: false, problems: p.list }; }

  const ident = prepareIdentity(identity);

  lines.forEach((line, i) => {
    const n = i + 1;

    if (line.includes('\r')) p.add('V2', 'encoding', n);
    checkLine(line, n, ident, p);
    const code = line.startsWith('#') ? 'grammar' : line === '' ? null : grammarCode(line);

    if (code) p.add('V5', code, n);
  });

  for (const line of secretLines(text, rules)) p.add('V7', 'privacy-secret', line);

  return p.list.length ? { ok: false, problems: p.list } : { ok: true, problems: [], text };
}
