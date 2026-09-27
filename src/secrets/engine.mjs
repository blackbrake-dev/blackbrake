// Secret detection using the gitleaks default rule set (vendored, MIT). Semantics follow
// gitleaks: keyword prefilter, first capture group (or secretGroup) as the secret, Shannon
// entropy threshold, per-rule and global allowlists and stopwords.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const RULES_FILE = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../vendor/gitleaks.rules.json');

// gitleaks' generated rules start with `[\w.-]{0,50}?(?:[\w.-]{0,50}?(?:keyword)…`: an optional
// identifier prefix before the keyword. It never changes the captured secret, only where the match
// starts, but in JavaScript's backtracking engine the two nested lazy runs cost up to 2,500 steps
// per position; a line of dense keywords ("okta.okta.okta…") took seconds per 20 KB. Removed.
const LAZY_PREFIX = '[\\w.-]{0,50}?';

export function trimPrefix(source) {
  let s = source;

  while (s.startsWith(LAZY_PREFIX)) s = s.slice(LAZY_PREFIX.length);

  while (s.startsWith(`(?:${LAZY_PREFIX}`)) s = `(?:${s.slice(3 + LAZY_PREFIX.length)}`;

  return s;
}

export function loadRules(file = RULES_FILE) {
  const data = JSON.parse(fs.readFileSync(file, 'utf8'));
  const compile = (r) => new RegExp(trimPrefix(r.source), r.flags.includes('g') ? r.flags : r.flags + 'g');
  const compileTest = (r) => new RegExp(r.source, r.flags.replace('g', ''));
  // One combined, case-insensitive search for every rule keyword. A fragment is only tested
  // against the rules whose keywords it contains (gitleaks' own prefilter, done in one pass).
  const byKeyword = new Map();
  const alwaysRun = [];
  data.rules.forEach((r, i) => {
    if (!r.keywords.length) alwaysRun.push(i);

    for (const k of r.keywords) (byKeyword.get(k) ?? byKeyword.set(k, []).get(k)).push(i);
  });
  const escape = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const keywordRe = new RegExp([...byKeyword.keys()].sort((a, b) => b.length - a.length).map(escape).join('|'), 'gi');

  return {
    keywordRe,
    byKeyword,
    alwaysRun,
    meta: { upstreamCommit: data.upstreamCommit, generated: data.generated, count: data.rules.length },
    global: {
      regexes: data.globalAllowlist.regexes.map(compileTest),
      stopwords: data.globalAllowlist.stopwords,
    },
    rules: data.rules.map((r) => ({
      id: r.id,
      re: compile(r.regex),
      // Rules that can span lines (private keys) always see the whole fragment.
      multiline: /\\n|\\s\*|\\s\+|\[\\s\\S|\(\?s\)/.test(r.regex.source) || r.regex.flags.includes('s'),
      keywords: r.keywords,
      entropy: r.entropy,
      secretGroup: r.secretGroup,
      allowlists: r.allowlists.map((a) => ({
        condition: a.condition,
        target: a.regexTarget,
        regexes: a.regexes.map(compileTest),
        stopwords: a.stopwords,
      })),
    })),
  };
}

export function shannon(s) {
  if (!s) return 0;
  const counts = new Map();

  for (const ch of s) counts.set(ch, (counts.get(ch) ?? 0) + 1);
  let h = 0;

  for (const n of counts.values()) { const p = n / s.length; h -= p * Math.log2(p); }

  return h;
}

function allowed(al, secret, match, line) {
  const target = al.target === 'match' ? match : al.target === 'line' ? line : secret;
  const hitRe = al.regexes.length > 0 && al.regexes.some((re) => re.test(target));
  const lower = secret.toLowerCase();
  const hitStop = al.stopwords.length > 0 && al.stopwords.some((w) => lower.includes(w));

  if (al.condition === 'AND') {
    const checks = [];

    if (al.regexes.length) checks.push(hitRe);

    if (al.stopwords.length) checks.push(hitStop);

    return checks.length > 0 && checks.every(Boolean);
  }

  return hitRe || hitStop;
}

const lineAround = (text, index, len) => text.slice(lineStartNear(text, index, 4000), lineEndNear(text, index + len, 4000));

// Which rules to run and, for keyword rules, where their keywords appear.
function candidateRules(rules, text) {
  const hits = new Map(rules.alwaysRun.map((i) => [i, null]));
  rules.keywordRe.lastIndex = 0;
  let m;

  while ((m = rules.keywordRe.exec(text)) !== null) {
    for (const i of rules.byKeyword.get(m[0].toLowerCase()) ?? []) {
      if (!hits.has(i)) hits.set(i, []);
      hits.get(i)?.push([m.index, m[0].length]);
    }
  }

  return [...hits].sort((a, b) => a[0] - b[0]).map(([i, at]) => [rules.rules[i], at]);
}

// Regexes run on a window around each keyword, not on the whole fragment: gitleaks' patterns are
// linear in Go's RE2 but can backtrack in JavaScript, so a long fragment with many keyword hits (a
// Spanish text full of "consumo" for the "sumo" rule) could take seconds or be abused on purpose.
// Keyword rules match within ~300 characters of their keyword; the window is wider than that.
const WINDOW = 1000;

// Line boundaries, searched only up to `limit` characters away (a 300k-character line with
// thousands of keyword hits must not be walked once per hit).
function lineStartNear(text, pos, limit) {
  const from = Math.max(0, pos - limit);
  const i = text.slice(from, pos).lastIndexOf('\n');

  return i === -1 ? from : from + i + 1;
}

function lineEndNear(text, pos, limit) {
  const to = Math.min(text.length, pos + limit);
  const i = text.slice(pos, to).indexOf('\n');

  return i === -1 ? to : pos + i;
}

// Rules that span lines (private keys, curl commands, Kubernetes YAML) get a wider window that
// ignores line breaks, so their cost is bounded too.
const MULTILINE_WINDOW = 8000;

// A merged span never grows past this; a longer run of keyword hits is cut into pieces.
const MAX_SPAN = 64 * 1024;

function windowsFor(text, at, multiline) {
  const spans = [];

  for (const [pos, len] of at) {
    const start = multiline ? Math.max(0, pos - MULTILINE_WINDOW) : lineStartNear(text, pos, WINDOW);
    const end = multiline ? Math.min(text.length, pos + len + MULTILINE_WINDOW) : lineEndNear(text, pos + len, WINDOW);
    const last = spans.at(-1);

    if (last && start <= last[1] && end - last[0] <= MAX_SPAN) last[1] = Math.max(last[1], end);
    else spans.push([start, end]);
  }

  return spans;
}

// Returns [{ ruleId, secret, index, length }]
export function scanText(rules, text) {
  const out = [];

  for (const [rule, at] of candidateRules(rules, text)) {
    const small = text.length <= 2 * (rule.multiline ? MULTILINE_WINDOW : WINDOW);
    const spans = !at || small ? [[0, text.length]] : windowsFor(text, at, rule.multiline);

    for (const [start, end] of spans) {
      const part = start === 0 && end === text.length ? text : text.slice(start, end);
      rule.re.lastIndex = 0;
      let m;

      while ((m = rule.re.exec(part)) !== null) {
        if (m[0].length === 0) { rule.re.lastIndex++; continue; }

        const group = rule.secretGroup ?? (m.length > 1 ? m.findIndex((g, i) => i > 0 && g !== undefined) : 0);
        const secret = (group > 0 ? m[group] : m[0]) ?? m[0];

        if (!secret) continue;

        if (rule.entropy !== null && shannon(secret) < rule.entropy) continue;

        if (rules.global.regexes.some((re) => re.test(secret))) continue;
        const lowerSecret = secret.toLowerCase();

        if (rules.global.stopwords.some((w) => lowerSecret.includes(w))) continue;
        const index = start + m.index;
        const line = lineAround(text, index, m[0].length);
        // Allowlists that look at the whole match expect gitleaks' identifier prefix (up to ~100
        // characters before the keyword, trimmed from the regex above): give it back to them.
        const whole = text.slice(Math.max(0, lineStartNear(text, index, 100)), index + m[0].length);

        if (rule.allowlists.some((al) => allowed(al, secret, whole, line))) continue;
        out.push({ ruleId: rule.id, secret, index: index + Math.max(0, m[0].indexOf(secret)), length: secret.length });
      }
    }
  }

  return dedupeOverlaps(out);
}

// When two rules match the same span (e.g. a specific rule and generic-api-key), keep one.
function dedupeOverlaps(findings) {
  findings.sort((a, b) => a.index - b.index || (a.ruleId === 'generic-api-key') - (b.ruleId === 'generic-api-key'));
  const kept = [];

  for (const f of findings) {
    const prev = kept.at(-1);

    if (prev && f.index < prev.index + prev.length && f.secret.includes(prev.secret.slice(0, 8))) continue;
    kept.push(f);
  }

  return kept;
}
