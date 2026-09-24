// Secret detection using the gitleaks default rule set (vendored, MIT). Semantics follow
// gitleaks: keyword prefilter, first capture group (or secretGroup) as the secret, Shannon
// entropy threshold, per-rule and global allowlists and stopwords.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const RULES_FILE = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../vendor/gitleaks.rules.json');

export function loadRules(file = RULES_FILE) {
  const data = JSON.parse(fs.readFileSync(file, 'utf8'));
  const compile = (r) => new RegExp(r.source, r.flags.includes('g') ? r.flags : r.flags + 'g');
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

const lineAround = (text, index, len) => {
  const start = text.lastIndexOf('\n', index) + 1;
  const endNl = text.indexOf('\n', index + len);
  return text.slice(start, endNl === -1 ? text.length : endNl);
};

// Returns [{ ruleId, secret, index, length }]
function candidateRules(rules, text) {
  const idx = new Set(rules.alwaysRun);
  rules.keywordRe.lastIndex = 0;
  let m;
  while ((m = rules.keywordRe.exec(text)) !== null) {
    for (const i of rules.byKeyword.get(m[0].toLowerCase()) ?? []) idx.add(i);
  }
  return [...idx].sort((a, b) => a - b).map((i) => rules.rules[i]);
}

export function scanText(rules, text) {
  const out = [];
  for (const rule of candidateRules(rules, text)) {
    rule.re.lastIndex = 0;
    let m;
    while ((m = rule.re.exec(text)) !== null) {
      if (m[0].length === 0) { rule.re.lastIndex++; continue; }
      const group = rule.secretGroup ?? (m.length > 1 ? m.findIndex((g, i) => i > 0 && g !== undefined) : 0);
      const secret = (group > 0 ? m[group] : m[0]) ?? m[0];
      if (!secret) continue;
      if (rule.entropy !== null && shannon(secret) < rule.entropy) continue;
      if (rules.global.regexes.some((re) => re.test(secret))) continue;
      const lowerSecret = secret.toLowerCase();
      if (rules.global.stopwords.some((w) => lowerSecret.includes(w))) continue;
      const line = lineAround(text, m.index, m[0].length);
      if (rule.allowlists.some((al) => allowed(al, secret, m[0], line))) continue;
      out.push({ ruleId: rule.id, secret, index: m.index + Math.max(0, m[0].indexOf(secret)), length: secret.length });
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
