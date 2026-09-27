// Converts the vendored gitleaks default config (MIT, see THIRD_PARTY_NOTICES) into a JSON rule
// set that JavaScript's RegExp engine can run on Node >= 20.
//
// Go's RE2 and JavaScript differ in a few places. Conversions applied:
//   (?i) / (?i:...)        -> the whole regex becomes case-insensitive ("i" flag). This can only
//                             widen a match, never lose one, so recall is preserved.
//   (?-i:...) / (?-i)      -> dropped: the group simply stays case-insensitive. Inline modifier
//                             groups only exist in Node >= 23, and widening keeps recall.
//   (?s) / (?m)            -> "s" / "m" flags
//   (?P<name>              -> (?<name>
//   \A  \z                 -> ^  $
//   [[:alnum:]] and friends -> explicit ranges
// Rules that still fail to compile are dropped and listed, so the gap is visible, not silent.
//
// Usage: node scripts/build-rules.mjs  (reads vendor/src/gitleaks.toml, writes vendor/gitleaks.rules.json)
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const SRC = path.join(root, 'vendor/src/gitleaks.toml');
const OUT = path.join(root, 'vendor/gitleaks.rules.json');
const UPSTREAM_COMMIT = process.env.GITLEAKS_COMMIT ?? 'unknown';

// ---------------------------------------------------------------------------------------------
// Minimal parser for the subset of TOML used by gitleaks.toml: tables, arrays of tables, and
// key = value where value is a '''literal''', "basic" string, number, or an array of strings.
function parseGitleaksToml(text) {
  const doc = { allowlist: {}, rules: [] };
  let target = null;
  let i = 0;
  const lines = text.split(/\r?\n/);

  const readString = (s, start) => {
    if (s.startsWith("'''", start)) {
      const end = s.indexOf("'''", start + 3);
      return { value: s.slice(start + 3, end), next: end + 3 };
    }
    if (s[start] === "'") {
      const end = s.indexOf("'", start + 1);
      return { value: s.slice(start + 1, end), next: end + 1 };
    }
    if (s[start] === '"') {
      let j = start + 1, out = '';
      while (s[j] !== '"') {
        if (s[j] === '\\') { out += JSON.parse(`"${s[j]}${s[j + 1]}"`); j += 2; } else out += s[j++];
      }
      return { value: out, next: j + 1 };
    }
    return null;
  };

  while (i < lines.length) {
    const line = lines[i].trim();
    i++;
    if (!line || line.startsWith('#')) continue;
    if (line === '[allowlist]') { target = doc.allowlist; continue; }
    if (line === '[[rules]]') { target = {}; doc.rules.push(target); continue; }
    if (line === '[[rules.allowlists]]') {
      const rule = doc.rules.at(-1);
      target = {};
      (rule.allowlists ??= []).push(target);
      continue;
    }
    const m = line.match(/^([A-Za-z]+)\s*=\s*(.*)$/);
    if (!m || !target) continue;
    const [, key, rest] = m;
    if (rest.startsWith("'''") && rest.indexOf("'''", 3) === -1) {
      // Multi-line literal string (betterleaks filters and validators).
      let buf = rest.slice(3);
      while (i < lines.length && !lines[i].includes("'''")) buf += '\n' + lines[i++];
      if (i < lines.length) buf += '\n' + lines[i++].split("'''")[0];
      target[key] = buf;
    } else if (rest.startsWith('[')) {
      // Array, possibly spanning several lines.
      let buf = rest;
      while (!/\]\s*(#.*)?$/.test(buf.trim())) buf += '\n' + lines[i++];
      const values = [];
      let j = 1;
      while (j < buf.length) {
        const ch = buf[j];
        if (ch === ']') break;
        const s = readString(buf, j);
        if (s) { values.push(s.value); j = s.next; } else j++;
      }
      target[key] = values;
    } else {
      const s = readString(rest, 0);
      if (s) target[key] = s.value;
      else if (/^-?\d+(\.\d+)?/.test(rest)) target[key] = Number.parseFloat(rest);
      else target[key] = rest;
    }
  }
  return doc;
}

// ---------------------------------------------------------------------------------------------
const POSIX = {
  alnum: 'a-zA-Z0-9', alpha: 'a-zA-Z', digit: '0-9', lower: 'a-z', upper: 'A-Z',
  space: '\\s', xdigit: '0-9A-Fa-f', word: '\\w', punct: '!-\\/:-@\\[-`{-~',
};

export function convertRegex(src) {
  const flags = new Set();
  let re = src;
  re = re.replace(/\(\?([ims]+)\)/g, (_, f) => { for (const c of f) flags.add(c); return ''; });
  re = re.replace(/\(\?([ims]+):/g, (_, f) => { for (const c of f) flags.add(c); return '(?:'; });
  re = re.replace(/\(\?-[ims]+:/g, '(?:').replace(/\(\?-[ims]+\)/g, '');
  re = re.replace(/\(\?P</g, '(?<');
  re = re.replace(/\\A/g, '^').replace(/\\z/g, '$');
  re = re.replace(/\[:(\w+):\]/g, (all, name) => POSIX[name] ?? all);
  const f = [...flags].join('');
  new RegExp(re, f); // throws if JavaScript cannot compile it
  return { source: re, flags: f };
}

function convertList(list = [], dropped, where) {
  const out = [];
  for (const r of list) {
    try { out.push(convertRegex(r)); } catch (e) { dropped.push({ where, regex: r, error: e.message }); }
  }
  return out;
}

const doc = parseGitleaksToml(fs.readFileSync(SRC, 'utf8'));
const dropped = [];
const rules = [];
for (const r of doc.rules) {
  if (!r.regex) continue; // path-only rules do not apply to transcript text
  let regex;
  try { regex = convertRegex(r.regex); } catch (e) { dropped.push({ where: r.id, regex: r.regex, error: e.message }); continue; }
  rules.push({
    id: r.id,
    source: 'gitleaks',
    description: r.description ?? '',
    regex,
    keywords: (r.keywords ?? []).map((k) => k.toLowerCase()),
    entropy: typeof r.entropy === 'number' ? r.entropy : null,
    secretGroup: typeof r.secretGroup === 'number' ? r.secretGroup : null,
    allowlists: (r.allowlists ?? []).map((a) => ({
      condition: a.condition ?? 'OR',
      regexTarget: a.regexTarget ?? 'secret',
      regexes: convertList(a.regexes, dropped, `${r.id}.allowlist`),
      stopwords: (a.stopwords ?? []).map((s) => s.toLowerCase()),
    })),
  });
}

// Betterleaks (MIT, by the gitleaks author) adds rules gitleaks does not have, many for AI
// providers (OpenRouter, DeepSeek, Groq, xAI, Mistral, Gemini, Cursor, Supabase…). Only rules with
// a new id are taken; gitleaks keeps the shared ones. From each: regex, keywords, and the entropy
// floor of its Expr filter. Not taken: other Expr filters, live validation (network: never, N0),
// multi-part rules and skipReport helpers.
const BL = path.join(root, 'vendor/src/betterleaks.toml');
const BL_COMMIT = process.env.BETTERLEAKS_COMMIT ?? 'unknown';
let fromBetterleaks = 0;
if (fs.existsSync(BL)) {
  const known = new Set(rules.map((r) => r.id));
  for (const r of parseGitleaksToml(fs.readFileSync(BL, 'utf8')).rules) {
    if (!r.regex || known.has(r.id) || r.components || r.skipReport === 'true' || r.skipReport === true) continue;
    let regex;
    try { regex = convertRegex(r.regex); } catch (e) { dropped.push({ where: `betterleaks:${r.id}`, regex: r.regex, error: e.message }); continue; }
    const floor = /entropy\(finding\["secret"\]\)\s*<=?\s*([\d.]+)/.exec(r.filter ?? '');
    rules.push({
      id: r.id,
      source: 'betterleaks',
      description: r.description ?? '',
      regex,
      keywords: (r.keywords ?? []).map((k) => k.toLowerCase()),
      entropy: floor ? Number.parseFloat(floor[1]) + 0.001 : null,
      secretGroup: typeof r.secretGroup === 'number' ? r.secretGroup : null,
      allowlists: [],
    });
    fromBetterleaks++;
  }
}

const out = {
  source: 'gitleaks default config (config/gitleaks.toml) + new rules from betterleaks (config/betterleaks.toml)',
  upstream: 'https://github.com/gitleaks/gitleaks',
  upstreamCommit: UPSTREAM_COMMIT,
  betterleaksCommit: BL_COMMIT,
  license: 'MIT, Copyright (c) 2019 Zachary Rice (gitleaks); MIT, Copyright (c) 2026 Zachary Rice (betterleaks). See THIRD_PARTY_NOTICES.',
  generated: new Date().toISOString().slice(0, 10),
  globalAllowlist: {
    regexes: convertList(doc.allowlist.regexes, dropped, 'global.allowlist'),
    stopwords: (doc.allowlist.stopwords ?? []).map((s) => s.toLowerCase()),
  },
  rules,
  dropped,
};
fs.writeFileSync(OUT, JSON.stringify(out, null, 1) + '\n');
console.log(`rules: ${rules.length} converted (${fromBetterleaks} from betterleaks), ${dropped.length} regexes dropped`);
for (const d of dropped) console.log(`  dropped ${d.where}: ${d.error}`);
