#!/usr/bin/env node
// blackbrake — local, read-only audit of AI coding agent transcripts.
// No network access, no writes, no dependencies. See README "What it does NOT do".
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { auditSecrets } from '../src/secrets/audit.mjs';
import { CLASSES } from '../src/secrets/context.mjs';
import { loadRules } from '../src/secrets/engine.mjs';
import { defaultRoot, listTranscripts } from '../src/transcripts.mjs';

const pkg = JSON.parse(fs.readFileSync(path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../package.json'), 'utf8'));

const HELP = `blackbrake ${pkg.version} — see what your AI coding agent has exposed, locally.

Usage:
  blackbrake audit [--path <dir>] [--json] [--all]

Options:
  --path <dir>  Transcript folder (default: ~/.claude/projects)
  --json        Machine-readable output (secret values are never included)
  --all         Also list findings classified as examples/tests or local-dev values
  -h, --help    Show this help
  -v, --version Show version

blackbrake reads files only. It opens no network connections and writes nothing to disk.`;

function parseArgs(argv) {
  const opts = { command: null, path: null, json: false, all: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '-h' || a === '--help') opts.help = true;
    else if (a === '-v' || a === '--version') opts.version = true;
    else if (a === '--json') opts.json = true;
    else if (a === '--all') opts.all = true;
    else if (a === '--path') opts.path = argv[++i];
    else if (!opts.command) opts.command = a;
    else throw new Error(`Unknown argument: ${a}`);
  }
  return opts;
}

const plural = (n, one, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;
const fmtBytes = (b) => (b > 1e6 ? `${(b / 1e6).toFixed(0)} MB` : `${Math.max(1, Math.round(b / 1e3))} KB`);

function describeWhere(where) {
  const groups = { you: 0, agent: 0, tools: 0, snapshots: 0, other: 0 };
  for (const [k, n] of Object.entries(where)) {
    if (k === 'user') groups.you += n;
    else if (k.startsWith('tool-output')) groups.tools += n;
    else if (k.startsWith('tool-input') || k === 'assistant') groups.agent += n;
    else if (k === 'snapshot') groups.snapshots += n;
    else groups.other += n;
  }
  return Object.entries(groups).filter(([, n]) => n).map(([k, n]) => `${k} ${n}`).join(' · ');
}

function printReport({ findings, files, bytes, ms, root, rulesMeta, showAll }) {
  const real = findings.filter((f) => f.classification === CLASSES.real);
  const other = findings.filter((f) => f.classification !== CLASSES.real);
  const out = [];
  out.push(`blackbrake audit · ${root}`, '');
  out.push('EXPOSURE — secrets found in your agent transcripts');
  if (!findings.length) {
    out.push('  No secrets detected.');
  } else {
    out.push(`  ${plural(real.length, 'secret')} look real · ${plural(other.length, 'finding')} look like examples, tests or local-dev values`);
    if (real.length) {
      out.push('', '  Looks real — consider rotating these:');
      for (const f of real) {
        out.push(`    ${f.ruleId.padEnd(24)} ${f.shape.padEnd(12)} ${plural(f.copies, 'copy', 'copies')} in ${plural(f.sessions, 'session')}${f.subagentCopies ? ` (${f.subagentCopies} in subagents)` : ''}`);
        out.push(`    ${''.padEnd(24)} first ${f.origin}${f.firstSeen ? ` on ${f.firstSeen.slice(0, 10)}` : ''} · copies by: ${describeWhere(f.where)}`);
      }
    }
    if (showAll && other.length) {
      out.push('', '  Probably not real (shown because of --all):');
      for (const f of other) out.push(`    ${f.ruleId.padEnd(24)} ${f.shape.padEnd(12)} ${f.classification.padEnd(16)} ${plural(f.copies, 'copy', 'copies')}`);
    } else if (other.length) {
      out.push('', `  ${plural(other.length, 'finding')} classified as examples/tests or local-dev hidden. Use --all to review them.`);
    }
    out.push('', '  Classification is a heuristic. Check where a finding appears before rotating anything.');
  }
  out.push('', '─'.repeat(72));
  out.push(`Read ${plural(files, 'file')} (${fmtBytes(bytes)}) in ${(ms / 1000).toFixed(1)} s · 0 network connections · 0 files written`);
  out.push(`blackbrake ${pkg.version} · ${rulesMeta.count} detection rules from gitleaks (MIT) · values are never printed`);
  console.log(out.join('\n'));
}

async function main() {
  let opts;
  try { opts = parseArgs(process.argv.slice(2)); } catch (e) { console.error(e.message); console.error(HELP); process.exit(2); }
  if (opts.version) { console.log(pkg.version); return; }
  if (opts.help || !opts.command) { console.log(HELP); return; }
  if (opts.command !== 'audit') { console.error(`Unknown command: ${opts.command}\n\n${HELP}`); process.exit(2); }

  const root = path.resolve(opts.path ?? defaultRoot());
  if (!fs.existsSync(root)) { console.error(`No transcripts folder at ${root}. Use --path to point to one.`); process.exit(1); }
  const files = listTranscripts(root);
  const bytes = files.reduce((n, f) => n + fs.statSync(f).size, 0);
  const rules = loadRules();
  const t0 = Date.now();
  const findings = await auditSecrets({ root, files, rules });
  const ms = Date.now() - t0;

  if (opts.json) {
    console.log(JSON.stringify({ version: pkg.version, root, files: files.length, bytes, ms, rules: rules.meta, secrets: findings }, null, 2));
  } else {
    printReport({ findings, files: files.length, bytes, ms, root, rulesMeta: rules.meta, showAll: opts.all });
  }
}

main().catch((e) => { console.error(e.stack ?? e.message); process.exit(1); });
