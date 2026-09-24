#!/usr/bin/env node
// blackbrake — local, read-only audit of AI coding agent transcripts and setup.
// No network access, no writes, no dependencies. See README "What it does NOT do".
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createCostAnalyzer } from '../src/cost/analyzer.mjs';
import { PRICES_DATE } from '../src/cost/prices.mjs';
import { inventory } from '../src/load/inventory.mjs';
import { runAnalyzers } from '../src/run.mjs';
import { createSecretsAnalyzer } from '../src/secrets/audit.mjs';
import { CLASSES } from '../src/secrets/context.mjs';
import { loadRules } from '../src/secrets/engine.mjs';
import { defaultRoot, listTranscripts } from '../src/transcripts.mjs';

const pkg = JSON.parse(fs.readFileSync(path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../package.json'), 'utf8'));

const HELP = `blackbrake ${pkg.version} — see what your AI coding agent has exposed, loads and spends. Locally.

Usage:
  blackbrake audit [--path <dir>] [--home <dir>] [--json] [--all]

Options:
  --path <dir>  Transcript folder (default: ~/.claude/projects)
  --home <dir>  Home folder holding .claude/ and .claude.json (default: your home)
  --json        Machine-readable output (secret values are never included)
  --all         Show every finding, including ones classified as examples/tests or local-dev
  -h, --help    Show this help
  -v, --version Show version

blackbrake reads files only. It opens no network connections and writes nothing to disk.`;

function parseArgs(argv) {
  const opts = { command: null, path: null, home: null, json: false, all: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '-h' || a === '--help') opts.help = true;
    else if (a === '-v' || a === '--version') opts.version = true;
    else if (a === '--json') opts.json = true;
    else if (a === '--all') opts.all = true;
    else if (a === '--path') opts.path = argv[++i];
    else if (a === '--home') opts.home = argv[++i];
    else if (!opts.command) opts.command = a;
    else throw new Error(`Unknown argument: ${a}`);
  }
  return opts;
}

const plural = (n, one, many = `${one}s`) => `${n.toLocaleString('en-US')} ${n === 1 ? one : many}`;
const fmtBytes = (b) => (b > 1e6 ? `${(b / 1e6).toFixed(0)} MB` : `${Math.max(1, Math.round(b / 1e3))} KB`);
const usd = (n) => `$${n >= 100 ? n.toFixed(0) : n.toFixed(2)}`;
const pct = (x) => `${Math.round(x * 100)}%`;
const k = (n) => (n >= 1000 ? `${(n / 1000).toFixed(1)}k` : String(n));

function describeWhere(where) {
  const groups = { you: 0, agent: 0, tools: 0, snapshots: 0, other: 0 };
  for (const [key, n] of Object.entries(where)) {
    if (key === 'user') groups.you += n;
    else if (key.startsWith('tool-output')) groups.tools += n;
    else if (key.startsWith('tool-input') || key === 'assistant') groups.agent += n;
    else if (key === 'snapshot') groups.snapshots += n;
    else groups.other += n;
  }
  return Object.entries(groups).filter(([, n]) => n).map(([g, n]) => `${g} ${n}`).join(' · ');
}

function exposureSection(findings, showAll) {
  const real = findings.filter((f) => f.classification === CLASSES.real);
  const other = findings.filter((f) => f.classification !== CLASSES.real);
  const out = ['EXPOSURE — secrets found in your agent transcripts'];
  if (!findings.length) return [...out, '  No secrets detected.'];
  out.push(`  ${plural(real.length, 'secret')} look real · ${plural(other.length, 'finding')} look like examples, tests or local-dev values`);
  if (real.length) {
    out.push('', '  Looks real — consider rotating these:');
    for (const f of real) {
      out.push(`    ${f.ruleId.padEnd(24)} ${f.shape.padEnd(12)} ${plural(f.copies, 'copy', 'copies')} in ${plural(f.sessions, 'session')}${f.subagentCopies ? ` (${f.subagentCopies} in subagents)` : ''}`);
      out.push(`    ${''.padEnd(24)} first ${f.origin}${f.firstSeen ? ` on ${f.firstSeen.slice(0, 10)}` : ''} · copies by: ${describeWhere(f.where)}`);
    }
  }
  if (showAll && other.length) {
    out.push('', '  Probably not real:');
    for (const f of other) out.push(`    ${f.ruleId.padEnd(24)} ${f.shape.padEnd(12)} ${f.classification.padEnd(16)} ${plural(f.copies, 'copy', 'copies')}`);
  } else if (other.length) {
    out.push(`  (${plural(other.length, 'finding')} classified as not real are hidden; --all shows them)`);
  }
  out.push('  Classification is a heuristic. Check where a finding appears before rotating anything.');
  return out;
}

function loadSection(inv, showAll) {
  const c = inv.counts;
  const out = ['WHAT YOU LOAD — skills, agents, plugins and MCP servers'];
  out.push(`  ${plural(c.skills, 'skill')} · ${plural(c.agents, 'agent')} · ${plural(c.commands, 'command')} · ${plural(c.pluginsEnabled, 'plugin')} enabled · ${plural(inv.mcp.length, 'MCP server')}`);
  if (c.duplicates) out.push(`  ${plural(c.duplicates, 'item')} installed twice under the same name (counted once)`);
  const perTurn = inv.perTurnTokens.skills + inv.perTurnTokens.agents;
  if (perTurn) out.push(`  Descriptions loaded into every turn: ~${k(perTurn)} tokens (skills ~${k(inv.perTurnTokens.skills)}, agents ~${k(inv.perTurnTokens.agents)}; estimated)`);
  if (inv.usedSkills !== null && c.skills) out.push(`  Skills used at least once: ${inv.usedSkills} of ${c.skills} (${pct(inv.usedSkills / c.skills)})`);
  const posture = [];
  if (inv.posture.dangerousModePromptSkipped) posture.push('the dangerous-mode confirmation prompt is turned off');
  if (inv.posture.defaultModeBypass) posture.push('permissions are bypassed by default');
  if (posture.length) out.push(`  Settings: ${posture.join('; ')}`);
  const inCode = inv.risks.filter((r) => r.inCode);
  const inDocs = inv.risks.filter((r) => !r.inCode);
  if (!inv.risks.length) out.push('  No risky patterns found in installed add-ons.');
  else {
    out.push(`  Patterns worth a look: ${plural(inCode.length, 'in executable code', 'in executable code')} · ${plural(inDocs.length, 'in documentation', 'in documentation')}`);
    const list = showAll ? inv.risks : inCode.slice(0, 10);
    for (const r of list) out.push(`    ${r.label.padEnd(48)} ${r.owner}  (${r.inCode ? 'code' : 'docs'})`);
    if (!showAll && inCode.length > 10) out.push(`    … ${inCode.length - 10} more in code; --all lists everything`);
    if (!showAll && inDocs.length) out.push('    Matches in documentation are often examples inside security skills; --all lists them.');
  }
  return out;
}

function spendSection(cost) {
  const out = ['SPEND — where your agent spend concentrates'];
  if (!cost.episodes) return [...out, '  No usage data found.'];
  out.push(`  ${usd(cost.total)} across ${plural(cost.episodes, 'episode')} (API list prices of ${PRICES_DATE}; on a subscription this is a unit of effort, not a bill)`);
  out.push(`  Your costliest 10% of episodes (${cost.topN}) account for ${pct(cost.topShare)} of it · typical episode ${usd(cost.p50)} · 90th percentile ${usd(cost.p90)}`);
  if (cost.worst.length) {
    out.push('  Costliest episodes:');
    for (const e of cost.worst) {
      const dur = e.hours !== null && e.hours >= 1 ? ` · ${e.hours.toFixed(0)} h` : '';
      out.push(`    ${usd(e.cost).padStart(8)}  ${e.date ?? '          '}  ${plural(e.turns, 'turn')} · ${plural(e.tools, 'tool call')}${e.subagents ? ` · ${plural(e.subagents, 'subagent')}` : ''}${dur}`);
    }
  }
  if (cost.floor.sessions) out.push(`  Fixed context per turn (median): ~${k(cost.floor.medianTokens)} tokens, ${pct(cost.floor.share)} of main-thread spend`);
  if (cost.unknownModels.length) out.push(`  Unknown models priced as mid-tier: ${cost.unknownModels.join(', ')}`);
  return out;
}

async function main() {
  let opts;
  try { opts = parseArgs(process.argv.slice(2)); } catch (e) { console.error(e.message); console.error(HELP); process.exit(2); }
  if (opts.version) { console.log(pkg.version); return; }
  if (opts.help || !opts.command) { console.log(HELP); return; }
  if (opts.command !== 'audit') { console.error(`Unknown command: ${opts.command}\n\n${HELP}`); process.exit(2); }

  const home = path.resolve(opts.home ?? os.homedir());
  const root = path.resolve(opts.path ?? (opts.home ? path.join(home, '.claude', 'projects') : defaultRoot()));
  if (!fs.existsSync(root)) { console.error(`No transcripts folder at ${root}. Use --path to point to one.`); process.exit(1); }

  const t0 = Date.now();
  const files = listTranscripts(root);
  const bytes = files.reduce((n, f) => n + fs.statSync(f).size, 0);
  const rules = loadRules();
  const [secrets, cost] = await runAnalyzers({ root, files, analyzers: [createSecretsAnalyzer(rules), createCostAnalyzer()] });
  const inv = inventory({ home });
  const ms = Date.now() - t0;

  if (opts.json) {
    console.log(JSON.stringify({ version: pkg.version, root, files: files.length, bytes, ms, rules: rules.meta, pricesDate: PRICES_DATE, secrets, load: inv, spend: cost }, null, 2));
    return;
  }
  const out = [`blackbrake audit · ${root}`, '', ...exposureSection(secrets, opts.all), '', ...loadSection(inv, opts.all), '', ...spendSection(cost)];
  out.push('', '─'.repeat(78));
  out.push(`Read ${plural(files.length, 'file')} (${fmtBytes(bytes)}) in ${(ms / 1000).toFixed(1)} s · 0 network connections · 0 files written`);
  out.push(`blackbrake ${pkg.version} · ${rules.meta.count} detection rules from gitleaks (MIT) · secret values are never printed`);
  console.log(out.join('\n'));
}

main().catch((e) => { console.error(e.stack ?? e.message); process.exit(1); });
