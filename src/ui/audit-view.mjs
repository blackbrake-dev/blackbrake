// The `audit` report, in blackbrake's look. Pure functions: data in, lines out.
// Three views: a calm summary (default), the full details, and tailored precautions.
// Data stays in English; every string a person reads goes through t() (see src/i18n.mjs).
import { dec, num, plural, t } from '../i18n.mjs';
import { CLASSES } from '../secrets/context.mjs';
import { clean } from '../text.mjs';
import { band, bar, padEnd, padStart, screen, width, withLogo, wrapText } from './term.mjs';

const fmtBytes = (b) => (b > 1e6 ? `${(b / 1e6).toFixed(0)} MB` : b >= 1e3 ? `${Math.round(b / 1e3)} KB` : `${b} B`);

const usd = (n) => `$${n >= 100 ? num(Math.round(n)) : dec(n, 2)}`;

const pct = (x) => `${Math.round(x * 100)}%`;

const k = (n) => (n >= 1000 ? `${dec(n / 1000, 1)}k` : String(n));

const tidy = (lines) => lines.map((l) => (width(l) > 0 ? l : ''));

function describeWhere(where) {
  const groups = { you: 0, agent: 0, tools: 0, snapshots: 0, stored: 0, other: 0 };

  for (const [key, n] of Object.entries(where)) {
    if (key.startsWith('store:')) groups.stored += n;
    else if (key === 'user') groups.you += n;
    else if (key.startsWith('tool-output')) groups.tools += n;
    else if (key.startsWith('tool-input') || key === 'assistant') groups.agent += n;
    else if (key === 'snapshot') groups.snapshots += n;
    else groups.other += n;
  }

  return Object.entries(groups).filter(([, n]) => n).map(([g, n]) => `${t(g)} ${n}`).join(' · ');
}

function header(p, { version, root, files, storeFiles = 0, bytes, ms }, pose = 'idle') {
  return withLogo(p, [
    `${p.bold(p.cream('blackbrake audit'))}${p.faint(`  v${version}`)}`,
    p.faint(clean(root, 200)),
    p.faint(`${plural(files, 'transcript')} + ${plural(storeFiles, 'other file')} · ${fmtBytes(bytes)} · ${dec(ms / 1000, 1)} s`),
    p.amber(t('nothing left this machine')),
  ], pose);
}

// ---------- summary: one idea per line, details on demand ----------
const LABEL = 18;

const row = (p, label, text) => `  ${padEnd(label ? p.bold(p.orange(t(label))) : '', LABEL)}${text}`;

export function renderAudit(p, data, { adviceCount = 0, interactive = false } = {}) {
  const real = data.secrets.filter((f) => f.classification === CLASSES.real);
  const others = data.secrets.length - real.length;
  const inv = data.load;
  const s = data.spend;
  // The mascot reacts to the result: alarmed by real secrets, pleased when there are none.
  const out = ['', ...header(p, data, real.length ? 'alert' : 'happy'), ''];

  // Exposure
  if (!data.secrets.length) out.push(row(p, 'EXPOSURE', `${p.amber('✓')} ${t('no secrets found')}`));
  else {
    const head = real.length ? `${p.coral('●')} ${p.cream(t('{n} look real', { n: plural(real.length, 'secret') }))}` : `${p.amber('✓')} ${t('none look real')}`;
    out.push(row(p, 'EXPOSURE', `${head}${others ? p.faint(`   ${t('{n} more look like examples', { n: others })}`) : ''}`));

    for (const f of real.slice(0, 3)) out.push(row(p, '', `  ${padEnd(f.ruleId, 20)} ${p.coral(padEnd(f.shape, 17))} ${p.faint(t(f.origin))}`));

    if (real.length > 3) out.push(row(p, '', p.faint(`  + ${t('{n} more', { n: real.length - 3 })}`)));
  }

  // What you load
  out.push('');
  const warnings = [];
  const riskyCode = new Set(inv.risks.filter((r) => r.inCode).map((r) => r.owner)).size;

  if (riskyCode) warnings.push(t('{n} with a risky pattern', { n: plural(riskyCode, 'add-on') }));

  if (inv.posture.dangerousModePromptSkipped) warnings.push(t('bypass-mode warning off'));

  if (inv.posture.defaultModeBypass) warnings.push(t('permissions bypassed by default'));
  const settings = (inv.configIssues ?? []).length + (inv.mcpIssues ?? []).length;

  if (settings) warnings.push(plural(settings, 'risky setting'));

  if (data.claudeCode?.open?.length) warnings.push(t('Claude Code {v} outdated', { v: data.claudeCode.version }));
  out.push(row(p, 'WHAT YOU LOAD', warnings.length ? `${p.amber('▲')} ${p.cream(warnings.join(' · '))}` : `${p.amber('✓')} ${t('nothing risky found')}`));
  const c = inv.counts;
  const perTurn = inv.perTurnTokens.skills + inv.perTurnTokens.agents;
  const used = inv.usedSkills !== null && c.skills ? `, ${t('{n} ever used', { n: inv.usedSkills })}` : '';
  out.push(row(p, '', p.faint(`  ${plural(c.skills, 'skill')}${used} · ${plural(inv.mcp.length, 'MCP server')}${perTurn ? ` · ${t('~{n} tokens loaded every turn', { n: k(perTurn) })}` : ''}`)));

  // Spend
  out.push('');

  if (!s.episodes) out.push(row(p, 'SPEND', p.faint(t('no usage data found'))));
  else {
    out.push(row(p, 'SPEND', `${p.cream(t('{usd} over {n}', { usd: usd(s.total), n: plural(s.episodes, 'episode') }))}${p.faint(' · ')}${p.cream(t('costliest 10% = {pct}', { pct: pct(s.topShare) }))}`));
    out.push(row(p, '', p.faint(`  ${t('typical {a} · 90th percentile {b} · list prices, not a bill', { a: usd(s.p50), b: usd(s.p90) })}`)));
  }

  out.push('', `  ${p.faint('─'.repeat(64))}`);

  if (adviceCount) out.push(`  ${p.onAmber(p.ink(p.bold(` ${t('NEXT')} `)))} ${p.cream(t('{n} tailored to these results', { n: plural(adviceCount, 'precaution') }))}${interactive ? '' : p.faint('  ·  blackbrake audit --advice')}`);
  else out.push(`  ${p.amber('✓')} ${p.cream(t('Nothing to fix right now.'))}`);

  if (!interactive) out.push(`  ${p.faint(t('Full details: blackbrake audit --details'))}`);
  out.push('');

  return tidy(out);
}

// ---------- precautions ----------
const center = (s) => {
  const pad = Math.max(0, 10 - s.length);

  return `${' '.repeat(Math.floor(pad / 2))}${s}${' '.repeat(Math.ceil(pad / 2))}`;
};

const BADGE = {
  critical: (p) => p.onCoral(p.ink(p.bold(center(t('CRITICAL'))))),
  high: (p) => p.onAmber(p.ink(p.bold(center(t('HIGH'))))),
  medium: (p) => p.onBrown(p.cream(center(t('MEDIUM')))),
  info: (p) => p.faint(center(t('INFO'))),
};

export function renderAdvice(p, advice, { cols = 96 } = {}) {
  const out = screen(p, t('PRECAUTIONS'), t('tailored to your audit'), cols, { pose: 'think', line: t('Most important first.') });
  const indent = ' '.repeat(18);
  const max = Math.max(30, cols - indent.length - 4);

  if (!advice.length) return tidy([...out, `  ${p.amber('✓')} ${t('Nothing to fix right now. Run the audit again after new sessions.')}`, '']);
  advice.forEach((a, i) => {
    out.push(`  ${p.faint(padStart(String(i + 1), 2))}  ${BADGE[a.level](p)}  ${p.bold(p.cream(a.title))}`);

    for (const l of wrapText(a.why, max)) out.push(`${indent}${p.faint(l)}`);

    for (const s of a.steps) wrapText(s, max).forEach((l, j) => out.push(`${indent}${j ? '  ' : `${p.orange('›')} `}${l}`));
    out.push('');
  });

  return tidy(out);
}

// ---------- full details (previous full report) ----------
function exposure(p, findings, showAll) {
  const real = findings.filter((f) => f.classification === CLASSES.real);
  const other = findings.filter((f) => f.classification !== CLASSES.real);
  const out = [band(p, t('EXPOSURE'), t('secrets found in your agent transcripts')), ''];

  if (!findings.length) return [...out, `  ${p.amber('✓')} ${t('No secrets detected.')}`];
  out.push(`  ${p.coral('●')} ${p.cream(t('{n} look real', { n: plural(real.length, 'secret') }))}   ${p.faint(`○ ${t('{n} look like examples, tests or local-dev values', { n: plural(other.length, 'finding') })}`)}`);

  if (real.length) {
    out.push('');

    for (const f of real) {
      out.push(`  ${p.coral('●')} ${p.cream(padEnd(f.ruleId, 24))} ${p.coral(padEnd(f.shape, 17))} ${plural(f.copies, 'copy', 'copies')} · ${plural(f.sessions, 'session')}${f.subagentCopies ? p.faint(` (${t('{n} in subagents', { n: f.subagentCopies })})`) : ''}`);
      out.push(`    ${p.faint(`${t('first {origin}', { origin: t(f.origin) })}${f.firstSeen ? ` ${t('on {d}', { d: f.firstSeen.slice(0, 10) })}` : ''} · ${t('copies by:')} ${describeWhere(f.where)}`)}`);

      if (f.stores?.length) out.push(`    ${p.faint(`${t('also kept in:')} ${f.stores.map((x) => t(x)).join(', ')}`)}`);
    }

    out.push('', `    ${p.faint(t('Classification is a heuristic: check where a finding appears before rotating.'))}`);
  }

  if (showAll && other.length) {
    out.push('', `  ${p.faint(t('Probably not real:'))}`);

    for (const f of other) out.push(`  ${p.faint(`○ ${padEnd(f.ruleId, 24)} ${padEnd(f.shape, 17)} ${padEnd(t(f.classification), 16)} ${plural(f.copies, 'copy', 'copies')}`)}`);
  } else if (other.length) {
    out.push(`  ${p.faint(t('{n} classified as not real are hidden · --all shows them', { n: plural(other.length, 'finding') }))}`);
  }

  return out;
}

function load(p, inv, showAll) {
  const c = inv.counts;
  const out = [band(p, t('WHAT YOU LOAD'), t('skills, agents, plugins and MCP servers')), ''];
  const stat = (n, label) => `${p.cream(num(n))} ${p.faint(t(label))}`;
  out.push(`  ${[stat(c.skills, 'skills'), stat(c.agents, 'agents'), stat(c.commands, 'commands'), stat(c.pluginsEnabled, 'plugins on'), stat(inv.mcp.length, 'MCP servers')].join('   ')}`);

  if (c.duplicates) out.push(`  ${p.faint(t('{n} installed twice under the same name (counted once)', { n: plural(c.duplicates, 'item') }))}`);
  const perTurn = inv.perTurnTokens.skills + inv.perTurnTokens.agents;
  const label = (s) => padEnd(p.faint(t(s)), 26);

  if (perTurn) out.push(`  ${label('Loaded on every turn')}${p.cream(t('~{n} tokens', { n: k(perTurn) }))} ${p.faint(t('(skills ~{a}, agents ~{b}; estimated)', { a: k(inv.perTurnTokens.skills), b: k(inv.perTurnTokens.agents) }))}`);

  if (inv.usedSkills !== null && c.skills) out.push(`  ${label('Skills ever used')}${bar(p, inv.usedSkills / c.skills, 20, 'amber')} ${p.cream(t('{a} of {b}', { a: inv.usedSkills, b: c.skills }))} ${p.faint(`(${pct(inv.usedSkills / c.skills)})`)}`);

  if (inv.posture.dangerousModePromptSkipped) out.push(`  ${p.amber('▲')} ${t('the bypass-mode confirmation prompt is turned off')}`);

  if (inv.posture.defaultModeBypass) out.push(`  ${p.amber('▲')} ${t('permissions are bypassed by default')}`);

  for (const i of inv.configIssues ?? []) out.push(`  ${p.amber('▲')} ${t(i.where)}: ${t(i.issue)}`);

  for (const m of inv.mcpIssues ?? []) out.push(`  ${p.amber('▲')} MCP ${m.server} (${m.source}): ${t(m.issue)}`);

  if (inv.posture.claudeDirExposure) out.push(`  ${p.amber('▲')} ${t('~/.claude is inside {where}', { where: inv.posture.claudeDirExposure.kind === 'git' ? t('a git repository') : inv.posture.claudeDirExposure.where })}`);
  const inCode = inv.risks.filter((r) => r.inCode);
  const inDocs = inv.risks.filter((r) => !r.inCode);

  if (!inv.risks.length) return [...out, `  ${p.amber('✓')} ${t('No risky patterns found in installed add-ons.')}`];
  out.push(`  ${p.cream(t('Patterns worth a look:'))} ${plural(inCode.length, 'in code', 'in code')} ${p.faint(`· ${plural(inDocs.length, 'in docs', 'in docs')}`)}`);
  const list = showAll ? inv.risks : inCode.slice(0, 10);

  for (const r of list) out.push(`  ${r.inCode ? p.coral('●') : p.faint('○')} ${padEnd(t(r.label), 48)} ${p.faint(`${r.owner} (${t(r.inCode ? 'code' : 'docs')})`)}`);

  if (!showAll && inCode.length > 10) out.push(`  ${p.faint(t('… {n} more in code · --all lists everything', { n: inCode.length - 10 }))}`);

  if (!showAll && inDocs.length) out.push(`  ${p.faint(t('Matches in docs are often examples inside security skills · --all lists them'))}`);

  return out;
}

function spendDetails(p, cost, pricesDate) {
  const out = [band(p, t('SPEND'), t('where your agent spend concentrates')), ''];

  if (!cost.episodes) return [...out, `  ${p.faint(t('No usage data found.'))}`];
  out.push(`  ${p.cream(usd(cost.total))} ${t('across {n}', { n: plural(cost.episodes, 'episode') })}  ${p.faint(t('at API list prices of {d}', { d: pricesDate }))}`);
  out.push(`  ${p.faint(t('On a subscription this is a unit of effort, not a bill.'))}`, '');
  out.push(`  ${padEnd(p.faint(t('Costliest 10% of episodes')), 30)}${bar(p, cost.topShare, 24)} ${p.cream(pct(cost.topShare))} ${p.faint(t('of spend'))}`);
  out.push(`  ${padEnd(p.faint(t('Typical episode')), 30)}${p.cream(usd(cost.p50))}   ${p.faint(t('90th percentile'))} ${p.cream(usd(cost.p90))}`);

  if (cost.worst.length) {
    out.push('', `  ${p.faint(t('Costliest episodes'))}`);

    for (const e of cost.worst) {
      const dur = e.hours !== null && e.hours >= 1 ? ` · ${e.hours.toFixed(0)} h` : '';
      out.push(`  ${p.orange(padStart(usd(e.cost), 8))}  ${p.faint(e.date ?? '          ')}  ${plural(e.turns, 'turn')} · ${plural(e.tools, 'tool call')}${e.subagents ? ` · ${plural(e.subagents, 'subagent')}` : ''}${dur}`);
    }
  }

  if (cost.floor.sessions) out.push('', `  ${padEnd(p.faint(t('Fixed context per turn')), 30)}${p.cream(t('~{n} tokens', { n: k(cost.floor.medianTokens) }))} ${p.faint(t('median · {pct} of main-thread spend', { pct: pct(cost.floor.share) }))}`);

  if (cost.unknownModels.length) out.push(`  ${p.faint(`${t('Unknown models priced as mid-tier:')} ${cost.unknownModels.map((m) => clean(m, 60)).join(', ')}`)}`);

  return out;
}

export function renderDetails(p, data, { all = false } = {}) {
  const cc = data.claudeCode;

  return tidy([
    '',
    ...exposure(p, data.secrets, all),
    '',
    ...load(p, data.load, all),
    ...(cc ? ['', `  ${p.faint('Claude Code')} ${p.cream(cc.version)} ${p.faint(`${t('in your latest session ({d})', { d: cc.seen })} · ${cc.open.length ? t('{n} fixed in later versions', { n: plural(cc.open.length, 'published advisory', 'published advisories') }) : t('no published advisories open')}`)}`] : []),
    '',
    ...spendDetails(p, data.spend, data.pricesDate),
    '',
    `  ${p.faint(t('blackbrake {v} · {n} detection rules from gitleaks and betterleaks (MIT) · secret values are never printed', { v: data.version, n: data.rules.count }))}`,
    '',
  ]);
}
