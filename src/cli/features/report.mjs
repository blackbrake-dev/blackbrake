// Opt-in reports to the blackbrake team (guard-design#6x §5): write a local file → show it → the
// person edits or deletes it → they choose whether to email it. Nothing is sent by blackbrake: no
// network, no account, no server. The pure core (format, validator, aggregates, mailto) is src/report/
// (F6.7); the files are src/report/store.mjs; opening the mail app is src/report/open.mjs.
//
//   blackbrake report [product|security]   the wizard (terminal + a person: requireHuman)
//   blackbrake report list | show <name> | check <name>   read only; also work in a pipe
//   blackbrake report send <name>          address and subject; the mail app only on a key press
//   blackbrake report delete <name>|--all  --all asks for a typed word
//
// Everything that touches the machine goes through `deps`, so the tests never do.
import path from 'node:path';
import readline from 'node:readline';
import { isBackgroundRunning } from '../../guard/background.mjs';
import { confirmTyped, KIND } from '../../guard/cli.mjs';
import { requireHuman } from '../../guard/human.mjs';
import { isPaused } from '../../guard/pause.mjs';
import { detectedHarnesses } from '../../guard/registry.mjs';
import { getMode, getSetting, readLog } from '../../guard/state.mjs';
import { getLang, t } from '../../i18n.mjs';
import { aggregateReport } from '../../report/aggregate.mjs';
import { AFFECTED_PARTS, buildReport } from '../../report/build.mjs';
import { buildMailto } from '../../report/mailto.mjs';
import { openMailto } from '../../report/open.mjs';
import { deleteReport, listReports, readReport, REPORT_DAYS, reportKind, reportsDir, saveReport } from '../../report/store.mjs';
import { AUTO_SECTIONS, validateFreeText, validateReport } from '../../report/validate.mjs';
import { loadRules } from '../../secrets/engine.mjs';
import { clean } from '../../text.mjs';
import { checklist, select } from '../../ui/menu.mjs';
import { columns, screen } from '../../ui/term.mjs';
import { realDeps as uninstallDeps } from './uninstall-menu.mjs';

const defaultPrint = (lines) => console.log(lines.join('\n'));

// What the person types, per kind (design §5.3). `choices` fields pick from a closed list.
const FIELDS = {
  product: [
    { heading: 'Summary', label: () => t('Summary (one line)'), maxChars: 120, required: true },
    { heading: 'What happened', label: () => t('What happened'), maxChars: 1500, multiline: true },
    { heading: 'What you expected', label: () => t('What you expected'), maxChars: 600, multiline: true },
  ],
  security: [
    { heading: 'Affected part', label: () => t('Which part is affected?'), choices: AFFECTED_PARTS },
    { heading: 'Summary', label: () => t('Summary (one line)'), maxChars: 120, required: true },
    { heading: 'Steps', label: () => t('Steps to see it'), maxChars: 1000, multiline: true },
    { heading: 'Impact', label: () => t('Impact'), maxChars: 400, multiline: true },
  ],
};

// A problem as a generic reason (and where): never the text it is about.
const REASONS = {
  size: 'it is too long',
  lines: 'it is too long',
  'line-length': 'a line is too long',
  encoding: 'it is not plain UTF-8 text',
  nfc: 'it has unusual combined characters; type them again',
  grammar: 'a line starts like a list, a heading or a numbered item',
  'heading-in-field': 'a line starts like a list, a heading or a numbered item',
  heading: 'its headings were changed',
  'heading-duplicate': 'its headings were changed',
  title: 'its first line was changed',
  meta: 'its second line was changed',
  multiline: 'only one line goes here',
  'trailing-space': 'a line ends with spaces',
  link: 'links and web or mail addresses are not allowed',
  'privacy-hex': 'it has something that looks like an identifier',
  'privacy-ip': 'it has something that looks like an IP address',
  'privacy-token': 'it has something that looks like a token',
  'privacy-identity': 'it has your user or computer name',
  'privacy-path': 'it has a file path',
  'privacy-secret': 'it has something that looks like a secret',
  'version-mismatch': 'it was made by another version of blackbrake',
};

export function problemLines(p, problems) {
  return problems.slice(0, 10).map((x) => {
    const why = t(REASONS[x.code] ?? (x.rule === 'V4' ? 'it has a character that is not allowed here' : 'it is not a valid report'));
    const at = x.line ? ` ${t('(line {n})', { n: x.line })}` : '';

    return `    ${p.coral('✗')} ${p.cream(why)}${p.faint(at)}`;
  });
}

// ---------- the automatic data (aggregates only, all boxes off by default) ----------

export function gatherData({ home, days = 7, version } = {}) {
  const since = new Date(Date.now() - days * 864e5).toISOString();
  const kinds = {};
  const actions = {};
  const byRule = {};
  const add = (map, key) => { map[key] = (map[key] ?? 0) + 1; };

  for (const e of readLog(home, { since })) {
    if (!Object.hasOwn(KIND, e.kind)) continue;
    add(kinds, e.kind);

    // Only the actions guard writes (review B: anything that can append to the log could otherwise
    // put a word of its own into the activity section).
    if (ACTIONS.has(e.action)) add(actions, e.action);

    // Only secret findings carry a rule id; other kinds use that field for other things.
    if (/^secret-/.test(e.kind) && e.rule) add(byRule, e.rule);
  }

  let protectedIds = [];

  try { protectedIds = uninstallDeps().installedIds(); } catch { /* left out */ }

  return {
    setup: {
      version,
      os: process.platform,
      arch: process.arch,
      nodeMajor: Number.parseInt(process.versions.node, 10),
      lang: getLang(),
      harnessesDetected: detectedHarnesses().map((h) => h.id),
      harnessesProtected: protectedIds,
      mode: getMode(home),
      watcher: isBackgroundRunning(home),
      window: getSetting('window', true, home) === true,
      paused: isPaused(home),
    },
    kinds,
    actions,
    byRule,
    problems: { error: kinds.error ?? 0, tamper: kinds.tamper ?? 0 },
  };
}

// Every action guard records in its log (src/guard/policy.mjs, hook.mjs, background.mjs).
const ACTIONS = new Set(['denied', 'warned', 'blocked', 'redacted', 'asked', 'allowed', 'seen', 'noted', 'skipped', 'paused', 'start', 'running', 'end']);

const BOXES = [
  ['setup', 'About my setup'],
  ['activity', 'What guard did, last 7 days'],
  ['secrets', 'Which kinds of secrets were involved (shows which services you use)'],
  ['problems', 'Problems blackbrake had'],
];

export const realDeps = () => ({
  home: undefined,
  now: () => new Date(),
  rules: () => loadRules(),
  gather: (version) => gatherData({ version }),
  identity: undefined,
  select,
  checklist,
  open: (url) => openMailto(url),
});

// ---------- terminal helpers ----------

// Lines are read from readline's queue, so a pasted paragraph keeps every line (rl.question would
// drop the lines that arrive before the next question is asked). null: the input ended.
function lineReader(input, output) {
  const rl = readline.createInterface({ input, output, terminal: Boolean(output.isTTY && input.setRawMode) });
  const lines = rl[Symbol.asyncIterator]();

  return {
    async ask(question) {
      output.write(question);
      const next = await lines.next();

      return next.done ? null : next.value;
    },
    close: () => rl.close(),
  };
}

// One field. Validated as it is typed in; a refused answer is asked again (3 tries).
async function askField(p, reader, field, { rules, identity, print }) {
  for (let attempt = 0; attempt < 3; attempt++) {
    const hint = field.multiline ? t('several lines; an empty line ends') : t('one line');
    const lines = [await reader.ask(`\n  ${p.cream(field.label())} ${p.faint(`(${hint}, ${t('up to {n} characters', { n: field.maxChars })})`)}\n  > `)];

    while (field.multiline && lines.at(-1) !== '' && lines.at(-1) !== null) lines.push(await reader.ask('  > '));

    if (lines.includes(null)) return null;
    const text = lines.join('\n').replace(/\n+$/, '').trim();

    if (!text && !field.required) return '';

    if (!text) {
      print([`    ${p.coral('✗')} ${p.cream(t('This one is needed.'))}`]);
      continue;
    }

    const checked = validateFreeText(text, { rules, identity, maxChars: field.maxChars, multiline: Boolean(field.multiline) });

    if (checked.ok) return checked.text;
    print([...problemLines(p, checked.problems), `    ${p.faint(t('Type it again without that.'))}`]);
  }

  return null;
}

const numbered = (p, text) => String(text).replace(/\n$/, '').split('\n').map((l, i) => `  ${p.faint(String(i + 1).padStart(3))}  ${p.cream(clean(l, 220))}`);

const where = (name, home) => clean(path.join(reportsDir(home), name), 300);

const human = (io) => requireHuman({ env: io.env, input: io.input ?? process.stdin, output: io.output ?? process.stdout });

const unreadable = (p, e) => ['', `  ${p.coral('✗')} ${p.cream(t('That report cannot be read ({code}).', { code: clean(e?.code ?? 'error', 30) }))}`, ''];

// Without a person at a terminal: nothing is written, opened or sent (exit 1).
function refuse(p, io, print) {
  const h = human(io);

  if (h.reason === 'agent') print(['', `  ${p.amber(h.message)}`, `  ${p.faint(h.how)}`]);
  print(['', `  ${p.faint(t('Reports are prepared in an interactive terminal.'))}`, '']);

  return 1;
}

const cancelled = (p, print) => {
  print(['', `  ${p.faint(t('Nothing was written.'))}`, '']);

  return 0;
};

// ---------- sending ----------

async function sendFlow(p, name, { version, deps, io, print }) {
  const kind = reportKind(name);
  const pick = (items) => deps.select(p, items, { input: io.input ?? process.stdin, output: io.output ?? process.stdout });
  let bytes;

  try { bytes = readReport(name, { home: deps.home }); } catch (e) {
    print(unreadable(p, e));

    return 1;
  }

  // V9: checked again now, and the link is built from this very text.
  const mail = buildMailto({ kind, version, text: bytes, rules: deps.rules(), identity: deps.identity });

  if (!mail.ok) {
    print(['', `  ${p.coral('✗')} ${p.cream(t('This report is not valid any more:'))}`, ...problemLines(p, mail.problems), '']);

    return 1;
  }

  print(['', `  ${p.faint(t('To'))}       ${p.cream(mail.to)}`, `  ${p.faint(t('Subject'))}  ${p.cream(mail.subject)}`]);

  const how = await pick([
    { value: 'address', label: t('Show the address only') },
    { value: 'open', label: t('Open my mail app'), hint: t('shows the whole message first') },
    { value: 'back', label: t('Back') },
  ]);

  if (how === 'address') print(['', `  ${p.cream(t('Send it to {to} with the subject above. Paste the text of the file into the message or attach it: {path}', { to: mail.to, path: where(name, deps.home) }))}`, '']);

  if (how !== 'open') return 0;

  // RFC 6068 §7: the whole message is shown before anything opens.
  print(['', `  ${p.bold(p.cream(t('The message, exactly as it will appear')))}`, `  ${p.faint(t('To'))}       ${p.cream(mail.to)}`, `  ${p.faint(t('Subject'))}  ${p.cream(mail.subject)}`]);
  print(mail.body ? numbered(p, mail.body) : [`  ${p.amber(t('The report is too long for a mail link: only the subject goes in. Paste the text of the file into the message or attach it: {path}', { path: where(name, deps.home) }))}`]);

  if ((await pick([{ value: false, label: t('No') }, { value: true, label: t('Yes, open my mail app') }])) !== true) return 0;

  if (!deps.open(mail.url)) print(['', `  ${p.amber(t('No mail app could be opened. Send it yourself to {to}.', { to: mail.to }))}`]);
  print(['', `  ${p.faint(t('I cannot tell whether you sent it. The file stays here until you delete it (it expires in {n} days).', { n: REPORT_DAYS }))}`, '']);

  return 0;
}

// ---------- the wizard ----------

export async function runWizard(p, kind, { version, io = {}, deps = realDeps(), print = defaultPrint } = {}) {
  if (!human(io).ok) return refuse(p, io, print);
  const input = io.input ?? process.stdin;
  const output = io.output ?? process.stdout;

  print(screen(p, t('REPORT'), t(kind === 'security' ? 'a security issue in blackbrake' : 'feedback or a problem'), columns(), { pose: 'think', line: t('Nothing is sent. I write a file on this computer, you read and edit it, and only then you choose whether to email it.') }));

  if (kind === 'security') print([`  ${p.amber(t('This is for vulnerabilities in blackbrake itself. Do not include secrets, file paths or working exploit code: describe the kind of problem and the steps. Email is not end-to-end encrypted.'))}`]);
  const rules = deps.rules();
  const fields = {};

  // Closed lists first (they use the arrow keys), then the typed fields.
  for (const field of FIELDS[kind].filter((f) => f.choices)) {
    print(['', `  ${p.cream(field.label())}`]);
    const choice = await deps.select(p, field.choices.map((c) => ({ value: c, label: c })), { input, output });

    if (!field.choices.includes(choice)) return cancelled(p, print);
    fields[field.heading] = choice;
  }

  const reader = lineReader(input, output);

  try {
    for (const field of FIELDS[kind].filter((f) => !f.choices)) {
      const text = await askField(p, reader, field, { rules, identity: deps.identity, print });

      if (text === null) return cancelled(p, print);
      fields[field.heading] = text;
    }
  } finally {
    reader.close();
  }

  // The automatic data: every box off, with the exact lines each would add.
  const data = deps.gather(version);
  const ruleIds = new Set(rules.rules.map((r) => r.id));
  const kindIds = new Set(Object.keys(KIND));
  const all = aggregateReport(data, { selected: Object.fromEntries(BOXES.map(([k]) => [k, true])), ruleIds, kindIds }).sections;

  print(['', `  ${p.bold(p.cream(t('You can add some numbers about your setup. Nothing is added unless you tick it; this is exactly what each box adds:')))}`]);

  for (const [box, label] of BOXES) print(['', `  ${p.cream(t(label))}`, ...all[AUTO_SECTIONS[box]].map((l) => `    ${p.faint(clean(l, 200))}`)]);
  const ticked = await deps.checklist(p, BOXES.map(([value, label]) => ({ value, label: t(label), on: false })), { input, output, proceed: { label: t('Write the report'), hint: t('nothing is sent') } });

  if (!ticked) return cancelled(p, print);
  const { sections } = aggregateReport(data, { selected: ticked, ruleIds, kindIds });
  const now = deps.now();
  const built = buildReport({ kind, version, now, rules, identity: deps.identity, fields, sections });

  if (!built.ok) {
    print(['', `  ${p.coral('✗')} ${p.cream(t('The report could not be written:'))}`, ...problemLines(p, built.problems), '']);

    return 1;
  }

  const name = saveReport(kind, built.text, { home: deps.home, now });

  return afterSave(p, name, { version, deps, io, print, text: built.text });
}

function checkOne(p, name, { deps, print }) {
  let bytes;

  try { bytes = readReport(name, { home: deps.home }); } catch (e) {
    print(unreadable(p, e));

    return { ok: false };
  }

  const r = validateReport(bytes, { kind: reportKind(name), rules: deps.rules(), identity: deps.identity });

  print(r.ok ? ['', `  ${p.green('✓')} ${p.cream(t('The report is valid.'))}`, ''] : ['', `  ${p.coral('✗')} ${p.cream(t('The report is not valid:'))}`, ...problemLines(p, r.problems), '']);

  return r;
}

// The report on screen, then: read again · check after editing · delete · how to send · done.
async function afterSave(p, name, { version, deps, io, print, text }) {
  let shown = text;

  print(['', `  ${p.bold(p.cream(t('Your report')))} ${p.faint(t('(saved on this computer only)'))}`, ...numbered(p, shown), '', `  ${p.faint(t('Saved as {path}. Edit it with any text editor, then choose "Check it again".', { path: where(name, deps.home) }))}`]);

  for (;;) {
    const next = await deps.select(p, [
      { value: 'read', label: t('Read it again') },
      { value: 'check', label: t('Check it again after I edit it') },
      { value: 'delete', label: t('Delete this report') },
      { value: 'send', label: t('How do I send it?') },
      { value: 'done', label: t('Done, keep it') },
    ], { input: io.input ?? process.stdin, output: io.output ?? process.stdout });

    if (next === 'read') print(['', ...numbered(p, shown)]);
    else if (next === 'check') shown = checkOne(p, name, { deps, print }).text ?? shown;
    else if (next === 'delete') {
      deleteReport(name, { home: deps.home });
      print(['', `  ${p.amber('✓')} ${p.cream(t('Report deleted.'))}`, '']);

      return 0;
    } else if (next === 'send') await sendFlow(p, name, { version, deps, io, print });
    else {
      print(['', `  ${p.faint(t('Kept. It expires in {n} days; "blackbrake report list" shows it.', { n: REPORT_DAYS }))}`, '']);

      return 0;
    }
  }
}

// ---------- the command ----------

const USAGE = 'blackbrake report [product|security] · list · show <name> · check <name> · send <name> · delete <name>|--all';

function usage(p, print) {
  print(['', `  ${p.faint(USAGE)}`, '']);

  return 2;
}

export async function runReport(ctx, { io = {}, deps = realDeps() } = {}) {
  const { p, opts } = ctx;
  const print = ctx.print ?? defaultPrint;
  const version = ctx.pkg?.version;
  const [sub, name] = opts.rest ?? [];

  if (!sub || sub === 'product' || sub === 'security') return runWizard(p, sub ?? 'product', { version, io, deps, print });

  if (sub === 'list') {
    // Read only in a pipe: expired reports are deleted only with a person at a terminal.
    const items = listReports({ home: deps.home, now: deps.now(), prune: human(io).ok });
    const left = (r) => Math.max(0, Math.ceil(REPORT_DAYS - (deps.now() - r.date) / 864e5));

    print(items.length ? ['', ...items.map((r) => `  ${p.cream(r.name)}  ${p.faint(t('expires in {n} days', { n: left(r) }))}`), ''] : ['', `  ${p.faint(t('No reports saved.'))}`, '']);

    return 0;
  }

  if ((sub === 'show' || sub === 'check') && !reportKind(name)) return usage(p, print);

  if (sub === 'check') return checkOne(p, name, { deps, print }).ok ? 0 : 1;

  if (sub === 'show') {
    let bytes;

    try { bytes = readReport(name, { home: deps.home }); } catch (e) {
      print(unreadable(p, e));

      return 1;
    }

    // An edited or planted file is shown, but never as if it were a valid report (review B).
    const valid = validateReport(bytes, { kind: reportKind(name), rules: deps.rules(), identity: deps.identity });
    const warning = valid.ok ? [] : [`  ${p.coral('✗')} ${p.cream(t('This file is not a valid report any more; it is shown as plain text:'))}`, ...problemLines(p, valid.problems)];

    print(['', ...warning, ...numbered(p, new TextDecoder().decode(bytes)), '']);

    return valid.ok ? 0 : 1;
  }

  // Everything else writes, opens or deletes: a person at a terminal only.
  if (!human(io).ok) return refuse(p, io, print);

  if (sub === 'send') return reportKind(name) ? sendFlow(p, name, { version, deps, io, print }) : usage(p, print);

  if (sub === 'delete' && opts.all) {
    if (!(await confirmTyped(p, t('Delete every saved report?'), 'delete', getLang() === 'es' ? 'borrar' : null, io))) return cancelled(p, print);
    const items = listReports({ home: deps.home, now: deps.now(), prune: false });

    for (const r of items) deleteReport(r.name, { home: deps.home });
    print(['', `  ${p.amber('✓')} ${p.cream(t('{n} report(s) deleted.', { n: items.length }))}`, '']);

    return 0;
  }

  if (sub !== 'delete' || !reportKind(name)) return usage(p, print);

  try { deleteReport(name, { home: deps.home }); } catch (e) {
    print(unreadable(p, e));

    return 1;
  }

  print(['', `  ${p.amber('✓')} ${p.cream(t('Report deleted.'))}`, '']);

  return 0;
}

export default {
  id: 'report',
  commands: [
    { name: 'report', usage: 'blackbrake report [product|security]', help: () => t('prepare a report; nothing is sent'), args: 3, run: (ctx) => runReport(ctx) },
  ],
  menu: [
    {
      slot: 'more',
      order: 65,
      value: 'report-product',
      label: () => t('Send feedback or report a problem…'),
      hint: () => t('prepare a message for hello@blackbrake.dev; nothing is sent'),
      run: async (ctx) => { await runWizard(ctx.p, 'product', { version: ctx.pkg?.version, print: ctx.print }); },
    },
    {
      slot: 'more',
      order: 66,
      value: 'report-security',
      label: () => t('Report a security issue…'),
      hint: () => t('prepare a message for security@blackbrake.dev; nothing is sent'),
      run: async (ctx) => { await runWizard(ctx.p, 'security', { version: ctx.pkg?.version, print: ctx.print }); },
    },
  ],
};
