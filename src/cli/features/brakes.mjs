// "Spend brakes": the user picks how soon each brake fires, or switches it off.
//
//   blackbrake brakes                      shows every brake and how to change it
//   blackbrake brakes <brake[.field]> <v>  e.g. cost.percentile 95 · cost.fixed 10 · cost.fixed off ·
//                                          loop off · loop.repeats 4 · loop.minutes 5 · quota.weekly 90
//   blackbrake brakes reset                back to the defaults
//
// Tightening (fires sooner, or back on) needs nothing. Loosening (later or never) lowers protection:
// a person at a terminal types loosen|aflojar (requireHuman), as for "mode observe". While paused,
// nothing changes until resumed. The values live in state.json settings.spend, which the agent cannot
// write while guard runs (policy.mjs).
import { confirmTyped, pausedBadge } from '../../guard/cli.mjs';
import { requireHuman } from '../../guard/human.mjs';
import { isPaused } from '../../guard/pause.mjs';
import { applyBrakeChange, getSpendSettings, loosens, parseBrakeChange, PERCENTILES, setSpendSettings, SPEND_DEFAULTS } from '../../guard/spend-settings.mjs';
import { getLang, t } from '../../i18n.mjs';
import { select } from '../../ui/menu.mjs';
import { padEnd } from '../../ui/term.mjs';

const defaultPrint = (lines) => console.log(lines.join('\n'));

export const realDeps = () => ({ get: () => getSpendSettings(), set: (s) => setSpendSettings(s), paused: () => isPaused() });

const onOff = (p, on) => (on ? p.green(t('enabled')) : p.coral(t('disabled')));

// One line per brake, in words.
export function brakeLines(p, s) {
  const cost = !s.cost.on ? onOff(p, false) : s.cost.fixed !== null ? `${onOff(p, true)} · ${t('above API≈${amount} per episode (amount you set)', { amount: s.cost.fixed.toFixed(2) })}` : `${onOff(p, true)} · ${t('above your local p{pct}', { pct: s.cost.percentile })}`;
  const tokens = s.tokens.on ? `${onOff(p, true)} · ${t('above your local p{pct}', { pct: s.tokens.percentile })}` : onOff(p, false);
  const loop = s.loop.on ? `${onOff(p, true)} · ${t('the same call {n} times in {m} minutes', { n: s.loop.repeats, m: s.loop.minutes })}` : onOff(p, false);
  const quota = s.quota.on ? `${onOff(p, true)} · ${t('5-hour at {a}% · weekly at {b}%', { a: s.quota.fiveHour, b: s.quota.weekly })}` : onOff(p, false);

  return [
    `  ${padEnd(p.faint(t('Episode cost')), 22)}${cost}`,
    `  ${padEnd(p.faint(t('Episode tokens')), 22)}${tokens} ${p.faint(t('(Codex, Devin)'))}`,
    `  ${padEnd(p.faint(t('Repeated calls')), 22)}${loop}`,
    `  ${padEnd(p.faint(t('Codex quota')), 22)}${quota}`,
  ];
}

// Applies one change (or a reset). Resolves to the exit code: 0 done or nothing to do, 1 refused.
export async function applyBrakes(p, change, { io = {}, deps = realDeps(), print = defaultPrint } = {}) {
  if (deps.paused()) {
    print(['', `  ${pausedBadge(p)} ${p.cream(t('blackbrake is paused; run "blackbrake resume" first.'))}`, '']);

    return 1;
  }

  const prev = deps.get();
  const next = change === 'reset' ? structuredClone(SPEND_DEFAULTS) : applyBrakeChange(prev, change);

  if (JSON.stringify(next) === JSON.stringify(prev)) {
    print(['', `  ${p.faint(t('Nothing changed.'))}`, '']);

    return 0;
  }

  if (loosens(prev, next)) {
    const human = requireHuman({ env: io.env, input: io.input ?? process.stdin, output: io.output ?? process.stdout });
    const question = t('This makes a spend brake warn later or never. Your agents can spend more before blackbrake says anything.');

    if (!(await confirmTyped(p, question, 'loosen', getLang() === 'es' ? 'aflojar' : null, io))) {
      print(['', `  ${p.faint(t(human.ok ? 'Nothing changed.' : 'Nothing changed: this must be confirmed in an interactive terminal.'))}`, '']);

      return human.ok ? 0 : 1;
    }
  }

  deps.set(next);
  print(['', `  ${p.green('✓')} ${p.cream(t('Spend brakes saved'))}`, ...brakeLines(p, deps.get()), '']);

  return 0;
}

export async function runBrakes(p, words, { io = {}, deps = realDeps(), print = defaultPrint } = {}) {
  if (!words.length) {
    print(['', `  ${p.bold(p.cream(t('Spend brakes')))} ${p.faint(t('(list-price equivalents; never a bill or a saving)'))}`, ...brakeLines(p, deps.get()), '',
      `  ${p.faint(t('Change: blackbrake brakes cost.percentile 95 · cost.fixed 10 · cost.fixed off · loop.repeats 4 · loop.minutes 5 · quota.weekly 90 · tokens off · reset'))}`,
      `  ${p.faint(t('Percentiles: {list}. Loosening asks you to confirm in your own terminal.', { list: PERCENTILES.join(', ') }))}`, '']);

    return 0;
  }

  if (words.length === 1 && words[0].toLowerCase() === 'reset') return applyBrakes(p, 'reset', { io, deps, print });
  const change = parseBrakeChange(words);

  if (!change) {
    print(['', `  ${p.coral(t('Unknown brake or value.'))} ${p.faint(t('Run "blackbrake brakes" to see what can be changed.'))}`, '']);

    return 2;
  }

  return applyBrakes(p, change, { io, deps, print });
}

// The menu: pick a setting, then a value. Same rules as the command.
const CHOICES = () => [
  { label: t('Episode cost: brake'), key: 'cost.on', values: ['on', 'off'] },
  { label: t('Episode cost: percentile'), key: 'cost.percentile', values: PERCENTILES.map(String) },
  { label: t('Episode cost: fixed amount (API≈$)'), key: 'cost.fixed', values: ['off', '1', '5', '10', '25', '50', '100'] },
  { label: t('Episode tokens: brake'), key: 'tokens.on', values: ['on', 'off'] },
  { label: t('Episode tokens: percentile'), key: 'tokens.percentile', values: PERCENTILES.map(String) },
  { label: t('Repeated calls: brake'), key: 'loop.on', values: ['on', 'off'] },
  { label: t('Repeated calls: times'), key: 'loop.repeats', values: ['2', '3', '4', '5', '10'] },
  { label: t('Repeated calls: within minutes'), key: 'loop.minutes', values: ['1', '2', '5', '10', '30'] },
  { label: t('Codex quota: brake'), key: 'quota.on', values: ['on', 'off'] },
  { label: t('Codex quota: 5-hour %'), key: 'quota.fiveHour', values: ['80', '90', '95', '99'] },
  { label: t('Codex quota: weekly %'), key: 'quota.weekly', values: ['80', '90', '95', '98', '99'] },
];

const valueLabel = (v) => (v === 'on' ? t('enabled') : v === 'off' ? t('disabled') : v);

export async function brakesMenu(p, { io = {}, deps = realDeps(), print = defaultPrint } = {}) {
  print(['', ...brakeLines(p, deps.get()), '']);
  const choices = CHOICES();
  const picked = await select(p, [...choices.map((c, i) => ({ value: String(i), label: c.label })), { value: 'reset', label: t('Back to the defaults') }], io);

  if (picked === null) return 0;

  if (picked === 'reset') return applyBrakes(p, 'reset', { io, deps, print });
  const choice = choices[Number(picked)];
  const value = await select(p, choice.values.map((v) => ({ value: v, label: valueLabel(v) })), io);

  if (value === null) return 0;

  return applyBrakes(p, parseBrakeChange([choice.key, value]), { io, deps, print });
}

export default {
  id: 'brakes',
  commands: [
    { name: 'brakes', usage: 'blackbrake brakes [<brake> <value> | reset]', help: () => t('see or change how soon each spend brake warns'), args: 2, run: (ctx) => runBrakes(ctx.p, ctx.opts.rest, { print: ctx.print }) },
  ],
  menu: [
    {
      slot: 'protect',
      order: 25,
      value: 'brakes',
      label: () => t('Spend brakes'),
      hint: () => t('how soon blackbrake warns about cost, tokens, loops and quota'),
      run: async (ctx) => { await brakesMenu(ctx.p, { print: ctx.print }); },
    },
  ],
};
