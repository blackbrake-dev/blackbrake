// The human gate: lowering protection needs a person at a terminal, typing the word. An AI agent
// that runs inside a pseudo-terminal is refused too, and told how to do it properly.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { PassThrough } from 'node:stream';
import { test } from 'node:test';
import { confirmTyped, isInteractive } from '../src/guard/cli.mjs';
import { AGENT_MARKERS, requireHuman } from '../src/guard/human.mjs';
import { decide } from '../src/guard/policy.mjs';
import { setLang } from '../src/i18n.mjs';
import { loadRules } from '../src/secrets/engine.mjs';
import { createPainter } from '../src/ui/term.mjs';

const p = createPainter(0);

// A terminal the test controls: both ends report isTTY, the "person" types into `input`.
function fakeTerminal() {
  const input = new PassThrough();
  const output = new PassThrough();
  input.isTTY = true;
  output.isTTY = true;
  let written = '';
  output.on('data', (d) => { written += d; });

  return { input, output, text: () => written };
}

const type = (term, word) => setImmediate(() => term.input.write(`${word}\r`));

test('requireHuman: a person in a terminal with no agent markers passes', () => {
  const term = fakeTerminal();
  assert.deepEqual(requireHuman({ env: {}, input: term.input, output: term.output }), { ok: true });
  // Unrelated variables, and an empty marker, do not count as an agent.
  assert.equal(requireHuman({ env: { PATH: 'x', CLAUDECODE: '' }, input: term.input, output: term.output }).ok, true);
});

test('requireHuman: without a terminal, nobody passes', () => {
  const r = requireHuman({ env: {}, input: { isTTY: false }, output: { isTTY: true } });
  assert.equal(r.ok, false);
  assert.equal(r.reason, 'no-terminal');
  assert.equal(requireHuman({ env: {}, input: { isTTY: true }, output: { isTTY: false } }).reason, 'no-terminal');
});

test('requireHuman: an agent marker refuses even with a terminal, and explains how to do it right', () => {
  assert.ok(AGENT_MARKERS.includes('CLAUDECODE'), 'CLAUDECODE is the verified marker');
  const term = fakeTerminal();
  const r = requireHuman({ env: { CLAUDECODE: '1' }, input: term.input, output: term.output });
  assert.equal(r.ok, false);
  assert.equal(r.reason, 'agent');
  assert.match(r.message, /Run this in your own terminal window, not inside an AI agent\./);
  assert.match(r.how, /outside Claude Code/);
  assert.match(r.how, /type the word yourself/i);

  setLang('es');
  const es = requireHuman({ env: { CLAUDECODE: '1' }, input: term.input, output: term.output });
  setLang('en');
  assert.match(es.message, /Ejecútalo en tu propia ventana de terminal, no dentro de un agente de IA\./);
  assert.match(es.how, /escribe tú la palabra/i);
});

test('isInteractive takes injected streams', () => {
  assert.equal(isInteractive({ input: { isTTY: true }, output: { isTTY: true } }), true);
  assert.equal(isInteractive({ input: { isTTY: true }, output: { isTTY: false } }), false);
});

test('confirmTyped: a person without agent markers can still confirm', async () => {
  const term = fakeTerminal();
  const done = confirmTyped(p, 'Remove it?', 'remove', 'quitar', { input: term.input, output: term.output, env: {} });
  type(term, 'remove');
  assert.equal(await done, true);
  assert.match(term.text(), /Remove it\?/);
});

test('confirmTyped: the alias works, anything else cancels', async () => {
  const a = fakeTerminal();
  const yes = confirmTyped(p, 'Remove it?', 'remove', 'quitar', { input: a.input, output: a.output, env: {} });
  type(a, 'QUITAR');
  assert.equal(await yes, true);

  const b = fakeTerminal();
  const no = confirmTyped(p, 'Remove it?', 'remove', 'quitar', { input: b.input, output: b.output, env: {} });
  type(b, 'yes');
  assert.equal(await no, false);
});

test('confirmTyped: false inside an agent even when the word is typed, with the explanation and no prompt', async () => {
  const term = fakeTerminal();
  term.input.write('remove\r');
  const ok = await confirmTyped(p, 'Remove it?', 'remove', null, { input: term.input, output: term.output, env: { CLAUDECODE: '1' } });
  assert.equal(ok, false);
  assert.match(term.text(), /Run this in your own terminal window, not inside an AI agent\./);
  assert.match(term.text(), /outside Claude Code/);
  assert.ok(!/Remove it\?/.test(term.text()), 'the question is not even asked');
});

test('confirmTyped: false without a terminal, and silent', async () => {
  const output = new PassThrough();
  output.isTTY = false;
  let written = '';
  output.on('data', (d) => { written += d; });
  assert.equal(await confirmTyped(p, 'Remove it?', 'remove', null, { input: { isTTY: false }, output, env: {} }), false);
  assert.equal(written, '');
});

test('the agent cannot invoke pause, resume, stop or report from the shell', () => {
  const rules = loadRules();
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'bb-human-'));

  for (const mode of ['observe', 'protect']) {
    for (const command of ['blackbrake pause', 'blackbrake resume', 'blackbrake stop', 'blackbrake report send x.md', 'blackbrake report', 'npx blackbrake pause', 'blackbrake.cmd resume', 'cd x && blackbrake report delete --all']) {
      const r = decide('PreToolUse', { tool_name: 'Bash', tool_input: { command } }, { mode, rules, home });
      assert.equal(r.output?.hookSpecificOutput?.permissionDecision, 'deny', `${mode}: ${command}`);
    }
  }
});
