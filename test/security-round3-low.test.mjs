import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { ADAPTERS } from '../src/guard/harnesses.mjs';
import { decide } from '../src/guard/policy.mjs';
import { isHarnessText, fragmentsOf } from '../src/transcripts.mjs';
import { clean, cleanDeep } from '../src/text.mjs';
import { validateFreeText } from '../src/report/validate.mjs';
import { loadRules } from '../src/secrets/engine.mjs';
import { episodesFromRecords } from '../src/cost/codex.mjs';

const identity = { home: '/Users/zzuser-q7', user: 'zzuser-q7', host: 'zzhost-k9' };

const rules = loadRules();

const field = (text, id = identity) => validateFreeText(text, { rules, identity: id, maxChars: 500 });

test('D3: Cursor Move/Rename check every destination alongside the source', (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'bb-r3-low-'));
  t.after(() => {
    assert.equal(path.dirname(root), path.resolve(os.tmpdir()));
    assert.ok(fs.existsSync(root));
    fs.rmSync(root, { recursive: true, force: true });
  });
  const source = path.join(root, 'safe.txt');
  const destination = path.join(root, '.blackbrake', 'state.json');

  for (const tool_name of ['Move', 'Rename']) {
    for (const key of ['destination', 'target', 'new_path', 'to', 'target_path', 'destination_path']) {
      const { input } = ADAPTERS.cursor.normalize('PreToolUse', { tool_name, tool_input: { file_path: source, [key]: destination } }, 'preToolUse');
      const result = decide('PreToolUse', input, { mode: 'protect', rules, home: root });
      assert.equal(result.output?.hookSpecificOutput?.permissionDecision, 'deny', `${tool_name} ${key}`);
    }
  }
});

test('D4: only known harness tags suppress a user episode', () => {
  for (const text of ['<div>Change this HTML</div>', '< 10 tokens please', '<custom>my task</custom>', '<system-reminder-extra>my task']) {
    assert.equal(isHarnessText(text), false, text);
    assert.equal([...fragmentsOf({ message: { role: 'user', content: text } }, new Map())][0].kind, 'user');
  }

  for (const text of ['<system-reminder>context</system-reminder>', '<task-notification>completed</task-notification>', 'Base directory for this skill: temporary', '[Subagent hand-back] done']) assert.equal(isHarnessText(text), true, text);
});

test('D4: Codex environment and subagent notifications do not create episodes', () => {
  const message = (text) => ({ type: 'response_item', payload: { type: 'message', role: 'user', content: [{ type: 'input_text', text }] } });

  const count = (total) => ({ type: 'event_msg', payload: { type: 'token_count', info: { total_token_usage: { total_tokens: total, cached_input_tokens: 0 } } } });

  for (const tag of ['environment_context', 'subagent_notification']) {
    assert.equal(isHarnessText(`<${tag}>fixture</${tag}>`), true, tag);
    assert.equal(isHarnessText(`<${tag}-extra>user text`), false, `${tag} boundary`);
  }

  const { episodes } = episodesFromRecords([
    message('<environment_context>fixture</environment_context>'), count(50),
    message('First real task'), count(150),
    message('<subagent_notification>fixture</subagent_notification>'), count(250),
    message('<div>Second real task</div>'), count(350),
  ]);

  assert.deepEqual(episodes.map((episode) => episode.tokens), [200, 100]);
});

test('V6: report validator rejects reviewer token, address and link variants', () => {
  for (const text of ['hunter2hunter2-abcdefghijk-lmnop', 'hex abcdefabcde', 'host 2130706433', 'host 127.1', 'evil.com/x', 'xn--caf-dma.com', 'a:b', 'node:arbitrary']) assert.equal(field(text).ok, false, text);
  assert.equal(field('Jose had a crash', { ...identity, user: 'josé' }).ok, false);
});

test('V7: short identity needs a boundary and common technical prose is accepted', () => {
  assert.equal(field('tomorrow the menu opens', { ...identity, user: 'tom' }).ok, true);
  assert.equal(field('the laptop opens', { ...identity, host: 'lap' }).ok, true);
  assert.equal(field('tom had a crash', { ...identity, user: 'tom' }).ok, false);
  assert.equal(field('host lap had a crash', { ...identity, host: 'lap' }).ok, false);

  for (const text of ['read/write/execute', 'node:fs', 'localhost:8080', 'install.sh and README.md']) assert.equal(field(text).ok, true, text);

  // A path and an address intentionally remain private even when they can be technical prose.
  for (const text of ['/status', '1.2.3.4']) assert.equal(field(text).ok, false, text);
});

test('V8: clean removes reviewer invisible ranges in labels and nested keys', () => {
  const ranges = [[0x206a, 0x206f], [0x2800, 0x2800], [0x1d173, 0x1d17a], [0x1bca0, 0x1bca3], [0x13430, 0x13438], [0xfffc, 0xfffc]];

  for (const [from, to] of ranges) for (let cp = from; cp <= to; cp++) {
    const hidden = String.fromCodePoint(cp);
    assert.equal(clean(`a${hidden}b`), 'ab', cp.toString(16));
    assert.deepEqual(cleanDeep({ [`a${hidden}b`]: `c${hidden}d` }), { ab: 'cd' });
  }
});
