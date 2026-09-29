// F5.7: live Claude Code spend includes only subagents owned by the parent session. Fixtures mirror
// the real layout: <project>/<session UUID>/subagents/agent-<hex>.jsonl.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import test from 'node:test';
import * as liveCost from '../src/cost/live.mjs';
import { usageCost } from '../src/cost/prices.mjs';
import { accountClaudeSubagents } from '../src/guard/spend-hook.mjs';
import { setSpendBaseline } from '../src/guard/spend-state.mjs';
import { getSession } from '../src/guard/state.mjs';

const SESSION = '11111111-1111-4111-8111-111111111111';

const FOREIGN = '22222222-2222-4222-8222-222222222222';

const jsonl = (rows) => `${rows.map((row) => JSON.stringify(row)).join('\n')}\n`;

const usage = (id, sessionId, at, input = 10_000) => ({
  type: 'assistant',
  sessionId,
  timestamp: at,
  requestId: `request-${id}`,
  message: {
    id: `response-${id}`,
    role: 'assistant',
    model: 'claude-sonnet-5',
    content: [],
    usage: { input_tokens: input, output_tokens: 100, cache_creation_input_tokens: 0, cache_read_input_tokens: 0 },
  },
});

const child = (id, sessionId, at, input) => [
  { type: 'system', agentId: id, parentSessionId: sessionId, contextLength: 0 },
  usage(id, sessionId, at, input),
];

const fixture = (tag) => {
  const base = fs.mkdtempSync(path.join(os.tmpdir(), `blackbrake-subagents-${tag}-`));
  const claude = path.join(base, 'claude');
  const root = path.join(claude, 'projects');
  const project = path.join(root, 'fixture-project');
  const transcript = path.join(project, `${SESSION}.jsonl`);
  const children = path.join(project, SESSION, 'subagents');
  const home = path.join(base, 'blackbrake');

  fs.mkdirSync(children, { recursive: true });
  fs.writeFileSync(transcript, '');

  return { base, claude, root, project, transcript, children, home };
};

const hook = ({ claude, home }) => (event, input) => {
  const env = {
    ...process.env,
    HOME: path.dirname(claude),
    USERPROFILE: path.dirname(claude),
    CLAUDE_CONFIG_DIR: claude,
    BLACKBRAKE_HOME: home,
    BLACKBRAKE_NO_WINDOW: '1',
    BLACKBRAKE_LANG: 'en',
  };

  const result = spawnSync(process.execPath, ['src/guard/hook.mjs', event], {
    cwd: path.resolve('.'),
    env,
    input: JSON.stringify(input),
    encoding: 'utf8',
  });

  assert.equal(result.status, 0, result.stderr);

  return result.stdout ? JSON.parse(result.stdout) : null;
};

const event = (transcript, extra = {}) => ({ session_id: SESSION, transcript_path: transcript, ...extra });

const listClaudeSubagentFiles = liveCost.listClaudeSubagentFiles;

test('Claude live spend attributes a new matching subagent to the open parent episode', () => {
  const f = fixture('attribute');
  const run = hook(f);

  setSpendBaseline('claude', { n: 30, p50: 0.000001, p90: 0.000002, ready: true }, f.home);
  run('SessionStart', event(f.transcript));
  run('UserPromptSubmit', event(f.transcript, { prompt: 'fixture parent prompt' }));
  const started = getSession(SESSION, f.home).spend.open.start;
  const after = new Date(started + 1000).toISOString();
  const before = new Date(started - 1000).toISOString();

  fs.writeFileSync(path.join(f.children, 'agent-aaaaaaaaaaaaaaaa.jsonl'), jsonl(child('owned', SESSION, after)));
  fs.writeFileSync(path.join(f.children, 'agent-bbbbbbbbbbbbbbbb.jsonl'), jsonl(child('foreign', FOREIGN, after, 900_000)));
  fs.writeFileSync(path.join(f.children, 'agent-cccccccccccccccc.jsonl'), jsonl(child('past', SESSION, before, 900_000)));

  const result = run('PostToolUse', event(f.transcript, { tool_name: 'Read', tool_input: { file_path: 'fixture.txt' }, tool_response: 'fixture' }));
  const open = getSession(SESSION, f.home).spend.open;
  const expected = usageCost(usage('owned', SESSION, after).message.usage, 'claude-sonnet-5');

  assert.match(result.systemMessage, /local p90/);
  assert.equal(open.responses, 1);
  assert.ok(Math.abs(open.cost - expected) < 1e-12);

  const persisted = fs.readFileSync(path.join(f.home, 'sessions', fs.readdirSync(path.join(f.home, 'sessions'))[0]), 'utf8');

  assert.doesNotMatch(persisted, /agent-|fixture-project|11111111|owned|foreign|past|request-|response-/i);
});

test('existing child spend is silent and a rewritten child response is not counted twice', () => {
  const f = fixture('rewrite');
  const run = hook(f);
  const oldFile = path.join(f.children, 'agent-aaaaaaaaaaaaaaaa.jsonl');

  fs.writeFileSync(oldFile, jsonl(child('old', SESSION, '2020-01-01T00:00:00.000Z', 900_000)));
  setSpendBaseline('claude', { n: 30, p50: 0.000001, p90: 0.000002, ready: true }, f.home);
  run('SessionStart', event(f.transcript));
  run('UserPromptSubmit', event(f.transcript, { prompt: 'fixture parent prompt' }));
  const first = run('PostToolUse', event(f.transcript, { tool_name: 'Read', tool_input: {}, tool_response: 'fixture' }));

  assert.doesNotMatch(JSON.stringify(first), /local p90/);
  assert.equal(getSession(SESSION, f.home).spend.open.cost, 0);

  const started = getSession(SESSION, f.home).spend.open.start;
  const liveFile = path.join(f.children, 'agent-bbbbbbbbbbbbbbbb.jsonl');
  const rows = child('live', SESSION, new Date(started + 1000).toISOString());

  fs.writeFileSync(liveFile, jsonl(rows));
  run('PostToolUse', event(f.transcript, { tool_name: 'Read', tool_input: {}, tool_response: 'fixture' }));
  const counted = { ...getSession(SESSION, f.home).spend.open };

  fs.writeFileSync(liveFile, '');
  run('PostToolUse', event(f.transcript, { tool_name: 'Read', tool_input: {}, tool_response: 'fixture' }));
  fs.writeFileSync(liveFile, jsonl(rows));
  run('PostToolUse', event(f.transcript, { tool_name: 'Read', tool_input: {}, tool_response: 'fixture' }));
  const rewritten = { ...getSession(SESSION, f.home).spend.open };

  const replacement = path.join(f.children, 'replacement.jsonl');

  fs.writeFileSync(replacement, jsonl(rows));
  fs.rmSync(liveFile);
  fs.renameSync(replacement, liveFile);
  run('PostToolUse', event(f.transcript, { tool_name: 'Read', tool_input: {}, tool_response: 'fixture' }));
  const rotated = getSession(SESSION, f.home).spend.open;

  assert.equal(rewritten.cost, counted.cost);
  assert.equal(rewritten.responses, counted.responses);
  assert.equal(rotated.cost, counted.cost);
  assert.equal(rotated.responses, counted.responses);
});

test('a child that continues after the next parent prompt is not reassigned to the new episode', () => {
  const f = fixture('boundary');
  const run = hook(f);

  setSpendBaseline('claude', { n: 30, p50: 100, p90: 200, ready: true }, f.home);
  run('SessionStart', event(f.transcript));
  run('UserPromptSubmit', event(f.transcript, { prompt: 'first parent prompt' }));
  const firstStart = getSession(SESSION, f.home).spend.open.start;
  const firstFile = path.join(f.children, 'agent-aaaaaaaaaaaaaaaa.jsonl');

  fs.writeFileSync(firstFile, jsonl(child('first-a', SESSION, new Date(firstStart + 100).toISOString())));
  run('PostToolUse', event(f.transcript, { tool_name: 'Read', tool_input: {}, tool_response: 'fixture' }));
  run('UserPromptSubmit', event(f.transcript, { prompt: 'second parent prompt' }));
  const secondStart = getSession(SESSION, f.home).spend.open.start;

  fs.appendFileSync(firstFile, jsonl([usage('first-b', SESSION, new Date(secondStart + 100).toISOString())]));
  run('PostToolUse', event(f.transcript, { tool_name: 'Read', tool_input: {}, tool_response: 'fixture' }));
  assert.equal(getSession(SESSION, f.home).spend.open.cost, 0);

  const secondFile = path.join(f.children, 'agent-bbbbbbbbbbbbbbbb.jsonl');

  fs.writeFileSync(secondFile, jsonl(child('second', SESSION, new Date(secondStart + 200).toISOString())));
  run('PostToolUse', event(f.transcript, { tool_name: 'Read', tool_input: {}, tool_response: 'fixture' }));
  assert.ok(getSession(SESSION, f.home).spend.open.cost > 0);
});

test('subagent enumeration rejects foreign paths, links, malformed entries and bounds its work', (t) => {
  const f = fixture('paths');

  for (let i = 0; i < 4; i++) fs.writeFileSync(path.join(f.children, `agent-${String(i).padStart(16, 'a')}.jsonl`), '{}\n');
  fs.writeFileSync(path.join(f.children, 'journal.jsonl'), '{}\n');
  fs.writeFileSync(path.join(f.children, 'agent-deadbeefdeadbeef.jsonl'), 'x'.repeat(200));
  const outside = fs.mkdtempSync(path.join(os.tmpdir(), 'blackbrake-subagents-outside-'));
  const planted = path.join(outside, 'agent-feedfacefeedface.jsonl');

  fs.writeFileSync(planted, '{}\n');

  try {
    fs.symlinkSync(planted, path.join(f.children, 'agent-cafebabecafebabe.jsonl'), 'file');
  } catch (error) {
    t.diagnostic(`file symlink unavailable: ${error.code ?? error.message}`);
  }

  const listed = listClaudeSubagentFiles(f.transcript, SESSION, {
    roots: [f.root],
    maxFiles: 2,
    maxEntries: 16,
    maxFileBytes: 100,
  });

  assert.equal(listed.length, 2);
  assert.ok(listed.every((entry) => path.dirname(entry.file) === f.children));
  assert.ok(listed.every((entry) => /^agent-[0-9a-f]+\.jsonl$/i.test(path.basename(entry.file))));
  const allSafe = listClaudeSubagentFiles(f.transcript, SESSION, { roots: [f.root], maxFileBytes: 100 });

  assert.doesNotMatch(allSafe.map((entry) => path.basename(entry.file)).join(','), /deadbeef|cafebabe|journal/i);
  assert.deepEqual(listClaudeSubagentFiles(f.transcript, '../foreign', { roots: [f.root] }), []);
  assert.deepEqual(listClaudeSubagentFiles(f.transcript, FOREIGN, { roots: [f.root] }), []);

  const linkedProject = path.join(f.root, 'linked-project');

  fs.symlinkSync(f.project, linkedProject, process.platform === 'win32' ? 'junction' : 'dir');
  assert.throws(() => listClaudeSubagentFiles(path.join(linkedProject, `${SESSION}.jsonl`), SESSION, { roots: [f.root] }), /Untrusted/);

  const linkedSession = fixture('linked-session');
  const outsideSession = path.join(outside, 'session');

  fs.mkdirSync(path.join(outsideSession, 'subagents'), { recursive: true });
  fs.writeFileSync(path.join(outsideSession, 'subagents', 'agent-facefeedfacefeed.jsonl'), '{}\n');
  fs.rmSync(path.join(linkedSession.project, SESSION), { recursive: true });
  fs.symlinkSync(outsideSession, path.join(linkedSession.project, SESSION), process.platform === 'win32' ? 'junction' : 'dir');
  assert.deepEqual(listClaudeSubagentFiles(linkedSession.transcript, SESSION, { roots: [linkedSession.root] }), []);
});

test('opening a listed child revalidates session and subagents under the projects root', () => {
  for (const swapped of ['session', 'subagents']) {
    const f = fixture(`race-${swapped}`);
    const name = 'agent-aabbccddaabbccdd.jsonl';
    const safeFile = path.join(f.children, name);
    const outside = fs.mkdtempSync(path.join(os.tmpdir(), `blackbrake-subagents-race-${swapped}-`));
    const outsideChildren = swapped === 'session' ? path.join(outside, 'subagents') : outside;
    const started = Date.now() - 1000;

    fs.writeFileSync(safeFile, '{}\n');
    fs.mkdirSync(outsideChildren, { recursive: true });
    fs.writeFileSync(path.join(outsideChildren, name), jsonl(child(`outside-${swapped}`, SESSION, new Date(started + 100).toISOString())));

    let replaced = false;

    const live = {
      ...liveCost,
      listClaudeSubagentFiles(...args) {
        const listed = listClaudeSubagentFiles(...args);

        if (swapped === 'session') {
          const sessionRoot = path.dirname(f.children);

          fs.rmSync(sessionRoot, { recursive: true });
          fs.symlinkSync(outside, sessionRoot, process.platform === 'win32' ? 'junction' : 'dir');
        } else {
          fs.rmSync(f.children, { recursive: true });
          fs.symlinkSync(outsideChildren, f.children, process.platform === 'win32' ? 'junction' : 'dir');
        }

        replaced = true;

        return listed;
      },
    };

    const spend = {
      open: { start: started, cost: 0, responses: 0, tokens: 0, costAlerted: false },
      responses: [],
      subagents: { initialized: true, files: {} },
    };

    accountClaudeSubagents({ live, transcript: f.transcript, root: f.root, sessionId: SESSION, spend, secret: 'fixture-secret' });

    assert.equal(replaced, true);
    assert.equal(spend.open.cost, 0, `${swapped} replacement escaped the projects root`);
    assert.equal(spend.open.responses, 0, `${swapped} replacement was accounted`);
  }
});

test('unchanged children stay closed while rewrite, truncate and rotation remain deduplicated', () => {
  const f = fixture('metadata');
  const name = 'agent-aabbccddaabbccdd.jsonl';
  const file = path.join(f.children, name);
  const started = Date.now() - 1000;
  const at = (delta) => new Date(started + delta).toISOString();
  const rows = child('first', SESSION, at(100));

  fs.writeFileSync(file, jsonl(rows));

  let opens = 0;

  const live = {
    ...liveCost,
    tailTranscript(...args) {
      opens++;

      return liveCost.tailTranscript(...args);
    },
  };

  const spend = {
    open: { start: started, cost: 0, responses: 0, tokens: 0, costAlerted: false },
    responses: [],
    subagents: { initialized: true, files: {} },
  };

  const account = () => accountClaudeSubagents({ live, transcript: f.transcript, root: f.root, sessionId: SESSION, spend, secret: 'fixture-secret' });

  account();
  assert.equal(opens, 1);
  const first = { cost: spend.open.cost, responses: spend.open.responses };

  account();
  assert.equal(opens, 1, 'an unchanged child was reopened');

  rows.push(usage('second', SESSION, at(200)));
  fs.appendFileSync(file, jsonl([rows.at(-1)]));
  account();
  assert.equal(opens, 2, 'an appended child was not reopened');
  assert.equal(spend.open.responses, first.responses + 1);
  const counted = { cost: spend.open.cost, responses: spend.open.responses };

  fs.writeFileSync(file, jsonl(rows));
  const future = new Date(Date.now() + 5000);

  fs.utimesSync(file, future, future);
  account();
  assert.equal(opens, 3, 'a same-size rewrite was not reopened');
  assert.deepEqual({ cost: spend.open.cost, responses: spend.open.responses }, counted);

  fs.writeFileSync(file, '');
  account();
  assert.equal(opens, 4, 'a truncation was not reopened');
  fs.writeFileSync(file, jsonl(rows));
  account();
  assert.equal(opens, 5, 'a rewritten truncated child was not reopened');

  const replacement = path.join(f.children, 'replacement.jsonl');

  fs.writeFileSync(replacement, jsonl(rows));
  fs.rmSync(file);
  fs.renameSync(replacement, file);
  account();
  assert.equal(opens, 6, 'a rotated child was not reopened');
  assert.deepEqual({ cost: spend.open.cost, responses: spend.open.responses }, counted);
});

test('unchanged metadata does not skip the unread remainder of a bounded child tail', () => {
  const f = fixture('bounded-tail');
  const file = path.join(f.children, 'agent-aabbccddaabbccdd.jsonl');
  const started = Date.now() - 1000;

  fs.writeFileSync(file, `${'x'.repeat(300 * 1024)}\n${jsonl(child('after-large-line', SESSION, new Date(started + 100).toISOString()))}`);

  let opens = 0;

  const live = {
    ...liveCost,
    tailTranscript(...args) {
      opens++;

      return liveCost.tailTranscript(...args);
    },
  };

  const spend = {
    open: { start: started, cost: 0, responses: 0, tokens: 0, costAlerted: false },
    responses: [],
    subagents: { initialized: true, files: {} },
  };

  const account = () => accountClaudeSubagents({ live, transcript: f.transcript, root: f.root, sessionId: SESSION, spend, secret: 'fixture-secret' });

  account();
  assert.equal(spend.open.responses, 0);
  account();
  assert.equal(spend.open.responses, 1);
  assert.equal(opens, 2);
  account();
  assert.equal(opens, 2, 'a fully consumed unchanged child was reopened');
});
