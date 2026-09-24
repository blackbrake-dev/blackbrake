// Tests use only synthetic secrets assembled at runtime, so no credential-shaped literal exists
// in this repository (GitHub push protection and other scanners have nothing to flag).
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { auditSecrets } from '../src/secrets/audit.mjs';
import { CLASSES, classifyOccurrence } from '../src/secrets/context.mjs';
import { loadRules, scanText } from '../src/secrets/engine.mjs';
import { listTranscripts } from '../src/transcripts.mjs';

const BIN = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../bin/blackbrake.mjs');
const rules = loadRules();

// Deterministic pseudo-random base62 string, so values have realistic entropy.
function token(seed, len) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let x = seed, s = '';
  for (let i = 0; i < len; i++) { x = (x * 1103515245 + 12345) % 2147483648; s += alphabet[x % 62]; }
  return s;
}
const GITHUB = 'gh' + 'p_' + token(7, 36);
const LINEAR = 'lin' + '_api_' + token(11, 40);

function makeTranscripts(records) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'blackbrake-test-'));
  const project = path.join(dir, 'project-a');
  fs.mkdirSync(path.join(project, 'sess-1', 'subagents'), { recursive: true });
  const line = (o) => JSON.stringify(o) + '\n';
  fs.writeFileSync(path.join(project, 'sess-1.jsonl'), records.main.map(line).join(''));
  if (records.sub) fs.writeFileSync(path.join(project, 'sess-1', 'subagents', 'agent-1.jsonl'), records.sub.map(line).join(''));
  return dir;
}

const user = (text, ts) => ({ type: 'user', timestamp: ts, message: { role: 'user', content: text } });
const toolUse = (id, name, input, ts) => ({ type: 'assistant', timestamp: ts, message: { role: 'assistant', content: [{ type: 'tool_use', id, name, input }] } });
const toolResult = (id, content, ts) => ({ type: 'user', timestamp: ts, message: { role: 'user', content: [{ type: 'tool_result', tool_use_id: id, content }] } });

test('converted rules use only regex syntax that Node 20 supports', () => {
  const data = JSON.parse(fs.readFileSync(path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../vendor/gitleaks.rules.json'), 'utf8'));
  const all = [...data.rules.map((r) => r.regex), ...data.globalAllowlist.regexes, ...data.rules.flatMap((r) => r.allowlists.flatMap((a) => a.regexes))];
  // Inline modifiers such as (?i) (?i:...) (?-i:...) only compile on Node >= 23.
  for (const r of all) assert.ok(!/\(\?-?[ims]+[:)]/.test(r.source), `non-portable modifier in: ${r.source.slice(0, 80)}`);
});

test('detects a GitHub token and a Linear key', () => {
  assert.equal(scanText(rules, `export GITHUB_TOKEN=${GITHUB}`)[0].ruleId, 'github-pat');
  assert.equal(scanText(rules, `setx LINEAR_API_KEY "${LINEAR}"`)[0].ruleId, 'linear-api-key');
});

test('classifies context: fixtures, known examples, local values, real', () => {
  const at = (text, secret) => text.indexOf(secret);
  const fake = `use this fake token for the scanner test: ${GITHUB}`;
  assert.equal(classifyOccurrence({ secret: GITHUB, text: fake, index: at(fake, GITHUB) }), CLASSES.example);
  const inTest = `const t = '${GITHUB}'`;
  assert.equal(classifyOccurrence({ secret: GITHUB, text: inTest, index: 11, filePath: 'src/tests/auth.test.ts' }), CLASSES.example);
  assert.equal(classifyOccurrence({ secret: 'AKIA' + 'IOSFODNN7EXAMPLE', text: 'x', index: 0 }), CLASSES.example);
  const local = `open http://127.0.0.1:3000/verify?token=${GITHUB}`;
  assert.equal(classifyOccurrence({ secret: GITHUB, text: local, index: at(local, GITHUB) }), CLASSES.local);
  const pasted = `please set my key ${LINEAR}`;
  assert.equal(classifyOccurrence({ secret: LINEAR, text: pasted, index: at(pasted, LINEAR) }), CLASSES.real);
  assert.equal(classifyOccurrence({ secret: '"password"', text: 'x', index: 0 }), CLASSES.example);
});

test('audit counts copies, subagent copies and the origin of the first copy', async () => {
  const dir = makeTranscripts({
    main: [
      user(`set this for me: ${LINEAR}`, '2026-01-01T10:00:00Z'),
      toolUse('t1', 'Bash', { command: `setx LINEAR_API_KEY "${LINEAR}"` }, '2026-01-01T10:00:05Z'),
      toolResult('t1', 'SUCCESS: Specified value was saved.', '2026-01-01T10:00:06Z'),
    ],
    sub: [toolUse('s1', 'Bash', { command: `echo ${LINEAR}` }, '2026-01-01T10:05:00Z')],
  });
  const findings = await auditSecrets({ root: dir, files: listTranscripts(dir), rules });
  assert.equal(findings.length, 1);
  const f = findings[0];
  assert.equal(f.ruleId, 'linear-api-key');
  assert.equal(f.classification, CLASSES.real);
  assert.equal(f.copies, 3);
  assert.equal(f.subagentCopies, 1);
  assert.equal(f.origin, 'pasted by you');
});

test('a value written into a test file is classified as a fixture', async () => {
  const dir = makeTranscripts({
    main: [
      toolUse('w1', 'Write', { file_path: 'repo/tests/login.test.ts', content: `const token = '${GITHUB}'` }, '2026-01-01T10:00:00Z'),
      toolUse('b1', 'Bash', { command: `curl -H "Authorization: token ${GITHUB}" x` }, '2026-01-01T10:01:00Z'),
    ],
  });
  const [f] = await auditSecrets({ root: dir, files: listTranscripts(dir), rules });
  assert.equal(f.classification, CLASSES.example);
});

test('harness-injected text is not counted as something the user pasted', async () => {
  const dir = makeTranscripts({
    main: [user(`Another Claude session sent a message: the key is ${LINEAR}`, '2026-01-01T10:00:00Z')],
  });
  const [f] = await auditSecrets({ root: dir, files: listTranscripts(dir), rules });
  assert.notEqual(f.origin, 'pasted by you');
});

test('CLI never prints a secret value, in text or JSON output', () => {
  const dir = makeTranscripts({
    main: [user(`my key ${LINEAR} and ${GITHUB}`, '2026-01-01T10:00:00Z')],
  });
  for (const args of [['audit', '--path', dir, '--home', dir, '--all'], ['audit', '--path', dir, '--home', dir, '--json']]) {
    const out = execFileSync(process.execPath, [BIN, ...args], { encoding: 'utf8' });
    assert.ok(!out.includes(LINEAR), `Linear key leaked in: ${args.join(' ')}`);
    assert.ok(!out.includes(GITHUB), `GitHub token leaked in: ${args.join(' ')}`);
    assert.ok(!out.includes(LINEAR.slice(4, 20)), 'partial value leaked');
  }
});

test('the package does not import any network module', () => {
  const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
  const files = ['bin', 'src'].flatMap((d) => listJs(path.join(root, d)));
  const NET = /from\s+['"](node:)?(http|https|net|dgram|dns|tls|http2)['"]|\bfetch\s*\(|\bWebSocket\b/;
  for (const f of files) assert.ok(!NET.test(fs.readFileSync(f, 'utf8')), `network use in ${f}`);
});

function listJs(dir) {
  return fs.readdirSync(dir, { withFileTypes: true }).flatMap((e) =>
    e.isDirectory() ? listJs(path.join(dir, e.name)) : e.name.endsWith('.mjs') ? [path.join(dir, e.name)] : []);
}
