// Tests use only synthetic secrets assembled at runtime, so no credential-shaped literal exists
// in this repository (GitHub push protection and other scanners have nothing to flag).
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { auditSecrets, mask } from '../src/secrets/audit.mjs';
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

test('scanning time grows linearly on keyword-dense text, and secrets inside it are still found', () => {
  const sample = (n) => {
    const filler = 'el consumo de energía y el resumo del informe: asumo que el consumo sube. '.repeat(n);
    const text = `${filler}\nmy key ${GITHUB}\n${filler}`;
    const t0 = performance.now();
    const found = scanText(rules, text);

    return { ms: performance.now() - t0, found };
  };

  const small = sample(500);
  const big = sample(4000);
  assert.ok(big.found.some((f) => f.secret === GITHUB), 'the real token is still found');
  assert.ok(big.ms < Math.max(50, small.ms) * 8 * 3, `8x the text took ${(big.ms / small.ms).toFixed(1)}x the time (${big.ms.toFixed(0)} ms)`);
});

test('allowlists that read the whole match still see the identifier before the keyword', () => {
  const value = token(31, 32);
  const hits = (text) => scanText(rules, text).filter((f) => f.ruleId === 'generic-api-key' && f.secret === value);
  assert.equal(hits(`rapidapi_key = "${value}"`).length, 0, 'gitleaks allowlists "rapid" before "api"');
  assert.equal(hits(`service_api_key = "${value}"`).length, 1);
});

test('AI provider keys from the betterleaks rules are detected', () => {
  const ids = new Set(rules.rules.map((r) => r.id));

  for (const id of ['openrouter-api-key', 'deepseek-api-key', 'groq-api-key', 'xai-api-key', 'mistral-api-key', 'anthropic-api-key', 'openai-api-key']) assert.ok(ids.has(id), `missing rule ${id}`);

  const hex = (seed, n) => {
    let x = seed, s = '';

    for (let i = 0; i < n; i++) { x = (x * 1103515245 + 12345) % 2147483648; s += '0123456789abcdef'[(x >> 16) % 16]; }

    return s;
  };

  const openrouter = `sk-or-v1-${hex(21, 64)}`;
  const found = scanText(rules, `OPENROUTER_API_KEY=${openrouter}\n`);
  assert.ok(found.some((f) => f.ruleId === 'openrouter-api-key' && f.secret === openrouter));
});

test('masked shapes show at most a public service prefix, never secret characters', () => {
  const generic = `${'Zq7'}${'x'.repeat(29)}`;
  assert.equal(mask(generic), '••••(32)', 'generic secrets show no characters');
  assert.equal(mask(LINEAR), `lin_api_••••(${LINEAR.length})`);
  assert.ok(mask(GITHUB).startsWith('ghp_••••('));

  for (const s of [LINEAR, GITHUB, generic]) assert.ok(!mask(s).includes(s.slice(8, 12)), 'no characters beyond the prefix');
});

test('the package does not import any network module', () => {
  const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
  const files = ['bin', 'src'].flatMap((d) => listJs(path.join(root, d)));
  const NET = /from\s+['"](node:)?(http|https|net|dgram|dns|tls|http2)['"]|\bfetch\s*\(|\bWebSocket\b/;

  for (const f of files) assert.ok(!NET.test(fs.readFileSync(f, 'utf8')), `network use in ${f}`);
});

// guard starts processes: Claude Code's own CLI (setup, launch), `node --version`, the operating
// system's notifier and a terminal window for the alerts. Each command is fixed (checked in
// test/watch.test.mjs); nothing goes through a shell.
test('child processes: only from the guard installer, launcher, notifier and alerts window', () => {
  const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
  const files = ['bin', 'src', 'plugin'].flatMap((d) => listJs(path.join(root, d)));
  const allowed = new Set(['src/guard/install.mjs', 'src/guard/cli.mjs', 'src/guard/watch.mjs', 'src/guard/window.mjs', 'src/guard/background.mjs', 'src/guard/autostart.mjs', 'src/fix/agent.mjs']);

  for (const f of files) {
    const text = fs.readFileSync(f, 'utf8');
    const rel = path.relative(root, f).replace(/\\/g, '/');

    if (!/child_process|\beval\s*\(|new Function\s*\(/.test(text)) continue;
    assert.ok(allowed.has(rel), `process or dynamic code in ${rel}`);
    assert.ok(!/\beval\s*\(|new Function\s*\(/.test(text), `dynamic code in ${rel}`);

    for (const m of text.matchAll(/\bspawn(?:Sync)?\(\s*([^,]+),/g)) assert.match(m[1].trim(), /^('claude'|'node'|c\.file|process\.execPath)$/, `unexpected process in ${rel}: ${m[1]}`);

    // Only spawn/spawnSync, imported by name: no exec (it runs a shell), execFile, fork, or aliases.
    for (const m of text.matchAll(/import\s*\{([^}]*)\}\s*from\s*['"](?:node:)?child_process['"]/g)) assert.match(m[1], /^\s*spawn(Sync)?\s*(,\s*spawn(Sync)?\s*)?$/, `child_process import in ${rel}: ${m[1]}`);
    assert.ok(!/\b(exec|execSync|execFile|execFileSync|fork)\s*\(/.test(text), `exec/fork in ${rel}`);
    assert.ok(!/require\(\s*['"](?:node:)?child_process/.test(text) && !/import\s+\*\s+as\s+\w+\s+from\s+['"](?:node:)?child_process/.test(text), `child_process imported whole in ${rel}`);
  }

  // Dynamic imports load fixed files only.
  for (const f of files) {
    for (const m of fs.readFileSync(f, 'utf8').matchAll(/\bimport\(\s*([^)]*)\)/g)) assert.match(m[1].trim(), /^(['"])[./\w-]+\.mjs\1$/, `computed dynamic import in ${f}: ${m[1]}`);
  }
});

function listJs(dir) {
  return fs.readdirSync(dir, { withFileTypes: true }).flatMap((e) =>
    e.isDirectory() ? listJs(path.join(dir, e.name)) : e.name.endsWith('.mjs') ? [path.join(dir, e.name)] : []);
}
