// Other Claude Code stores (prompt history, file copies, configuration) and where ~/.claude lives.
// Synthetic secrets are assembled at runtime so no credential-shaped literal exists in the repo.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { buildAdvice } from '../src/advice.mjs';
import { CLASSES } from '../src/secrets/context.mjs';
import { createSecretsAnalyzer } from '../src/secrets/audit.mjs';
import { loadRules } from '../src/secrets/engine.mjs';
import { claudeDirExposure, listStores, readTextFile } from '../src/stores.mjs';

function token(seed, len) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let x = seed, s = '';

  for (let i = 0; i < len; i++) { x = (x * 1103515245 + 12345) % 2147483648; s += alphabet[x % 62]; }

  return s;
}

const PASTED = 'gh' + 'p_' + token(3, 36);

const IN_CONFIG = 'gh' + 'p_' + token(5, 36);

const CREDS = 'gh' + 'p_' + token(9, 36);

const put = (file, text) => { fs.mkdirSync(path.dirname(file), { recursive: true }); fs.writeFileSync(file, text); };

function makeHome() {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'blackbrake-stores-'));
  const project = path.join(home, 'work', 'app');
  put(path.join(home, '.claude', 'history.jsonl'), `${JSON.stringify({ display: `deploy with my token ${PASTED}`, pastedContents: {} })}\n`);
  put(path.join(home, '.claude', '.credentials.json'), JSON.stringify({ token: CREDS }));
  put(path.join(home, '.claude', 'file-history', 's1', 'a@v1'), 'no secrets here');
  put(path.join(home, '.claude', 'file-history', 's1', 'img@v1'), Buffer.from([0x89, 0x50, 0x00, 0x01]));
  put(path.join(home, '.claude.json'), JSON.stringify({ projects: { [project]: {} } }));
  put(path.join(project, '.mcp.json'), JSON.stringify({ mcpServers: { gh: { command: 'npx', env: { GITHUB_TOKEN: IN_CONFIG } } } }));

  return { home, project };
}

test('stores: history, file copies and project config are listed; credential files are not', () => {
  const { home, project } = makeHome();
  const stores = listStores({ home, projects: [project] });
  const names = stores.map((s) => s.store);
  assert.ok(names.includes('prompt history'));
  assert.ok(names.includes('file history'));
  assert.ok(names.includes('project config (app)'));
  assert.ok(!stores.some((s) => s.file.endsWith('.credentials.json')), 'the credential store is never read');
  assert.equal(readTextFile(path.join(home, '.claude', 'file-history', 's1', 'img@v1')), null, 'binary files are skipped');
});

test('stores: a key only in config is "stored", a pasted one counts as sent, and advice differs', () => {
  const { home, project } = makeHome();
  const analyzer = createSecretsAnalyzer(loadRules());

  for (const s of listStores({ home, projects: [project] })) {
    const text = readTextFile(s.file);

    if (text) analyzer.onStoreFile({ ...s, text });
  }

  const found = analyzer.finish();
  const pasted = found.find((f) => f.stores.includes('prompt history'));
  const config = found.find((f) => f.inConfig);
  assert.ok(pasted && config, 'both keys are found');
  assert.ok(!found.some((f) => f.shape.includes(CREDS.slice(4, 10))), 'nothing from the credential file');
  assert.equal(config.classification, CLASSES.real);

  const load = { counts: { skills: 0, agents: 0, commands: 0, pluginsEnabled: 0, duplicates: 0 }, mcp: [], perTurnTokens: { skills: 0, agents: 0 }, usedSkills: null, posture: {}, risks: [] };
  const advice = buildAdvice({ secrets: found, load, spend: { episodes: 0, worst: [], floor: {} } });
  assert.ok(advice.some((a) => a.level === 'critical' && /Rotate the 1 key/.test(a.title)), 'the pasted key is sent: rotate it');
  assert.ok(advice.some((a) => /out of plain-text config/.test(a.title)), 'the config key gets its own precaution');
});

test('~/.claude inside a git repository or a synced folder is flagged', () => {
  const { home } = makeHome();
  assert.equal(claudeDirExposure(home), null);
  fs.mkdirSync(path.join(home, '.git'));
  assert.equal(claudeDirExposure(home).kind, 'git');

  const synced = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'blackbrake-sync-')), 'Dropbox', 'me');
  fs.mkdirSync(path.join(synced, '.claude'), { recursive: true });
  assert.deepEqual(claudeDirExposure(synced), { kind: 'synced', where: 'Dropbox' });
});
