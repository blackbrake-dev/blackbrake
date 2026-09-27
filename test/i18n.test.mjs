// Every string the code sends through t() or plural() has a Spanish translation, and every
// translation keeps the same {placeholders} as its English original.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { ES } from '../src/i18n-es.mjs';
import { setLang, t } from '../src/i18n.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

const sources = () => ['bin/blackbrake.mjs', ...fs.readdirSync(path.join(ROOT, 'src'), { recursive: true }).filter((f) => f.endsWith('.mjs')).map((f) => path.join('src', f))]
  .map((f) => fs.readFileSync(path.join(ROOT, f), 'utf8'));

const unescape = (s) => s.replace(/\\'/g, "'");

test('every translatable string has a Spanish version', () => {
  const missing = new Set();

  for (const s of sources()) {
    for (const m of s.matchAll(/\bt\(\s*'((?:[^'\\]|\\.)*)'/g)) if (!(unescape(m[1]) in ES)) missing.add(unescape(m[1]));

    for (const m of s.matchAll(/\bplural\([^,()]+(?:\([^)]*\))?,\s*'([^']+)'(?:,\s*'([^']+)')?/g)) {
      for (const w of [m[1], m[2] ?? `${m[1]}s`]) if (!(w in ES)) missing.add(`[noun] ${w}`);
    }
  }

  assert.deepEqual([...missing], []);
});

test('translations keep every {placeholder}', () => {
  const vars = (s) => [...s.matchAll(/\{(\w+)\}/g)].map((m) => m[1]).sort().join(',');

  for (const [en, es] of Object.entries(ES)) assert.equal(vars(es), vars(en), `placeholders differ: ${en}`);
});

test('guard speaks Spanish inside Claude Code too', async () => {
  const { decide } = await import('../src/guard/policy.mjs');
  setLang('es');
  const read = decide('PreToolUse', { tool_name: 'Read', tool_input: { file_path: '/r/.env' } }, { mode: 'observe' });
  assert.match(read.output.systemMessage, /el agente quiere leer \/r\/\.env/);
  const deny = decide('PreToolUse', { tool_name: 'Bash', tool_input: { command: 'blackbrake mode observe' } }, { mode: 'protect' });
  assert.match(deny.output.hookSpecificOutput.permissionDecisionReason, /^Bloqueado por blackbrake/);
  setLang('en');
});

test('t() falls back to English and fills variables', () => {
  setLang('es');
  assert.equal(t('Last {n} days', { n: 7 }), 'Últimos 7 días');
  assert.equal(t('a string nobody translated'), 'a string nobody translated');
  assert.equal(t('stored in prompt history'), 'guardada en historial de prompts');
  setLang('en');
  assert.equal(t('Last {n} days', { n: 7 }), 'Last 7 days');
});
