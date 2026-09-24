// What the agent loads: skills, agents, commands, plugins, hooks and MCP servers, how much of it
// is paid for on every turn, how much is ever used, and static patterns worth a look.
// Static only: nothing found here is ever executed (unlike scanners that start MCP servers).
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const readJson = (f) => { try { return JSON.parse(fs.readFileSync(f, 'utf8')); } catch { return null; } };
const readText = (f, max = 256 * 1024) => {
  try { const st = fs.statSync(f); if (!st.isFile() || st.size > max) return null; return fs.readFileSync(f, 'utf8'); } catch { return null; }
};
const listDir = (d) => { try { return fs.readdirSync(d, { withFileTypes: true }); } catch { return []; } };

// Frontmatter "name" and "description" (single line, or folded/literal block).
export function frontmatter(text) {
  const m = /^---\r?\n([\s\S]*?)\r?\n---/.exec(text ?? '');
  if (!m) return {};
  const out = {};
  const lines = m[1].split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const kv = /^([A-Za-z_-]+):\s*(.*)$/.exec(lines[i]);
    if (!kv) continue;
    let value = kv[2].trim();
    if (/^[|>][-+]?$/.test(value)) {
      const block = [];
      while (i + 1 < lines.length && /^\s+/.test(lines[i + 1])) block.push(lines[++i].trim());
      value = block.join(' ');
    }
    out[kv[1]] = value.replace(/^["']|["']$/g, '');
  }
  return out;
}

// Rough token estimate (~4 characters per token for English text).
const tokens = (s) => Math.ceil((s ?? '').length / 4);

function collectItems(dir, kind, source) {
  const items = [];
  for (const e of listDir(dir)) {
    const full = path.join(dir, e.name);
    if (kind === 'skill' && e.isDirectory()) {
      const md = path.join(full, 'SKILL.md');
      const text = readText(md);
      if (text === null) continue;
      const fm = frontmatter(text);
      const name = fm.name ?? e.name;
      items.push({ kind, source, name, dir: full, file: md, perTurnTokens: tokens(`${name}: ${fm.description ?? ''}`) });
    } else if ((kind === 'agent' || kind === 'command') && e.isFile() && e.name.endsWith('.md')) {
      const text = readText(full);
      if (text === null) continue;
      const fm = frontmatter(text);
      const name = fm.name ?? e.name.replace(/\.md$/, '');
      items.push({ kind, source, name, dir: null, file: full, perTurnTokens: kind === 'agent' ? tokens(`${name}: ${fm.description ?? ''}`) : 0 });
    } else if (kind === 'command' && e.isDirectory()) {
      items.push(...collectItems(full, kind, source));
    }
  }
  return items;
}

function pluginInstalls(claudeDir, settings) {
  const installed = readJson(path.join(claudeDir, 'plugins', 'installed_plugins.json'));
  const enabled = settings?.enabledPlugins ?? {};
  const out = [];
  for (const [id, entries] of Object.entries(installed?.plugins ?? {})) {
    const entry = Array.isArray(entries) ? entries[0] : entries;
    if (!entry?.installPath) continue;
    out.push({ id, path: entry.installPath, enabled: enabled[id] === true, version: entry.version ?? null });
  }
  return out;
}

function mcpServers(home, claudeJson, pluginList) {
  const servers = [];
  const add = (obj, source) => {
    for (const [name, cfg] of Object.entries(obj ?? {})) servers.push({ name, source, command: [cfg?.command, ...(cfg?.args ?? [])].filter(Boolean).join(' ') || cfg?.url || '' });
  };
  add(claudeJson?.mcpServers, 'user');
  for (const [proj, p] of Object.entries(claudeJson?.projects ?? {})) add(p?.mcpServers, `project:${path.basename(proj)}`);
  for (const pl of pluginList.filter((p) => p.enabled)) add(readJson(path.join(pl.path, '.mcp.json'))?.mcpServers ?? readJson(path.join(pl.path, '.mcp.json')), `plugin:${pl.id}`);
  return servers;
}

// ------------------------------------------------------------------------------------------------
// Static patterns. A match is "worth a look", not a verdict: security skills legitimately describe
// these patterns in their documentation. Matches in executable files and hooks weigh more than
// matches in Markdown.
const PATTERNS = [
  { id: 'remote-exec', label: 'downloads and runs code', re: /\b(curl|wget)\b[^\n|]{0,200}\|\s*(sudo\s+)?(ba|z)?sh\b|\b(iwr|irm|Invoke-WebRequest|Invoke-RestMethod)\b[^\n|]{0,200}\|\s*(iex|Invoke-Expression)\b/i },
  { id: 'instruction-override', label: 'tells the agent to ignore rules or hide actions', re: /ignore (all )?(previous|prior|above) instructions|do not (tell|inform|mention (this )?to) the user|without (asking|telling|notifying) the user|hide (this|it) from the user/i },
  { id: 'permission-bypass', label: 'disables permission checks', re: /--dangerously-skip-permissions|bypassPermissions|skipDangerousModePermissionPrompt/ },
  { id: 'credential-access', label: 'reads credential files', re: /~\/\.ssh\/|id_rsa\b|\.aws\/credentials|\.claude\/\.credentials\.json|\.git-credentials|\.npmrc\b/ },
  { id: 'exfiltration', label: 'sends environment or secrets over the network', re: /\b(curl|wget|fetch|requests\.(post|put)|Invoke-WebRequest|Invoke-RestMethod)\b[^\n]{0,160}(\$\{?\w*(TOKEN|SECRET|KEY|PASSWORD)|process\.env|os\.environ|printenv|\benv\b\s*\|)/i },
  { id: 'obfuscation', label: 'decodes and runs hidden content', re: /base64\s+(-d|--decode)[^\n]{0,80}\|\s*(ba)?sh|eval\s*\(\s*(atob|Buffer\.from)\s*\(|[A-Za-z0-9+/]{400,}={0,2}/ },
];
const CODE_EXT = /\.(sh|bash|zsh|ps1|py|js|mjs|cjs|ts|rb|json)$/i;
const SCAN_EXT = /\.(md|sh|bash|zsh|ps1|py|js|mjs|cjs|ts|rb|json|toml|ya?ml)$/i;

function scanFiles(files, owner) {
  const findings = [];
  for (const f of files) {
    const text = readText(f);
    if (text === null) continue;
    for (const p of PATTERNS) {
      if (p.re.test(text)) findings.push({ owner, patternId: p.id, label: p.label, file: f, inCode: CODE_EXT.test(f) });
    }
  }
  return findings;
}

function filesUnder(dir, depth = 3) {
  if (!dir || depth < 0) return [];
  return listDir(dir).flatMap((e) => {
    const full = path.join(dir, e.name);
    if (e.isDirectory()) return e.name === 'node_modules' || e.name.startsWith('.git') ? [] : filesUnder(full, depth - 1);
    return SCAN_EXT.test(e.name) ? [full] : [];
  });
}

export function inventory({ home = os.homedir() } = {}) {
  const claudeDir = path.join(home, '.claude');
  const settings = readJson(path.join(claudeDir, 'settings.json')) ?? {};
  const claudeJson = readJson(path.join(home, '.claude.json')) ?? {};
  const plugins = pluginInstalls(claudeDir, settings);

  const items = [
    ...collectItems(path.join(claudeDir, 'skills'), 'skill', 'user'),
    ...collectItems(path.join(claudeDir, 'agents'), 'agent', 'user'),
    ...collectItems(path.join(claudeDir, 'commands'), 'command', 'user'),
  ];
  for (const pl of plugins.filter((p) => p.enabled)) {
    items.push(
      ...collectItems(path.join(pl.path, 'skills'), 'skill', `plugin:${pl.id}`),
      ...collectItems(path.join(pl.path, 'agents'), 'agent', `plugin:${pl.id}`),
      ...collectItems(path.join(pl.path, 'commands'), 'command', `plugin:${pl.id}`),
    );
  }

  // The same skill or agent can be installed twice (e.g. copied to ~/.claude and bundled in a
  // plugin). Count each name once; report how many duplicates were found.
  const seen = new Set();
  const unique = [];
  let duplicates = 0;
  for (const i of items) {
    const key = `${i.kind}:${i.name.toLowerCase()}`;
    if (seen.has(key)) { duplicates++; continue; }
    seen.add(key);
    unique.push(i);
  }

  const usage = claudeJson.skillUsage ?? null;
  const usedNames = new Set(Object.entries(usage ?? {}).filter(([, v]) => (v?.usageCount ?? 0) > 0).flatMap(([k]) => [k, k.split(':').pop()]));
  const skills = unique.filter((i) => i.kind === 'skill');
  const usedSkills = usage ? skills.filter((s) => usedNames.has(s.name) || usedNames.has(path.basename(s.dir))).length : null;

  const risks = [
    ...unique.flatMap((i) => scanFiles(i.dir ? filesUnder(i.dir) : [i.file], `${i.kind}:${i.name}`)),
    ...plugins.filter((p) => p.enabled).flatMap((p) => scanFiles(filesUnder(path.join(p.path, 'hooks')), `plugin-hooks:${p.id}`)),
  ];

  const hookEvents = Object.keys(settings.hooks ?? {});
  return {
    counts: {
      skills: skills.length,
      agents: unique.filter((i) => i.kind === 'agent').length,
      commands: unique.filter((i) => i.kind === 'command').length,
      pluginsEnabled: plugins.filter((p) => p.enabled).length,
      pluginsInstalled: plugins.length,
      duplicates,
    },
    perTurnTokens: {
      skills: skills.reduce((a, s) => a + s.perTurnTokens, 0),
      agents: unique.filter((i) => i.kind === 'agent').reduce((a, s) => a + s.perTurnTokens, 0),
    },
    usedSkills,
    mcp: mcpServers(home, claudeJson, plugins),
    posture: {
      dangerousModePromptSkipped: settings.skipDangerousModePermissionPrompt === true,
      defaultModeBypass: settings.permissions?.defaultMode === 'bypassPermissions',
      hookEvents,
    },
    risks,
  };
}
