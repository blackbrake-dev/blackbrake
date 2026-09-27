// What the agent loads: skills, agents, commands, plugins, hooks and MCP servers, how much of it
// is paid for on every turn, how much is ever used, and static patterns worth a look.
// Static only: nothing found here is ever executed (unlike scanners that start MCP servers).
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { claudeDirExposure } from '../stores.mjs';
import { cleanDeep, isLocalPath, localFileStat } from '../text.mjs';

// A planted symlink could point at a network share (NTLM leak) or a device: see localFileStat.
const readText = (f, max = 256 * 1024) => {
  try { const st = localFileStat(f);

 if (!st || st.size > max) return null;

 return fs.readFileSync(f, 'utf8'); } catch { return null; }
};

const readJson = (f) => { try { return JSON.parse(readText(f, 20e6) ?? 'null'); } catch { return null; } };

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

    if (!isLocalPath(entry?.installPath)) continue;
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
  { id: 'credential-access', label: 'reads credential files', re: /~\/\.ssh\/|id_rsa\b|\.aws\/credentials|\.claude\/\.credentials\.json|\.git-credentials|\.npmrc\b|\.config\/gh\/hosts\.yml|security\s+find-(generic|internet)-password|Login Data\b|\.docker\/config\.json/ },
  { id: 'exfiltration', label: 'sends environment or secrets over the network', re: /\b(curl|wget|fetch|requests\.(post|put)|Invoke-WebRequest|Invoke-RestMethod)\b[^\n]{0,160}(\$\{?\w*(TOKEN|SECRET|KEY|PASSWORD)|process\.env|os\.environ|printenv|\benv\b\s*\|)/i },
  { id: 'obfuscation', label: 'decodes and runs hidden content', re: /base64\s+(-d|--decode)[^\n]{0,80}\|\s*(ba)?sh|eval\s*\(\s*(atob|Buffer\.from)\s*\(|[A-Za-z0-9+/]{400,}={0,2}/ },
  // From public research on malicious agent skills (Snyk ToxicSkills, Cisco skill-scanner): 91% of
  // confirmed malicious skills use prompt injection, often invisible to a human reviewer.
  { id: 'hidden-text', label: 'hides text the model reads but you cannot see', test: hiddenText },
  { id: 'exfil-endpoint', label: 'contacts a tunnel, paste or webhook service', re: /\b(ngrok(-free)?\.(io|app|dev)|trycloudflare\.com|webhook\.site|requestbin\.|pipedream\.net|pastebin\.com\/raw|transfer\.sh|discord(app)?\.com\/api\/webhooks|api\.telegram\.org\/bot|interact\.sh|oast\.(fun|pro|live|site|online|me)|burpcollaborator\.net)/i },
  { id: 'persistence', label: 'sets something to run at login or on a schedule', re: /\bcrontab\s+(-[el]|\S+\.cron)|launchctl\s+(load|bootstrap)|systemctl\s+(--user\s+)?enable|\\CurrentVersion\\Run(Once)?\b|schtasks(\.exe)?\s+\/create|Register-ScheduledTask|>>\s*~\/\.(bashrc|zshrc|profile|bash_profile)\b/i },
  { id: 'system-impersonation', label: 'poses as a system message to the model', re: /<\/?system-reminder>|<\/?system>|\bSYSTEM OVERRIDE\b|you are now in (developer|god) mode/i },
];

// Unicode tag characters (U+E0000–E007F) spell out text that renders as nothing; bidirectional
// controls reorder what a reviewer sees ("Trojan Source"); runs of zero-width characters hide text.
function hiddenText(text) {
  if (/[\u{E0000}-\u{E007F}]/u.test(text)) return true;

  if (/[\u202A-\u202E\u2066-\u2069]/.test(text)) return true;

  return (text.match(/[\u200B\u2060\u2062-\u2064\u180E]/g) ?? []).length >= 3;
}

// MCP servers: what a supply-chain or transport problem looks like in the config, statically.
function mcpIssues(servers) {
  const out = [];

  for (const s of servers) {
    const cmd = s.command;
    const pkg = /\b(npx|bunx|uvx|pnpm\s+dlx|yarn\s+dlx)\s+(?:-y\s+|--yes\s+)?(@?[\w.-]+(?:\/[\w.-]+)?)(@[\w.^~-]+)?/.exec(cmd);

    if (pkg && !pkg[3] && !pkg[2].startsWith('-')) out.push({ server: s.name, source: s.source, issue: `runs "${pkg[2]}" without a pinned version` });

    if (/^http:\/\//i.test(cmd) && !/^http:\/\/(localhost|127\.0\.0\.1|\[::1\])/i.test(cmd)) out.push({ server: s.name, source: s.source, issue: 'connects over plain http' });
  }

  return out;
}

// Settings that widen what the agent can do or where its traffic goes, from one settings file.
function settingsIssues(s, where, home) {
  const out = [];

  if (!s) return out;
  const allow = s.permissions?.allow ?? [];

  if (allow.some((a) => /^Bash(\((\*|\*:\*)\))?$/.test(a))) out.push({ where, issue: 'allows every shell command without asking', key: 'permissions.allow' });
  const dirs = s.permissions?.additionalDirectories ?? [];

  if (dirs.some((d) => ['~', '/', home].includes(String(d).replace(/[\\/]+$/, '')) || /^[A-Za-z]:\\?$/.test(String(d)))) out.push({ where, issue: 'gives file access to your whole home or disk', key: 'permissions.additionalDirectories' });

  if (s.enableAllProjectMcpServers === true) out.push({ where, issue: 'approves every MCP server a project ships, without asking', key: 'enableAllProjectMcpServers' });
  const base = s.env?.ANTHROPIC_BASE_URL;

  if (base && !/^https:\/\/api\.anthropic\.com\/?$/i.test(base)) out.push({ where, issue: `sends your API traffic to ${String(base).slice(0, 60)}`, key: 'env.ANTHROPIC_BASE_URL' });
  const hooks = Object.values(s.hooks ?? {}).flat().flatMap((h) => h?.hooks ?? []).filter((h) => h?.type === 'command').length;

  if (hooks && where !== 'user settings') out.push({ where, issue: `runs ${hooks} hook command${hooks === 1 ? '' : 's'} on your machine`, key: 'hooks' });

  return out;
}

const CODE_EXT = /\.(sh|bash|zsh|ps1|py|js|mjs|cjs|ts|rb|json)$/i;

const SCAN_EXT = /\.(md|sh|bash|zsh|ps1|py|js|mjs|cjs|ts|rb|json|toml|ya?ml)$/i;

function scanFiles(files, owner) {
  const findings = [];

  for (const f of files) {
    const text = readText(f);

    if (text === null) continue;

    for (const p of PATTERNS) {
      if (p.test ? p.test(text) : p.re.test(text)) findings.push({ owner, patternId: p.id, label: p.label, file: f, inCode: CODE_EXT.test(f) || p.id === 'hidden-text' });
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
  // Claude Code also records the home folder as a "project" when started there; its .claude/ is the
  // user configuration, already read above.
  const same = (a, b) => path.resolve(a).toLowerCase() === path.resolve(b).toLowerCase();
  const projectDirs = Object.keys(claudeJson.projects ?? {}).filter((d) => isLocalPath(d) && path.isAbsolute(d) && !same(d, home));
  const mcp = mcpServers(home, claudeJson, plugins);

  for (const dir of projectDirs) {
    const project = readJson(path.join(dir, '.mcp.json'));

    for (const [name, cfg] of Object.entries(project?.mcpServers ?? {})) mcp.push({ name, source: `project .mcp.json:${path.basename(dir)}`, command: [cfg?.command, ...(cfg?.args ?? [])].filter(Boolean).join(' ') || cfg?.url || '' });
  }

  const configIssues = [
    ...settingsIssues(settings, 'user settings', home),
    ...settingsIssues(readJson(path.join(claudeDir, 'settings.local.json')), 'user local settings', home),
    ...projectDirs.flatMap((d) => ['settings.json', 'settings.local.json'].flatMap((f) => settingsIssues(readJson(path.join(d, '.claude', f)), `${path.basename(d)}/.claude/${f}`, home))),
  ];

  // Everything below ends up on screen or in --json: names, paths and commands come from files
  // anyone can write (a skill's frontmatter, a project's .mcp.json), so they are cleaned.
  return {
    projectDirs,
    ...cleanDeep(report({ settings, configIssues, mcp, skills, unique, plugins, duplicates, usedSkills, hookEvents, home, risks })),
  };
}

function report({ settings, configIssues, mcp, skills, unique, plugins, duplicates, usedSkills, hookEvents, home, risks }) {
  return {
    platform: process.platform,
    sandbox: settings.sandbox?.enabled === true,
    configIssues,
    mcpIssues: mcpIssues(mcp),
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
    mcp,
    posture: {
      dangerousModePromptSkipped: settings.skipDangerousModePermissionPrompt === true,
      defaultModeBypass: settings.permissions?.defaultMode === 'bypassPermissions',
      hookEvents,
      claudeDirExposure: claudeDirExposure(home),
    },
    risks,
  };
}
