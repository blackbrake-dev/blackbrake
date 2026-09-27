// Precautions tailored to one audit: pure function, results in, a ranked list of actions out.
// Every step names a real setting or place; no savings figures (project rule: claims need data).
// Decisions compare the English data; only the text built here is translated (t()).
import { dec, plural, t } from './i18n.mjs';
import { CLASSES } from './secrets/context.mjs';

const LEVELS = ['critical', 'high', 'medium', 'info'];

// Where each kind of key is usually revoked. Text only: blackbrake never opens a connection.
const PROVIDERS = [
  [/^linear/, 'Linear › Settings › Security & access › API keys'],
  [/^github/, 'github.com/settings/tokens'],
  [/^gitlab/, 'GitLab › Preferences › Access tokens'],
  [/^openai/, 'platform.openai.com/api-keys'],
  [/^anthropic/, 'console.anthropic.com › Settings › API keys'],
  [/^aws/, 'AWS console › IAM › Security credentials'],
  [/^(gcp|google)/, 'Google Cloud console › APIs & Services › Credentials'],
  [/^slack/, 'api.slack.com/apps › your app › OAuth & Permissions'],
  [/^stripe/, 'dashboard.stripe.com › Developers › API keys'],
  [/^npm/, 'npmjs.com › Access Tokens'],
  [/^(huggingface|hf)/, 'huggingface.co/settings/tokens'],
];

const where = (ruleId) => PROVIDERS.find(([re]) => re.test(ruleId))?.[1] ?? t('its provider (the date and origin above tell you which)');

const k = (n) => (n >= 1000 ? `${dec(n / 1000, 1)}k` : String(n));

const list = (xs) => xs.map((x) => t(x)).join(', ');

export function buildAdvice({ secrets, load: inv, spend, claudeCode = null }) {
  const out = [];
  const allReal = secrets.filter((f) => f.classification === CLASSES.real);
  const stores = (f) => f.stores ?? [];
  // Sent to the model provider: in a transcript, or in the prompt history / paste cache.
  const sent = (f) => f.inTranscripts !== false || stores(f).some((s) => /prompt history|paste cache/.test(s));
  const real = allReal.filter(sent);
  const configOnly = allReal.filter((f) => !sent(f) && f.inConfig);
  const localOnly = allReal.filter((f) => !sent(f) && !f.inConfig);

  if (real.length) {
    const elsewhere = [...new Set(real.flatMap(stores))];
    out.push({
      level: 'critical',
      id: 'rotate',
      title: t('Rotate the {n} that look real', { n: plural(real.length, 'key') }),
      why: t('They sit in plain text in your transcripts and were already sent to the model provider.'),
      steps: [
        ...real.map((f) => `${f.ruleId} ${f.shape} (${t(f.origin)}${f.firstSeen ? `, ${f.firstSeen.slice(0, 10)}` : ''}) → ${where(f.ruleId)}`),
        t('Create the new key first, update where it is used, then revoke the old one.'),
        ...(elsewhere.length ? [t('Copies also remain in: {where} (under ~/.claude).', { where: list(elsewhere) })] : []),
      ],
    });
  }

  if (configOnly.length) {
    out.push({
      level: 'high',
      id: 'config-keys',
      title: t('Move {n} out of plain-text config', { n: plural(configOnly.length, 'key') }),
      why: t('Found in {where}. Config files get copied, synced and committed.', { where: list([...new Set(configOnly.flatMap(stores))]) }),
      steps: [
        t('In .mcp.json and settings, reference an environment variable instead of the value: "${MY_API_KEY}".'),
        t('Keep personal overrides in .claude/settings.local.json and make sure it is in .gitignore.'),
        t('If the file was ever committed or shared, rotate the key.'),
      ],
    });
  }

  if (localOnly.length) {
    out.push({
      level: 'medium',
      id: 'local-copies',
      title: t('Delete local copies of {n}', { n: plural(localOnly.length, 'key') }),
      why: t('Found only in {where}: kept on this machine, not seen in a conversation.', { where: list([...new Set(localOnly.flatMap(stores))]) }),
      steps: [t('Those folders under ~/.claude hold copies Claude Code keeps for undo and history; remove the affected files, or rotate the key if the machine is shared.')],
    });
  }

  if (inv.posture.claudeDirExposure) {
    const e = inv.posture.claudeDirExposure;
    const git = e.kind === 'git';
    out.push({
      level: 'high',
      id: 'claude-dir-exposure',
      title: git ? t('Keep ~/.claude out of git') : t('Keep ~/.claude out of {where}', { where: e.where }),
      why: git ? t('~/.claude is inside a git repository ({where}); transcripts can end up committed and pushed.', { where: e.where }) : t('~/.claude is inside a folder that syncs to the cloud ({where}); transcripts leave this machine.', { where: e.where }),
      steps: [git ? t('Add .claude/ to that repository\'s .gitignore, and check its history for committed transcripts.') : t('Exclude the .claude folder from sync, or move it outside the synced folder.')],
    });
  }

  if (real.length) {
    if (real.some((f) => /read from a file|printed by a command/.test(f.origin))) {
      out.push({
        level: 'high',
        id: 'deny-reads',
        title: t('Stop the agent from reading secret files'),
        why: t('At least one key reached the conversation through a file read or a command output.'),
        steps: [
          t('In ~/.claude/settings.json, under "permissions", add a "deny" list:'),
          '"deny": ["Read(./.env)", "Read(./.env.*)", "Read(~/.ssh/**)"]',
          t('Also set "permissions": { "blockReadsOutsideWorkingDirectories": true } so file tools stay inside the project.'),
          t('Keep secrets in environment variables the agent can use without printing them.'),
        ],
      });
    }

    if (!inv.sandbox && ['darwin', 'linux'].includes(inv.platform)) {
      out.push({
        level: 'medium',
        id: 'sandbox',
        title: t('Turn on the sandbox and hide credentials from it'),
        why: t('Claude Code can run shell commands in a sandbox that hides or masks credential files and variables.'),
        steps: [t('In ~/.claude/settings.json: "sandbox": { "enabled": true }, then list your credential files and variables under "sandbox.credentials".')],
      });
    }

    if (real.some((f) => f.origin === 'pasted by you')) {
      out.push({
        level: 'high',
        id: 'pasted',
        title: t('Keep keys out of your prompts'),
        why: t('At least one key was pasted into a prompt by you.'),
        steps: [t('Put the key in an environment variable or a .env file and tell the agent its name, not its value.'), t('guard in protect mode stops a message with a key before it is sent: blackbrake mode protect.')],
      });
    }

    const copies = real.reduce((n, f) => n + f.copies, 0);
    out.push({
      level: 'medium',
      id: 'cleanup-days',
      title: t('Let old transcripts expire sooner'),
      why: t('Rotating a key does not remove the {n} already stored in your transcripts.', { n: plural(copies, 'copy', 'copies') }),
      steps: [t('Set "cleanupPeriodDays" in ~/.claude/settings.json (for example 14) so Claude Code deletes old sessions earlier.')],
    });
  }

  if (inv.posture.dangerousModePromptSkipped) {
    out.push({
      level: 'high',
      id: 'bypass-prompt',
      title: t('Turn the bypass-mode warning back on'),
      why: t('Claude Code no longer asks before entering the mode that skips every permission check.'),
      steps: [
        t('Remove "skipDangerousModePermissionPrompt": true from ~/.claude/settings.json.'),
        t('To block that mode entirely: "permissions": { "disableBypassPermissionsMode": "disable" }.'),
      ],
    });
  }

  if (inv.posture.defaultModeBypass) {
    out.push({
      level: 'high',
      id: 'default-mode',
      title: t('Stop starting sessions with permissions bypassed'),
      why: t('New sessions start in bypassPermissions mode, so the agent acts without asking.'),
      steps: [t('Set "permissions": { "defaultMode": "default" } (or "acceptEdits") in ~/.claude/settings.json.')],
    });
  }

  const FIX = {
    'env.ANTHROPIC_BASE_URL': 'Remove ANTHROPIC_BASE_URL unless you set it yourself: a repository can use it to send your API key and prompts elsewhere (CVE-2026-21852).',
    'permissions.allow': 'Replace the blanket "Bash" rule with the specific commands you trust, e.g. "Bash(npm test:*)".',
    'permissions.additionalDirectories': 'List only the folders a project needs, not your whole home or disk.',
    enableAllProjectMcpServers: 'Set it to false and approve each project\'s MCP servers one by one (or with "enabledMcpjsonServers").',
    hooks: 'Read what each hook command runs before trusting the project; hooks from a repository run on your machine.',
  };

  for (const i of inv.configIssues ?? []) {
    out.push({
      level: i.key === 'hooks' ? 'medium' : 'high',
      where: i.where,
      id: `config:${i.key}`,
      title: `${t(i.where)}: ${t(i.issue)}`,
      why: i.key === 'hooks' ? t('Project settings come with the repository, so anyone who can commit to it decides what runs.') : t('This widens what the agent can do, or where your traffic goes, without asking you.'),
      steps: [t(FIX[i.key])],
    });
  }

  const mcp = inv.mcpIssues ?? [];

  if (mcp.length) {
    out.push({
      level: mcp.some((m) => /plain http/.test(m.issue)) ? 'high' : 'medium',
      id: 'mcp',
      title: t('Tighten {n}', { n: plural(mcp.length, 'MCP server') }),
      why: t('An unpinned package runs whatever its publisher releases next; plain http can be read or changed on the way.'),
      steps: [...mcp.slice(0, 5).map((m) => `${m.server} (${m.source}): ${t(m.issue)}`), t('Pin a version (package@1.2.3) and use https URLs.')],
    });
  }

  if (claudeCode?.open?.length) {
    const high = claudeCode.open.filter((a) => a.severity === 'high' || a.severity === 'critical');
    out.push({
      level: high.length ? 'high' : 'medium',
      id: 'update-claude',
      title: t('Update Claude Code ({v} has {n})', { v: claudeCode.version, n: plural(claudeCode.open.length, 'known vulnerability', 'known vulnerabilities') }),
      why: t('Your latest session ({d}) ran {v}; these were fixed in later versions (advisories as of {a}).', { d: claudeCode.seen, v: claudeCode.version, a: claudeCode.advisoriesDate }),
      steps: [...claudeCode.open.slice(0, 3).map((a) => `${a.id} (${t(a.severity)}, ${t('fixed in {v}', { v: a.fixed })}): ${a.summary}`), t('Run "claude update", or keep auto-updates on.')],
    });
  }

  const byOwner = new Map();

  for (const r of inv.risks.filter((x) => x.inCode)) (byOwner.get(r.owner) ?? byOwner.set(r.owner, []).get(r.owner)).push(r);

  for (const [owner, rs] of [...byOwner].slice(0, 3)) {
    out.push({
      level: 'high',
      id: `review:${owner}`,
      title: t('Review {owner}', { owner }),
      why: t('Its code matches: {what}.', { what: [...new Set(rs.map((r) => t(r.label)))].join('; ') }),
      steps: [...[...new Set(rs.map((r) => r.file))].slice(0, 3).map((f) => `${t('File:')} ${f}`), t('If you do not know why it needs this, disable or remove it until you do.')],
    });
  }

  const c = inv.counts;
  const perTurn = inv.perTurnTokens.skills + inv.perTurnTokens.agents;

  if (inv.usedSkills !== null && c.skills >= 20 && inv.usedSkills / c.skills < 0.3) {
    out.push({
      level: 'medium',
      id: 'trim-skills',
      title: t('Trim the skills you never use'),
      why: t('{n} of {total} have never been used, and every skill description is loaded on every turn (~{tokens} tokens with agents).', { n: plural(c.skills - inv.usedSkills, 'skill'), total: c.skills, tokens: k(perTurn) }),
      steps: [
        t('Move unused skill folders out of ~/.claude/skills, or disable the plugins that bring them.'),
        ...(c.duplicates ? [t('{n} are installed twice under the same name: keep one copy.', { n: plural(c.duplicates, 'item') })] : []),
      ],
    });
  }

  if (spend.floor?.sessions && spend.floor.medianTokens > 30000) {
    out.push({
      level: 'medium',
      id: 'context',
      title: t('Lighten the context sent on every turn'),
      why: t('Each turn starts with ~{n} tokens of fixed context before any work.', { n: k(spend.floor.medianTokens) }),
      steps: [t('Shorten CLAUDE.md files, and remove skills, agents and MCP servers you do not need in this project.')],
    });
  }

  if (spend.episodes && spend.topShare >= 0.5 && spend.worst.length) {
    const w = spend.worst[0];
    out.push({
      level: 'info',
      id: 'episodes',
      title: t('Watch your longest episodes'),
      why: t('Your costliest 10% of episodes are {pct}% of your spend; the costliest ran {turns} and {tools}.', { pct: Math.round(spend.topShare * 100), turns: plural(w.turns, 'turn'), tools: plural(w.tools, 'tool call') }),
      steps: [
        t('Split long tasks into shorter sessions, and start fresh when the task changes.'),
        t('Coming to guard: a live warning when an episode passes your own 90th percentile.'),
      ],
    });
  }

  return out.sort((a, b) => LEVELS.indexOf(a.level) - LEVELS.indexOf(b.level));
}
