// guard: what to do on each Claude Code hook event. Pure functions: event input in, a decision
// and log entries out. No I/O here, so every rule is testable.
//
// Modes (decided by the user in their own terminal, never by the agent):
//   observe  (default) warn the user and log; nothing is stopped.
//   protect  stop secrets before they are sent, ask before risky reads, hide secrets in tool
//            output before the model sees them.
// Tamper protection applies in both modes: the agent may not switch guard off.
//
// Limit, stated plainly: guard runs as the same user as the agent. Tamper protection closes the
// direct and the common indirect ways (tools, shell commands, MCP tools); an agent that can run
// arbitrary code can still find another way. `blackbrake status` checks the installed code.
import { mask } from '../secrets/audit.mjs';
import { isExampleValue } from '../secrets/context.mjs';
import { scanText } from '../secrets/engine.mjs';
import { t } from '../i18n.mjs';
import { clean } from '../text.mjs';

// ---------- detection ----------

// Secrets in a piece of text. Only the value itself can dismiss one as an example (see
// isExampleValue): the words around it cannot, because in a live prompt or request they are
// trivial to plant and common by accident.
export function findSecrets(rules, text) {
  if (!text) return [];
  const out = [];
  const seen = new Set();

  for (const view of decodedViews(String(text))) {
    for (const f of scanText(rules, view)) {
      if (seen.has(f.secret)) continue;
      seen.add(f.secret);

      if (!isExampleValue(f.secret)) out.push({ ruleId: f.ruleId, secret: f.secret, shape: mask(f.secret) });
    }
  }

  return out;
}

// The same text as a secret can hide in it, by accident or on purpose: without invisible
// characters (zero-width, bidi, soft hyphen), percent-decoded (URLs), and with base64 or hex runs
// decoded when they decode to readable text. Bounded: at most 64 decoded runs, 2 MB in total.
// Arbitrary transformations (reversing, spacing out) are not undone: the README says so.
// oxlint-disable-next-line no-control-regex
const INVISIBLE = /[\u00ad\u034f\u061c\u115f\u1160\u17b4\u17b5\u180b-\u180f\u200b-\u200f\u202a-\u202e\u2060-\u206f\ufe00-\ufe0f\ufeff]/g;

const printable = (s) => s.length > 0 && [...s].filter((c) => c >= ' ' && c <= '~').length / s.length > 0.9;

// Percent-decoding as UTF-8 (so an encoded zero-width character becomes one, and is then removed).
const percentDecode = (s) => s.replace(/(?:%[0-9a-f]{2})+/gi, (seq) => Buffer.from(seq.replace(/%/g, ''), 'hex').toString('utf8'));

export function decodedViews(text) {
  const views = new Set([text]);
  let decoded = text;

  for (let i = 0; i < 2 && /%[0-9a-f]{2}/i.test(decoded); i++) decoded = percentDecode(decoded);
  const bases = [...new Set([text, decoded])].map((b) => b.replace(INVISIBLE, ''));

  for (const b of [decoded, ...bases]) views.add(b);
  let budget = 2 * 1024 * 1024;
  let runs = 0;

  for (const base of new Set(bases)) {
    for (const m of base.matchAll(/[A-Za-z0-9+/_-]{24,}={0,2}|(?:[0-9a-fA-F]{2}){20,}/g)) {
      if (++runs > 64 || budget <= 0) break;
      const run = m[0];
      const hex = /^[0-9a-fA-F]+$/.test(run) && run.length % 2 === 0;
      let out = '';

      try { out = hex ? Buffer.from(run, 'hex').toString('latin1') : Buffer.from(run.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('latin1'); } catch { continue; }

      if (out.length >= 16 && printable(out)) {
        views.add(out);
        budget -= out.length;
      }
    }
  }

  return [...views];
}

// Files that exist to hold credentials. Templates (.env.example and friends) are not.
const SENSITIVE_FILE = /(^|[\\/])(\.env(\.[\w-]+)?|\.envrc|id_(rsa|dsa|ecdsa|ed25519)|[\w-]*\.(pem|key|p12|pfx)|\.netrc|\.npmrc|\.pypirc|\.git-credentials|credentials(\.json)?|service[-_]?account[\w-]*\.json|\.credentials\.json)$/i;

const SENSITIVE_DIR = /(^|[\\/])(\.ssh|\.aws|\.gnupg|\.kube|\.docker|\.config[\\/]gh)([\\/]|$)/i;

const TEMPLATE = /\.(example|sample|template|dist|defaults?)$/i;

export const isSensitivePath = (p) => Boolean(p) && !TEMPLATE.test(p) && (SENSITIVE_FILE.test(p) || SENSITIVE_DIR.test(p));

// Shell commands that print secrets into the conversation.
const SECRET_DUMP = [
  [/(^|[;&|]\s*)(printenv|env|set|Get-ChildItem\s+env:|gci\s+env:|dir\s+env:)\s*($|[;&|])/i, 'prints every environment variable'],
  [/\becho\s+["']?\$\{?\w*(TOKEN|SECRET|KEY|PASSWORD|PASSWD|CREDENTIAL)\w*/i, 'prints a secret variable'],
  [/\$env:\w*(TOKEN|SECRET|KEY|PASSWORD)\w*/i, 'prints a secret variable'],
];

// Commands whose real content cannot be read from the command line.
// Inline interpreter code (node -e, python -c…) can do anything a file write could, out of sight
// of the path checks; in protect mode it is asked about.
const OPAQUE = /\s-(e|en|enc|encodedcommand)\s+[A-Za-z0-9+/=]{16,}|\bbase64\s+(-d|--decode)\b[^\n]*\|\s*(ba|z)?sh\b|\b(iex|Invoke-Expression)\b|\beval\s+["'$]|\b(node|bun|deno)(\.exe)?\s+(-e|--eval|-p|--print)\b|\bpython[\d.]*(\.exe)?\s+-c\b|\bperl\s+-[a-z]*e\b|\bruby\s+-e\b/i;

// Commands that destroy work; asked for again right after a compaction (the agent may have lost
// the detail that made them safe).
const DESTRUCTIVE = /\brm\s+-[a-z]*r[a-z]*f|\brm\s+-[a-z]*f[a-z]*r|\bgit\s+(reset\s+--hard|clean\s+-[a-z]*f|push\s+(-f\b|--force)|branch\s+-D|checkout\s+--\s)|\b(DROP|TRUNCATE)\s+(TABLE|DATABASE|SCHEMA)\b|\bterraform\s+destroy\b|\bkubectl\s+delete\b|Remove-Item\b[^\n]*-Recurse|\bdel\s+\/s\b|\bformat\s+[a-z]:/i;

const COMPACTION_TTL_MS = 15 * 60 * 1000;

export function bashRisk(command = '') {
  for (const [re, label] of SECRET_DUMP) if (re.test(command)) return { kind: 'secret-dump', label: t(label) };
  // Any mention of a credential file, whatever the verb (cat, cp, certutil, tar, Get-Content…).
  const hit = command.split(/[\s;&|<>()'"`,=]+/).find((w) => isSensitivePath(w));

  if (hit) return { kind: 'sensitive-read', label: t('touches {path}', { path: clean(hit, 120) }) };

  if (OPAQUE.test(command)) return { kind: 'opaque-command', label: t('runs encoded or evaluated code that cannot be checked') };

  return null;
}

export const isDestructive = (command = '') => DESTRUCTIVE.test(command);

// ---------- tamper protection ----------

// Separators and case unified, and Windows' \\?\ and \\.\ prefixes removed (they name the same file).
const norm = (p) => String(p ?? '').replace(/\\/g, '/').replace(/^\/\/[?.]\//, '').replace(/^\/\?\?\//, '').replace(/\/+$/, '').toLowerCase();

// What a path is to guard: its own files, Claude Code's plugin/config state, or nothing.
export function protectedTarget(file, { home = '', guardDir = '', claudeDir = '' } = {}) {
  let f = norm(file);

  if (!f) return null;
  const g = norm(guardDir);

  if ((g && (f === g || f.startsWith(`${g}/`))) || /(^|\/)\.blackbrake(\/|$)/.test(f)) return 'guard';

  // A custom Claude Code folder (CLAUDE_CONFIG_DIR) is checked as if it were ~/.claude.
  const c = norm(claudeDir);

  if (c && (f === c || f.startsWith(`${c}/`))) f = `/.claude${f.slice(c.length)}`;

  // Claude Code's plugin registry decides whether guard runs at all, whatever its path says.
  if (/(^|\/)\.claude\/plugins\/(installed_plugins|known_marketplaces|config)\.json$/.test(f) || /(^|\/)\.claude\/plugins\/marketplaces\/blackbrake(\/|$)/.test(f)) return 'guard';

  if (/\/\.claude\/plugins\//.test(f) && f.includes('blackbrake')) return 'guard';

  // The login item that starts blackbrake's background watcher.
  if (/(^|\/)(blackbrake-watch\.(vbs|desktop)|dev\.blackbrake\.watch\.plist)$/.test(f)) return 'guard';

  if (/(^|\/)\.claude\.json$/.test(f) || (home && f === `${norm(home)}/.claude.json`)) return 'claude-config';

  if (/(^|\/)\.claude\/settings(\.local)?\.json$/.test(f) || /(^|\/)managed-settings\.json$/.test(f)) return 'settings';

  // Where the other agents keep the hooks that run guard (user level: never the agent's to edit).
  if (home && f.startsWith(`${norm(home)}/`) && AGENT_HOOK_FILES.test(f)) return 'agent-config';

  // The same files inside a project can add hooks; only switching hooks off is refused there.
  if (AGENT_HOOK_FILES.test(f)) return 'settings';

  return null;
}

// Anchored on a separator or the start: Codex patches name files relative to the project.
const AGENT_HOOK_FILES = /(^|\/)(\.codex\/(hooks\.json|config\.toml)|\.gemini\/(settings\.json|config\/hooks\.json)|\.cursor\/hooks\.json|\.copilot\/(hooks\/[^/]+\.json|settings\.json|config\.json)|\.github\/(hooks\/[^/]+\.json|copilot\/settings(\.local)?\.json)|\.codeium\/(windsurf\/)?hooks\.json|\.(windsurf|devin)\/hooks\.json|\.devin\/(hooks\.v1\.json|config(\.local)?\.json)|(roaming|\.config)\/devin\/config\.json)$/;

// Includes blackbrake's own environment variables: agents pass a settings file's "env" to hooks, so
// BLACKBRAKE_HOME there would point guard at a folder the repository controls.
const DISABLES = /disableAllHooks|"?blackbrake@[\w-]+"?\s*[:=]\s*false|"?(enableHooks|hooks)"?\s*[:=]\s*false|allow_managed_hooks_only|BLACKBRAKE_\w+/i;

// In an agent's hook file: switching its hooks off or emptying them (Gemini: hooks.enabled).
const HOOKS_OFF = /"?hooks"?\s*[:=]\s*\{\s*\}|"?hooks"?\s*[:=]\s*\{[^}]{0,200}?"?enabled"?\s*[:=]\s*false/i;

// guard's folder named in a command: reading it (ls, cat state.json) is fine; writing, deleting or
// running code against it is not. Includes globs that can expand to it (~/.b*, ~/.?lackbrake, ~/.*).
const GUARD_IN_SHELL = /\.blackbrake\b|blackbrake-watch\.(vbs|desktop)|dev\.blackbrake\.watch|\.b(l(a(c(k[a-z]*)?)?)?)?[*?[]|\.[?*[][a-z*?[\]]*ackbrake|(~|\$HOME|\$env:USERPROFILE|%USERPROFILE%)[\\/]+\.?[*?[]|\{[^}]*\.b(l(a(c(k[a-z]*)?)?)?)?[,}*?]/i;


// Commands that only read. Each part of a command line (split on pipes, ;, &&, ||, &, newlines)
// must start with one of these, with no redirection, no command substitution and none of the
// writing flags some of them have (find -delete/-exec, sort -o, tee is not listed).
// Not listed on purpose: uniq and sort (take an output file), less and more (run commands with !).
const READ_ONLY_VERBS = new Set(['ls', 'dir', 'cat', 'type', 'head', 'tail', 'stat', 'file', 'wc', 'du', 'tree', 'pwd', 'echo', 'printf', 'test', 'find', 'grep', 'egrep', 'fgrep', 'rg', 'findstr', 'select-string', 'sls', 'get-content', 'gc', 'get-childitem', 'gci', 'get-item', 'gi', 'get-itemproperty', 'gp', 'get-filehash', 'test-path', 'resolve-path', 'measure-object', 'measure', 'jq', 'sha256sum', 'shasum', 'md5sum', 'where', 'which', 'cd', 'sl', 'set-location', 'pushd', 'popd', 'blackbrake', 'npx', 'node']);

const BLACKBRAKE_READ = /^(?:node(?:\.exe)?\s+(?:"[^"]*[\\/]blackbrake\.mjs"|\S*[\\/]blackbrake\.mjs)|npx\s+(?:-y\s+)?blackbrake|blackbrake(?:\.cmd|\.ps1|\.exe)?)\s+(?:status|log|agents|scan|audit|help|--version|--help|-v|-h)(?:\s+--?[\w-]+(?:\s+[\w.,-]+)?)*$/i;

export function readOnlyCommand(command) {
  // Checked as the shell will see it: quotes and escaping backslashes (-d""elete, -d\elete) join
  // back into one word. Redirections that write nowhere (2>&1, 2>/dev/null, 2>nul) are not writes.
  const cmd = unquote(command).replace(/\d?>&\d/g, ' ').replace(/\d?>\s*(\/dev\/null|nul)\b/gi, ' ');
  // For the flags, backslash escapes inside a word are dropped too (-d\elete); not for the verbs,
  // where a backslash is a Windows path separator.
  const flags = cmd.replace(/(^|\s)(-+[\w\\]*)/g, (_, s, w) => s + w.replace(/\\/g, ''));

  // Output flags in every spelling: -o FILE, -oFILE, -o=FILE, --output. Flags that make a reader run
  // a program (rg --pre, rg -z with its decompressors) count as writes too.
  if (/(?<![\d&<>-])>{1,2}(?![&>])|\d>|`|\$\(|<\(|(^|\s)-(delete|exec|execdir|ok|okdir|fprint0?|fprintf|fls)\b|(^|\s)-o\S*|(^|\s)-\w*o(\s|=|$)|--output|--pre\b|--pre-glob|--search-zip|(^|\s)-z\b/i.test(flags)) return false;

  for (const part of cmd.split(/\|\||&&|[|;&\n]/)) {
    const words = part.trim().replace(/^[@&.]\s*/, '').split(/\s+/);
    let verb = (words[0] ?? '').replace(/^["']|["']$/g, '').toLowerCase().replace(/\.(exe|cmd|bat|ps1)$/, '');
    verb = verb.split(/[\\/]/).pop();

    if (!verb) continue;

    if (!READ_ONLY_VERBS.has(verb)) return false;

    // blackbrake (directly, through npx, or node + its script) only for its read-only commands,
    // and nothing else on that part: `node -e "…" status` is not a blackbrake call.
    if (['blackbrake', 'npx', 'node'].includes(verb) && !BLACKBRAKE_READ.test(part.trim())) return false;
  }

  return true;
}

// Lowering protection needs a person typing in a terminal. An agent has no terminal, but it can make
// one (script, expect, unbuffer, winpty, socat, a pty module, tmux/screen send-keys) and feed the
// confirmation word, or hide the program name behind a variable. So: a pseudo-terminal wrapper or a
// variable/expansion on the same line as a lowering word (mode observe, uninstall, background off,
// window off, permissions) is refused. Not airtight against arbitrary code (the README says so).
const PTY_WRAPPER = /\b(script|expect|unbuffer|winpty|socat|scriptreplay|conpty|ptyprocess|node-pty|pty\.spawn|pexpect)\b|\b(tmux|screen)\b[^\n]*(send-keys|-X\s+stuff)/i;

const LOWERING = /\b(mode\s+observe|observar|uninstall|background\s+off|window\s+off|permissions|--purge)\b/i;

const EXPANSION = /\$\{?\w+\}?|%\w+%|\$env:\w+|\$\(|`|\beval\b|\biex\b|Invoke-Expression|&\s*\(/i;

// Quotes and carets break words apart without changing what runs ('mo''de', "observe", o^bserve).
export const unquote = (cmd) => String(cmd).replace(/["'^]/g, '');

// blackbrake named anywhere, plus an expansion and a lowering word anywhere (not only adjacent):
// `blackbrake $(echo mode) observe`.
const LOWERING_WORD = /\b(observe|observar|uninstall|purge|permissions)\b|\bbackground\b[^\n]*\boff\b|\bwindow\b[^\n]*\boff\b/i;

export const lowersThroughWrapper = (raw) => {
  const cmd = unquote(raw);

  if (LOWERING.test(cmd) && PTY_WRAPPER.test(cmd)) return true;

  // Package managers uninstall packages all the time (npm uninstall $pkg): not blackbrake.
  if (EXPANSION.test(raw) && LOWERING.test(cmd) && !/\b(npm|pnpm|yarn|bun|pip3?|pipx|uv|brew|apt(-get)?|winget|choco|scoop|cargo|gem|go|dotnet|conda)\s+(uninstall|remove)\b/i.test(cmd)) return true;

  return /\bblackbrake\b/i.test(cmd) && EXPANSION.test(raw) && LOWERING_WORD.test(cmd);
};

const SHELL_TAMPER = /\bblackbrake(\.mjs|\.cmd|\.ps1|\.exe)?["']?\s+(mode|uninstall|setup|background|window|permissions|lang|fix)\b|\bwatch-main\.mjs|\b(node|bun|deno)(\.exe)?\b[^\n]*guard[\\/](cli|state|hook|policy|install)\.mjs|\bimport\(?[^\n]*guard[\\/](state|install)\.mjs|\bBLACKBRAKE_HOME\b|disableAllHooks|\bclaude(\.cmd|\.exe)?["']?\s+plugins?\s+(disable|uninstall|remove|rm)\b|\bplugins?\s+marketplace\s+(remove|rm)\b[^\n]*blackbrake/i;


const CLAUDE_CONFIG_IN_SHELL = /\.claude\.json\b|\.claude[\\/]+settings(\.local)?\.json\b|managed-settings\.json\b|\.codex[\\/]+(hooks\.json|config\.toml)|\.gemini[\\/]+(settings\.json|config[\\/]+hooks\.json)|\.cursor[\\/]+hooks\.json|\.copilot[\\/]+(hooks|settings\.json|config\.json)|\.github[\\/]+(hooks|copilot)[\\/]|\.codeium[\\/]+(windsurf[\\/]+)?hooks\.json|\.(windsurf|devin)[\\/]+hooks\.json|\.devin[\\/]+(hooks\.v1\.json|config(\.local)?\.json)|[\\/]devin[\\/]+config\.json/i;

// Returns a reason string when the call would weaken guard, else null.
export function tamper(tool, input = {}, ctx = {}) {
  const name = tool ?? '';

  if (name === 'Bash' || name === 'PowerShell') {
    const cmd = String(input.command ?? '');

    // Naming blackbrake's files or an agent's hook config is fine only for commands known to just
    // read (an allow-list: a list of writing verbs can never be complete).
    const plain = unquote(cmd);

    if (SHELL_TAMPER.test(cmd) || SHELL_TAMPER.test(plain) || lowersThroughWrapper(cmd) || ((GUARD_IN_SHELL.test(cmd) || GUARD_IN_SHELL.test(plain)) && !readOnlyCommand(cmd))) return t('it would change or switch off blackbrake');

    if ((CLAUDE_CONFIG_IN_SHELL.test(cmd) || CLAUDE_CONFIG_IN_SHELL.test(plain)) && !readOnlyCommand(cmd)) return t('it changes a coding agent\'s configuration through the shell, where the change cannot be checked; use the Edit tool instead');

    return null;
  }

  if (/^(Write|Edit|MultiEdit|NotebookEdit)$/.test(name)) {
    // One call can touch several files (a Codex patch): the most protected one decides.
    const targets = [input.file_path ?? input.notebook_path ?? '', ...(input.files ?? [])].map((f) => protectedTarget(f, ctx));

    if (targets.includes('guard')) return t('it writes to blackbrake\'s own files');

    if (targets.includes('claude-config')) return t('it rewrites ~/.claude.json, which controls enabled plugins');

    if (targets.includes('agent-config')) return t('it edits the hook configuration of a coding agent, which is what runs blackbrake');

    if (targets.includes('settings')) {
      const added = [input.content, input.new_string, ...(input.edits ?? []).map((e) => e?.new_string)].filter(Boolean).join('\n');
      // A full overwrite removes what the file held before (the hook passes it as old_content).
      const removed = [input.old_string, input.old_content, ...(input.edits ?? []).map((e) => e?.old_string)].filter(Boolean).join('\n');

      if (DISABLES.test(added)) return t('it would disable hooks or the blackbrake plugin');

      // The exact key must survive: renaming it to "blackbrake@blackbrake-off" disables it too.
      if (/"blackbrake@blackbrake"/i.test(removed) && !/"blackbrake@blackbrake"\s*:\s*true/i.test(added)) return t('it removes or renames the blackbrake plugin in the settings');

      // In another agent's hook file: guard's own entry must survive, and hooks must stay on.
      if ([input.file_path, ...(input.files ?? [])].some((f) => AGENT_HOOK_FILES.test(norm(f)))) {
        // Each guard entry removed must come back with exactly the same script path: pointing it at
        // another guard/hook.mjs (a copy the agent wrote) is a redirect, not an edit.
        // Counted, not just present: removing four of five identical entries leaves guard on one
        // event only.
        const entries = (text) => [...String(text).matchAll(new RegExp(GUARD_ENTRY.source, 'gi'))].map((m) => m[0].toLowerCase().replace(/\\\\/g, '\\').replace(/\\/g, '/'));
        const count = (list) => list.reduce((m, e) => m.set(e, (m.get(e) ?? 0) + 1), new Map());
        const kept = count(entries(added));
        const lost = [...count(entries(removed))].some(([e, n]) => (kept.get(e) ?? 0) < n);

        if (HOOKS_OFF.test(added) || lost) return t('it would disable hooks or the blackbrake plugin');
      }

      // A full overwrite whose previous content could not be read (too large, unreadable): what it
      // removes cannot be checked, so it is refused.
      if (input.old_content_unverified) return t('it rewrites a settings or hook file whose current content cannot be checked; edit it instead of rewriting it');
    }

    return null;
  }

  // Read-only tools are fine; any other tool (MCP, or a name this version does not know) is refused
  // when its arguments name guard's files or an agent's configuration.
  if (!READ_ONLY_TOOLS.test(name)) {
    let text = '';

    try { text = JSON.stringify(input ?? {}); } catch { return null; }

    if (/\.blackbrake|BLACKBRAKE_HOME|disableAllHooks|\.claude[\\/]+plugins[\\/]+[^"]*blackbrake/i.test(text) || CLAUDE_CONFIG_IN_SHELL.test(text)) return t(name.startsWith('mcp__') ? 'an MCP tool would touch blackbrake or Claude Code configuration' : 'this tool would touch blackbrake or an agent\'s configuration');
  }

  return null;
}

// guard's entry in an agent's hook file: the command that runs its hook script from blackbrake's
// folder. The bare word "blackbrake" (a name, a comment) does not count as the entry surviving.
const GUARD_ENTRY = /\.blackbrake[\\/]+(app|marketplace)[\\/]+[^"'\s]*guard[\\/]+hook\.mjs|[\\/]guard[\\/]+hook\.mjs/i;

const READ_ONLY_TOOLS = /^(Read|NotebookRead|Grep|Glob|LS|WebSearch|WebFetch|TodoWrite|Task|Agent|AskUserQuestion|ExitPlanMode)$/;

// ---------- decisions ----------

const offHint = () => t('Protect mode stops this before it happens: run "blackbrake mode protect" in your terminal.');

const where = (secrets) => secrets.map((s) => `${s.ruleId} ${s.shape}`).join(', ');

// Replace every secret value in every string of a value (object, array or string), keeping its shape.
export function redact(value, secrets) {
  if (typeof value === 'string') {
    let out = value;

    for (const s of secrets) out = out.split(s.secret).join(s.shape);

    return out;
  }

  if (Array.isArray(value)) return value.map((v) => redact(v, secrets));

  if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, redact(v, secrets)]));

  return value;
}

// All the text inside a value, joined by newlines (keys and non-text values skipped).
const MAX_TEXT = 4 * 1024 * 1024;

export function textOf(v, out = [], depth = 0) {
  if (typeof v === 'string') {
    if (v) out.push(v);
  } else if (v && typeof v === 'object' && depth < 20) {
    for (const x of Array.isArray(v) ? v : Object.values(v)) textOf(x, out, depth + 1);
  }

  return depth ? out : out.join('\n').slice(0, MAX_TEXT);
}

const deny = (reason) => ({ hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: 'deny', permissionDecisionReason: reason } });

// Returns { output, log }. `output` is the JSON Claude Code reads from stdout (or null for no
// opinion); `log` lists what happened, as counts and types only.
// `ctx.rules` may be a getter, so hooks that never look for secrets never load the rule set.
export function decide(event, input, ctx = {}) {
  const { mode = 'observe', compactedAt = null, now = Date.now() } = ctx;
  const protect = mode === 'protect';
  const realSecrets = (text, filePath) => (text ? findSecrets(ctx.rules, text, filePath) : []);
  const tool = input.tool_name ? clean(input.tool_name, 80) : null;
  const log = [];

  const note = (kind, action, extra = {}) => {
    const entry = { ev: event, kind, action, ...extra };

    if (tool) entry.tool = tool;
    log.push(entry);
  };

  if (event === 'SessionStart') {
    note('session', 'start');

    return {
      log,
      output: { systemMessage: protect ? t('blackbrake guard · PROTECT: secrets in your messages and in tool output are stopped before they are sent.') : `${t('blackbrake guard · OBSERVE: warns about secrets and risky reads.')} ${offHint()}` },
    };
  }

  if (event === 'UserPromptSubmit') {
    const found = realSecrets(input.prompt ?? '');

    if (!found.length) return { log, output: null };

    for (const s of found) note('secret-in-prompt', protect ? 'blocked' : 'warned', { rule: s.ruleId });

    if (protect) {
      return {
        log,
        output: {
          decision: 'block',
          reason: t('blackbrake stopped this message: it contains what looks like {what}. Put the value in an environment variable and tell the agent its name instead. (Protect mode; "blackbrake mode observe" in your terminal turns it off.)', { what: where(found) }),
          suppressOriginalPrompt: true,
        },
      };
    }

    return { log, output: { systemMessage: `${t('blackbrake: your message contained what looks like {what}. It has been sent to the model provider; rotate it.', { what: where(found) })} ${offHint()}` } };
  }

  if (event === 'PreToolUse') {
    const ti = input.tool_input ?? {};
    const why = tamper(input.tool_name, ti, ctx);

    if (why) {
      note('tamper', 'denied');

      return { log, output: deny(t('Blocked by blackbrake: {why}. Only the user can change blackbrake, from their own terminal.', { why })) };
    }

    const findings = [];
    const file = ti.file_path ?? ti.notebook_path ?? ti.path ?? null;
    const shown = clean(file, 160);

    const sensitive = [file, ...(ti.files ?? [])].find((f) => isSensitivePath(f));

    if (/^(Read|NotebookRead|Grep|Glob)$/.test(tool ?? '') && sensitive) findings.push({ kind: 'sensitive-read', why: t('the agent wants to read {path}; its contents would be sent to the model provider', { path: clean(sensitive, 160) }) });

    if (tool === 'Bash' || tool === 'PowerShell') {
      const cmd = String(ti.command ?? '');
      const risk = bashRisk(cmd);

      if (risk) findings.push({ kind: risk.kind, why: t('this command {what}', { what: risk.label }) });
      // A credential written into the command itself (curl -H "Authorization: Bearer …", a token in
      // a clone URL): it is sent to the provider now, and wherever the command sends it.
      const inCommand = realSecrets(cmd);

      if (inCommand.length) findings.push({ kind: 'secret-in-command', why: t('the command contains {what}', { what: where(inCommand) }) });

      if (compactedAt && now - Date.parse(compactedAt) < COMPACTION_TTL_MS && isDestructive(cmd)) findings.push({ kind: 'destructive-after-compaction', why: t('a destructive command right after the conversation was compacted, when the agent may have lost the details that made it safe') });
    }

    if (/^(Write|Edit|MultiEdit|NotebookEdit)$/.test(tool ?? '')) {
      const text = [ti.content, ti.new_string, ti.new_source, ...(ti.edits ?? []).map((e) => e?.new_string)].filter(Boolean).join('\n');
      const found = realSecrets(text, file);

      if (found.length) findings.push({ kind: 'secret-in-write', why: t('the agent is writing {what} into {path}', { what: where(found), path: shown }) });
    }

    // Requests that leave the machine: a secret in a URL or query is exfiltration.
    if (/^(WebFetch|WebSearch)$/.test(tool ?? '') || (tool ?? '').startsWith('mcp__')) {
      const found = realSecrets(textOf(ti));

      if (found.length) findings.push({ kind: 'secret-in-request', why: t('the agent is sending {what} in a {tool} request', { what: where(found), tool }) });
    }

    if (!findings.length) return { log, output: null };

    for (const f of findings) note(f.kind, protect ? 'asked' : 'warned');
    const reason = findings.map((f) => f.why).join('; ');

    if (protect) return { log, output: { hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: 'ask', permissionDecisionReason: `blackbrake: ${reason}.` } } };

    return { log, output: { systemMessage: `blackbrake: ${reason}. ${offHint()}` } };
  }

  if (event === 'PostToolUse') {
    const response = input.tool_response;
    const found = realSecrets(textOf(response));

    if (!found.length) return { log, output: null };

    // Protect: hide the values from the model in whatever shape the tool returned. If a value
    // somehow survives (split across fields), fall back to warning.
    // A value found only once decoded (base64, percent-encoding, invisible characters) is not in the
    // text literally, so it cannot be replaced: that case is warned about, never reported as hidden.
    const raw = textOf(response);
    const hidden = protect && found.every((s) => raw.includes(s.secret)) ? redact(response, found) : null;
    const safe = hidden !== null && !found.some((s) => textOf(hidden).includes(s.secret));

    for (const s of found) note('secret-in-output', safe ? 'redacted' : 'warned', { rule: s.ruleId });

    if (safe) {
      return {
        log,
        output: {
          systemMessage: t('blackbrake hid {what} from a {tool} result before the model saw it.', { what: where(found), tool: tool ?? 'tool' }),
          hookSpecificOutput: { hookEventName: 'PostToolUse', updatedToolOutput: hidden },
        },
      };
    }

    return {
      log,
      output: {
        systemMessage: `${t('blackbrake: a {tool} result contained what looks like {what}. It is now in the conversation; rotate it.', { tool: tool ?? 'tool', what: where(found) })}${protect ? '' : ` ${offHint()}`}`,
        hookSpecificOutput: { hookEventName: 'PostToolUse', additionalContext: 'The previous tool result contained a credential. Do not repeat it, store it in files, or use it unless the user explicitly asks.' },
      },
    };
  }

  if (event === 'PostCompact') {
    note('compaction', 'noted');

    return { log, output: null };
  }

  if (event === 'SessionEnd') {
    note('session', 'end');

    return { log, output: null };
  }

  return { log, output: null };
}
