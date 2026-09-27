// guard in other coding agents. Each adapter translates the agent's native hook event into the
// canonical one the policy understands (Claude Code's shape: UserPromptSubmit, PreToolUse with
// Bash/Read/Write/Edit/WebFetch/mcp__…, PostToolUse) and translates the decision back into what that
// agent reads. Capabilities differ, and each adapter does the strongest thing its agent allows:
// where "ask" is not supported, protect denies and says why; where output cannot be replaced, it warns.
// Formats checked against each agent's documentation on 2026-09-26 (context/nodes/oss-reuse.md §4e).
import path from 'node:path';
import { t } from '../i18n.mjs';
import { textOf } from './policy.mjs';

// ---------- canonical output helpers ----------

const decisionOf = (out) => out?.hookSpecificOutput?.permissionDecision ?? null;

const reasonOf = (out) => out?.hookSpecificOutput?.permissionDecisionReason ?? out?.reason ?? out?.systemMessage ?? '';

const hiddenOf = (out) => out?.hookSpecificOutput?.updatedToolOutput;

const blocked = (out) => out?.decision === 'block';

const noAsk = () => ` ${t('(This agent cannot ask for confirmation, so blackbrake denied it. Run it yourself if it is fine, or switch guard to observe.)')}`;

const maskedResult = (out) => `[${t('blackbrake hid credentials in this result')}]\n${textOf(hiddenOf(out))}`;

const parse = (v) => {
  if (typeof v !== 'string') return v ?? {};

  try { return JSON.parse(v); } catch { return v; }
};

const json = (o) => ({ stdout: JSON.stringify(o), code: 0 });

const none = { stdout: '', code: 0 };

// ---------- Codex (same schema as Claude Code, with differences) ----------

// apply_patch sends the whole patch in `command`; the files are in its headers (a rename names the
// destination in "Move to"). Paths are relative to the session's folder.
function patchFiles(patch = '', cwd = '') {
  return [...String(patch).matchAll(/^\*\*\* (?:(?:Add|Update|Delete) File|Move to): (.+)$/gm)].map((m) => {
    const f = m[1].trim();

    return cwd && !path.isAbsolute(f) ? path.resolve(cwd, f) : f;
  });
}

// A patch-shaped edit (Codex and Copilot apply_patch): the files come from the patch itself.
const patchInput = (raw, tool_input) => {
  const patch = String(tool_input?.command ?? tool_input?.input ?? tool_input?.patch ?? '');
  const files = patchFiles(patch, typeof raw.cwd === 'string' ? raw.cwd : '');

  return { file_path: files[0] ?? '', files, new_string: patch };
};

const codex = {
  id: 'codex',
  name: 'Codex',
  events: { SessionStart: 'SessionStart', UserPromptSubmit: 'UserPromptSubmit', PreToolUse: 'PreToolUse', PostToolUse: 'PostToolUse', PostCompact: 'PostCompact', SessionEnd: 'SessionEnd' },
  normalize(event, raw) {
    if (raw.tool_name === 'apply_patch') return { event, input: { ...raw, tool_name: 'Edit', tool_input: patchInput(raw, raw.tool_input) } };

    // Codex's shell tools (the command may be an argument list): checked as Bash.
    if (/^(shell|local_shell|unified_exec|exec_command|container\.exec)$/.test(String(raw.tool_name ?? ''))) {
      const c = raw.tool_input?.command ?? raw.tool_input?.cmd;

      return { event, input: { ...raw, tool_name: 'Bash', tool_input: { ...raw.tool_input, command: Array.isArray(c) ? c.join(' ') : String(c ?? JSON.stringify(raw.tool_input ?? {})) } } };
    }

    return { event, input: raw };
  },
  render(event, out) {
    if (!out) return none;

    if (event === 'PreToolUse') {
      const d = decisionOf(out);

      if (d === 'deny' || d === 'ask') return json({ hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: 'deny', permissionDecisionReason: `${reasonOf(out)}${d === 'ask' ? noAsk() : ''}` } });

      return json({ systemMessage: out.systemMessage });
    }

    if (event === 'PostToolUse' && hiddenOf(out) !== undefined) return json({ decision: 'block', reason: maskedResult(out), systemMessage: out.systemMessage });

    if (event === 'UserPromptSubmit' && blocked(out)) return json({ decision: 'block', reason: out.reason });

    return json(out);
  },
};

// ---------- Gemini CLI ----------

const GEMINI_TOOLS = {
  run_shell_command: (a) => ['Bash', { command: a.command }],
  read_file: (a) => ['Read', { file_path: a.file_path ?? a.absolute_path ?? a.path }],
  read_many_files: (a) => ['Read', { file_path: (a.paths ?? [])[0], files: a.paths ?? [] }],
  write_file: (a) => ['Write', { file_path: a.file_path, content: a.content }],
  replace: (a) => ['Edit', { file_path: a.file_path, old_string: a.old_string, new_string: a.new_string }],
  glob: (a) => ['Glob', { pattern: a.pattern, path: a.path }],
  search_file_content: (a) => ['Grep', { pattern: a.pattern, path: a.path }],
  web_fetch: (a) => ['WebFetch', { url: a.url, prompt: a.prompt }],
  google_web_search: (a) => ['WebSearch', { query: a.query }],
};

const geminiTool = (name = '', args = {}) => {
  const map = GEMINI_TOOLS[name];

  if (map) return map(args ?? {});

  // MCP tools are named mcp_<server>_<tool>.
  return [name.startsWith('mcp_') ? `mcp__${name.slice(4)}` : name, args ?? {}];
};

const gemini = {
  id: 'gemini',
  name: 'Gemini CLI',
  events: { SessionStart: 'SessionStart', BeforeAgent: 'UserPromptSubmit', BeforeTool: 'PreToolUse', AfterTool: 'PostToolUse', PreCompress: 'PostCompact', SessionEnd: 'SessionEnd' },
  normalize(event, raw) {
    if (event !== 'PreToolUse' && event !== 'PostToolUse') return { event, input: raw };
    const [tool_name, tool_input] = geminiTool(raw.tool_name, raw.tool_input);

    return { event, input: { ...raw, tool_name, tool_input, tool_response: raw.tool_response?.llmContent ?? raw.tool_response } };
  },
  render(event, out) {
    if (!out) return none;

    if (event === 'UserPromptSubmit' && blocked(out)) return json({ decision: 'deny', reason: out.reason, systemMessage: out.reason });

    if (event === 'PreToolUse') {
      const d = decisionOf(out);

      if (d === 'deny' || d === 'ask') {
        const reason = `${reasonOf(out)}${d === 'ask' ? noAsk() : ''}`;

        return json({ decision: 'deny', reason, systemMessage: reason });
      }
    }

    if (event === 'PostToolUse' && hiddenOf(out) !== undefined) return json({ decision: 'deny', reason: maskedResult(out), systemMessage: out.systemMessage });

    if (event === 'PostToolUse' && out.hookSpecificOutput?.additionalContext) return json({ systemMessage: out.systemMessage, hookSpecificOutput: { hookEventName: 'AfterTool', additionalContext: out.hookSpecificOutput.additionalContext } });

    return out.systemMessage ? json({ systemMessage: out.systemMessage }) : none;
  },
};

// ---------- Cursor ----------

// Permission hooks must always answer with valid JSON: silence or bad JSON blocks the action.
const ALLOW = { permission: 'allow' };

const cursor = {
  id: 'cursor',
  name: 'Cursor',
  events: {
    beforeSubmitPrompt: 'UserPromptSubmit',
    beforeShellExecution: 'PreToolUse',
    beforeReadFile: 'PreToolUse',
    beforeMCPExecution: 'PreToolUse',
    preToolUse: 'PreToolUse',
    postToolUse: 'PostToolUse',
    preCompact: 'PostCompact',
    sessionEnd: 'SessionEnd',
  },
  // Cursor's dedicated hooks cover shell, reads and MCP; preToolUse is kept for writes and edits.
  skip(native, raw) {
    return native === 'preToolUse' && /^(Shell|Terminal|Read|ReadFile|MCP)/i.test(String(raw.tool_name ?? ''));
  },
  normalize(event, raw, native) {
    const session_id = raw.conversation_id;

    if (native === 'beforeSubmitPrompt') return { event, input: { session_id, prompt: raw.prompt } };

    if (native === 'beforeShellExecution') return { event, input: { session_id, tool_name: 'Bash', tool_input: { command: raw.command } } };

    if (native === 'beforeReadFile') return { event, input: { session_id, tool_name: 'Read', tool_input: { file_path: raw.file_path }, content: raw.content } };

    if (native === 'beforeMCPExecution') return { event, input: { session_id, tool_name: `mcp__${raw.mcp_server_name ?? 'server'}__${raw.tool_name}`, tool_input: parse(raw.tool_input) } };

    if (native === 'postToolUse') return { event, input: { session_id, tool_name: raw.tool_name, tool_input: raw.tool_input, tool_response: parse(raw.tool_output) } };

    const name = String(raw.tool_name ?? '');
    const ti = parse(raw.tool_input);
    const input = ti && typeof ti === 'object' ? ti : {};
    // Deleting, moving or renaming a file is checked like writing to it.
    const file = input.file_path ?? input.target_file ?? input.path ?? input.target ?? input.destination;
    const tool_name = /^(Write|Create|Delete|Remove|Move|Rename)/i.test(name) ? 'Write' : /^(Edit|Str_?Replace|Replace|MultiEdit)/i.test(name) ? 'Edit' : /^web_?fetch$/i.test(name) ? 'WebFetch' : name;

    return { event, input: { session_id, tool_name, tool_input: tool_name === 'Write' || tool_name === 'Edit' ? { ...input, file_path: file } : input } };
  },
  render(event, out, { native, input = {} }) {
    if (native === 'beforeSubmitPrompt') return blocked(out) ? json({ continue: false, user_message: out.reason }) : json({ continue: true });

    if (event === 'PreToolUse') {
      const d = decisionOf(out);

      // Observe: the action goes ahead, with the warning attached for the user and the agent.
      if (!d) return json(out?.systemMessage ? { ...ALLOW, user_message: out.systemMessage, agent_message: out.systemMessage } : ALLOW);
      const canAsk = native === 'beforeShellExecution' || native === 'beforeMCPExecution';
      const reason = `${reasonOf(out)}${d === 'ask' && !canAsk ? noAsk() : ''}`;

      return json({ permission: d === 'ask' && canAsk ? 'ask' : 'deny', user_message: reason, agent_message: reason });
    }

    if (event === 'PostToolUse') {
      if (!out) return none;
      const hidden = hiddenOf(out);

      if (hidden !== undefined && /^(mcp__|MCP)/i.test(String(input.tool_name ?? ''))) return json({ updated_mcp_tool_output: hidden, additional_context: out.systemMessage });

      return json({ additional_context: `${out.systemMessage ?? ''} ${t('Do not repeat, store or use that credential unless the user explicitly asks.')}`.trim() });
    }

    if (event === 'PostCompact') return json({});

    // A permission hook this version does not know (a future Cursor event): silence would block it.
    return /^(before|pre)/.test(String(native ?? '')) ? json(ALLOW) : none;
  },
};

// ---------- GitHub Copilot CLI ----------

// Editor tools name their fields differently (path, file_text, old_str, new_str): the checks read
// Claude's names, so these are copied across (originals kept).
const editorFields = (ti) => {
  if (!ti || typeof ti !== 'object') return ti;

  return { ...ti, file_path: ti.file_path ?? ti.path ?? ti.filePath, content: ti.content ?? ti.file_text ?? ti.fileText, old_string: ti.old_string ?? ti.old_str ?? ti.oldText, new_string: ti.new_string ?? ti.new_str ?? ti.new_text ?? ti.insert_text ?? ti.newText };
};

const COPILOT_TOOLS = { bash: 'Bash', powershell: 'PowerShell', view: 'Read', create: 'Write', edit: 'Edit', str_replace_editor: 'Edit', apply_patch: 'Edit', grep: 'Grep', rg: 'Grep', glob: 'Glob', web_fetch: 'WebFetch', web_search: 'WebSearch' };

const copilot = {
  id: 'copilot',
  name: 'GitHub Copilot CLI',
  // PreToolUse in PascalCase gets Claude's tool names and field names; postToolUse in camelCase has
  // the documented `modifiedResult`. Prompt hooks' output is ignored by Copilot CLI: logged only.
  events: { userPromptSubmitted: 'UserPromptSubmit', PreToolUse: 'PreToolUse', postToolUse: 'PostToolUse', sessionEnd: 'SessionEnd' },
  normalize(event, raw, native) {
    const session_id = raw.session_id ?? raw.sessionId;

    if (native === 'postToolUse') {
      const name = String(raw.toolName ?? '');

      return { event, input: { session_id, tool_name: COPILOT_TOOLS[name] ?? name, tool_input: parse(raw.toolArgs), tool_response: raw.toolResult?.textResultForLlm ?? raw.toolResult } };
    }

    // Claude names are documented for PascalCase PreToolUse; runtime names are mapped too, in case.
    const name = String(raw.tool_name ?? '');
    const tool_input = parse(raw.tool_input);
    // A patch only when it is one: str_replace_editor also carries a `command` (create, str_replace…).
    const patch = name === 'apply_patch' || /^\s*\*\*\* Begin Patch/.test(String(tool_input?.command ?? tool_input?.input ?? ''));

    return { event, input: { ...raw, session_id, prompt: raw.prompt, tool_name: COPILOT_TOOLS[name] ?? name, tool_input: patch ? patchInput(raw, tool_input) : editorFields(tool_input) } };
  },
  render(event, out) {
    if (!out || event === 'UserPromptSubmit') return none;

    if (event === 'PreToolUse') {
      const d = decisionOf(out);

      return d ? json({ permissionDecision: d, permissionDecisionReason: reasonOf(out) }) : none;
    }

    if (event === 'PostToolUse') {
      const hidden = hiddenOf(out);

      if (hidden !== undefined) return json({ modifiedResult: { resultType: 'success', textResultForLlm: textOf(hidden) }, additionalContext: out.systemMessage });

      return json({ additionalContext: out.hookSpecificOutput?.additionalContext ?? out.systemMessage });
    }

    return none;
  },
};

// ---------- Windsurf (Devin Desktop Cascade) ----------

const windsurf = {
  id: 'windsurf',
  name: 'Windsurf',
  events: { pre_user_prompt: 'UserPromptSubmit', pre_read_code: 'PreToolUse', pre_write_code: 'PreToolUse', pre_run_command: 'PreToolUse', pre_mcp_tool_use: 'PreToolUse' },
  normalize(event, raw, native) {
    const info = raw.tool_info ?? {};
    const session_id = raw.trajectory_id;

    if (native === 'pre_user_prompt') return { event, input: { session_id, prompt: info.user_prompt } };

    if (native === 'pre_read_code') return { event, input: { session_id, tool_name: 'Read', tool_input: { file_path: info.file_path } } };

    if (native === 'pre_write_code') return { event, input: { session_id, tool_name: 'Edit', tool_input: { file_path: info.file_path, edits: info.edits ?? [] } } };

    if (native === 'pre_run_command') return { event, input: { session_id, tool_name: 'Bash', tool_input: { command: info.command_line } } };

    return { event, input: { session_id, tool_name: `mcp__${info.mcp_server_name ?? 'server'}__${info.mcp_tool_name}`, tool_input: info.mcp_tool_arguments ?? {} } };
  },
  // Pre-hooks block with exit code 2 and the reason on stderr; there is no "ask".
  render(event, out) {
    if (!out) return none;
    const d = decisionOf(out);

    if (blocked(out) || d === 'deny' || d === 'ask') return { stdout: '', stderr: `${blocked(out) ? out.reason : reasonOf(out)}${d === 'ask' ? noAsk() : ''}`, code: 2 };

    return { stdout: out.systemMessage ?? '', code: 0 };
  },
};

// ---------- Devin CLI ----------

const devin = {
  id: 'devin',
  name: 'Devin CLI',
  events: { SessionStart: 'SessionStart', UserPromptSubmit: 'UserPromptSubmit', PreToolUse: 'PreToolUse', PostToolUse: 'PostToolUse', PostCompaction: 'PostCompact', SessionEnd: 'SessionEnd' },
  normalize(event, raw) {
    if (event !== 'PreToolUse' && event !== 'PostToolUse') return { event, input: raw };
    const name = String(raw.tool_name ?? '');
    const ti = parse(raw.tool_input);
    const a = ti && typeof ti === 'object' ? ti : {};
    const file = a.file_path ?? a.path ?? a.notebook_path;
    let tool_name = name;
    let tool_input = a;

    // If the command is not where expected, the whole argument list is checked as the command.
    if (name === 'exec') [tool_name, tool_input] = ['Bash', { command: typeof a.command === 'string' ? a.command : JSON.stringify(a) }];
    // Text typed into a running process is a command too.
    else if (name === 'write_to_process') [tool_name, tool_input] = ['Bash', { command: String(a.text_input ?? a.bytes_input ?? '') }];
    else if (name === 'read' || name === 'notebook_read') [tool_name, tool_input] = ['Read', { ...a, file_path: file }];
    else if (name === 'write') [tool_name, tool_input] = ['Write', { ...a, file_path: file }];
    else if (name === 'edit' || name === 'notebook_edit') [tool_name, tool_input] = ['Edit', { ...a, file_path: file }];
    else if (name === 'apply_patch') [tool_name, tool_input] = ['Edit', patchInput(raw, a)];
    else if (name === 'grep' || name === 'glob') tool_name = name === 'grep' ? 'Grep' : 'Glob';
    else if (name === 'webfetch') tool_name = 'WebFetch';
    else if (name === 'mcp_call_tool') [tool_name, tool_input] = [`mcp__${a.server_name ?? 'server'}__${a.tool_name ?? 'tool'}`, a.arguments ?? {}];

    return { event, input: { ...raw, tool_name, tool_input, tool_response: raw.tool_response?.output ?? raw.tool_response } };
  },
  // Devin reads `decision: "block"` for prompts and tools; there is no "ask" and no way to replace a
  // tool's output, so protect denies and output secrets are warned about to the agent.
  render(event, out) {
    if (!out) return none;
    const d = decisionOf(out);

    if (blocked(out)) return json({ decision: 'block', reason: out.reason });

    if (d === 'deny' || d === 'ask') return json({ decision: 'block', reason: `${reasonOf(out)}${d === 'ask' ? noAsk() : ''}` });
    const text = [out.systemMessage, out.hookSpecificOutput?.additionalContext].filter(Boolean).join(' ');

    if (!text || !['UserPromptSubmit', 'SessionStart', 'PostToolUse'].includes(event)) return none;

    return json({ hookSpecificOutput: { hookEventName: event, additionalContext: event === 'PostToolUse' ? `${text} ${t('Do not repeat, store or use that credential unless the user explicitly asks.')}` : text } });
  },
};

// ---------- Claude Code (the plugin; identity) ----------

const claude = {
  id: 'claude',
  name: 'Claude Code',
  events: { SessionStart: 'SessionStart', UserPromptSubmit: 'UserPromptSubmit', PreToolUse: 'PreToolUse', PostToolUse: 'PostToolUse', PostCompact: 'PostCompact', SessionEnd: 'SessionEnd' },
  normalize: (event, raw) => ({ event, input: raw }),
  render: (event, out) => (out ? json(out) : none),
};

export const ADAPTERS = { claude, codex, gemini, cursor, copilot, windsurf, devin };

// What an adapter prints when guard itself fails: never block the agent, say it once.
export function renderError(harness, native, message) {
  const a = ADAPTERS[harness] ?? claude;

  if (a === cursor) return native === 'beforeSubmitPrompt' ? json({ continue: true }) : native.startsWith('before') || native === 'preToolUse' ? json({ ...ALLOW, user_message: message }) : none;

  if (a === windsurf) return { stdout: message, code: 0 };

  if (a === copilot) return none;

  if (a === devin) return ['UserPromptSubmit', 'SessionStart', 'PostToolUse'].includes(native) ? json({ hookSpecificOutput: { hookEventName: native, additionalContext: message } }) : none;

  return json({ systemMessage: message });
}
