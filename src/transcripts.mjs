// Reads Claude Code session transcripts (~/.claude/projects/**/*.jsonl) as a stream of text
// fragments, each labelled with where it came from. Read-only: nothing here writes to disk.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import readline from 'node:readline';

export const defaultRoot = () => path.join(os.homedir(), '.claude', 'projects');

export function listTranscripts(root) {
  const out = [];
  const walk = (dir) => {
    let entries;
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
    for (const e of entries) {
      const full = path.join(dir, e.name);
      if (e.isDirectory()) walk(full);
      else if (e.isFile() && e.name.endsWith('.jsonl')) out.push(full);
    }
  };
  walk(root);
  return out;
}

// Messages that arrive with role "user" but were written by the harness, not the person.
// Counting them as the user's words was a measured error in this project's own research.
const HARNESS_TEXT = /^(Another Claude session sent a message|\[Subagent hand-back\]|Base directory for this skill:|Caveat:|<)/;
export const isHarnessText = (text) => HARNESS_TEXT.test(text.trimStart());

export function describeFile(root, file) {
  const rel = path.relative(root, file).split(path.sep);
  const isSubagent = rel.includes('subagents');
  const session = isSubagent ? rel[rel.indexOf('subagents') - 1] : path.basename(file, '.jsonl');
  return { project: rel[0], session, isSubagent };
}

// Yields { kind, tool, text, ts, lineNo } for every string in a record.
//   kind: user | harness | assistant | tool-input | tool-output | snapshot | other
export function* fragmentsOf(record, toolNames) {
  const ts = record.timestamp ?? null;
  const msg = record.message;
  if (record.type === 'file-history-snapshot') {
    for (const text of strings(record)) yield { kind: 'snapshot', tool: null, text, ts };
    return;
  }
  if (msg && typeof msg === 'object') {
    const blocks = typeof msg.content === 'string' ? [{ type: 'text', text: msg.content }] : Array.isArray(msg.content) ? msg.content : [];
    for (const b of blocks) {
      if (!b || typeof b !== 'object') continue;
      if (b.type === 'text' && typeof b.text === 'string') {
        const kind = msg.role === 'user' ? (HARNESS_TEXT.test(b.text.trimStart()) ? 'harness' : 'user') : 'assistant';
        yield { kind, tool: null, text: b.text, ts };
      } else if (b.type === 'tool_use') {
        const filePath = b.input?.file_path ?? b.input?.path ?? b.input?.notebook_path ?? null;
        if (b.id) toolNames.set(b.id, { name: b.name ?? null, filePath });
        for (const text of strings(b.input)) yield { kind: 'tool-input', tool: b.name ?? null, filePath, text, ts };
      } else if (b.type === 'tool_result') {
        const call = toolNames.get(b.tool_use_id);
        for (const text of strings(b.content)) yield { kind: 'tool-output', tool: call?.name ?? null, filePath: call?.filePath ?? null, text, ts };
      } else if (b.type === 'thinking' && typeof b.thinking === 'string') {
        yield { kind: 'assistant', tool: null, text: b.thinking, ts };
      }
    }
  }
  // Everything else in the record (e.g. toolUseResult mirrors) is still scanned, so nothing
  // rides along unseen, but it is labelled separately.
  const { message: _m, ...rest } = record;
  for (const text of strings(rest)) yield { kind: 'other', tool: null, text, ts };
}

function* strings(value) {
  if (typeof value === 'string') { if (value.length >= 8) yield value; return; }
  if (Array.isArray(value)) { for (const v of value) yield* strings(v); return; }
  if (value && typeof value === 'object') for (const v of Object.values(value)) yield* strings(v);
}

export async function* readTranscript(file) {
  const rl = readline.createInterface({ input: fs.createReadStream(file, { encoding: 'utf8' }), crlfDelay: Infinity });
  let lineNo = 0;
  for await (const line of rl) {
    lineNo++;
    if (!line) continue;
    let record;
    try { record = JSON.parse(line); } catch { continue; }
    yield { record, lineNo };
  }
}
