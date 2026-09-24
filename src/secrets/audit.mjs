// Exposure audit: which secrets are in the transcripts, how many copies each one has, where the
// copies live and how the secret first got in. Values are never kept in the report: only a hash,
// the rule id and a masked shape.
import crypto from 'node:crypto';
import { describeFile, fragmentsOf, readTranscript } from '../transcripts.mjs';
import { classifyOccurrence, classifySecret, isTestPath } from './context.mjs';
import { scanText } from './engine.mjs';

export const mask = (s) => `${s.slice(0, 4)}…(${s.length})`;
const hash = (s) => crypto.createHash('sha256').update(s).digest('hex').slice(0, 12);

const ORIGIN = {
  user: 'pasted by you',
  'tool-output:Read': 'read from a file by the agent',
  'tool-output:Bash': 'printed by a command',
  'tool-output:PowerShell': 'printed by a command',
  'tool-output': 'returned by a tool',
  'tool-input': 'written by the agent',
  assistant: 'written by the agent',
  snapshot: 'file snapshot',
  harness: 'injected by the harness',
  other: 'transcript metadata',
};
const originOf = (kind, tool) => ORIGIN[`${kind}:${tool}`] ?? ORIGIN[kind] ?? kind;

export async function auditSecrets({ root, files, rules, onFile }) {
  const secrets = new Map();
  for (const file of files) {
    const { project, session, isSubagent } = describeFile(root, file);
    const toolCalls = new Map();
    for await (const { record } of readTranscript(file)) {
      for (const frag of fragmentsOf(record, toolCalls)) {
        const found = scanText(rules, frag.text);
        if (!found.length) continue;
        const filePath = frag.filePath ?? null;
        for (const f of found) {
          const key = hash(f.secret);
          let s = secrets.get(key);
          if (!s) {
            s = { key, ruleId: f.ruleId, shape: mask(f.secret), copies: 0, where: {}, sessions: new Set(), projects: new Set(), subagentCopies: 0, first: null, classes: [], seenInTestFile: false };
            secrets.set(key, s);
          }
          s.copies++;
          const place = frag.kind === 'tool-output' || frag.kind === 'tool-input' ? `${frag.kind}${frag.tool ? `:${frag.tool}` : ''}` : frag.kind;
          s.where[place] = (s.where[place] ?? 0) + 1;
          s.sessions.add(session);
          s.projects.add(project);
          if (isSubagent) s.subagentCopies++;
          if (isTestPath(filePath)) s.seenInTestFile = true;
          // Mirror copies stored in record metadata carry no context of their own: they count as
          // copies but do not vote on whether the value is real.
          if (frag.kind !== 'other') s.classes.push(classifyOccurrence({ secret: f.secret, text: frag.text, index: f.index, filePath }));
          const ts = frag.ts ? Date.parse(frag.ts) : Number.POSITIVE_INFINITY;
          if (!s.first || ts < s.first.ts) s.first = { ts, origin: originOf(frag.kind, frag.tool) };
        }
      }
    }
    onFile?.(file);
  }
  return [...secrets.values()].map((s) => ({
    key: s.key,
    ruleId: s.ruleId,
    shape: s.shape,
    classification: classifySecret(s.classes, { seenInTestFile: s.seenInTestFile }),
    copies: s.copies,
    subagentCopies: s.subagentCopies,
    sessions: s.sessions.size,
    projects: [...s.projects],
    where: s.where,
    firstSeen: Number.isFinite(s.first.ts) ? new Date(s.first.ts).toISOString() : null,
    origin: s.first.origin,
  })).sort((a, b) => b.copies - a.copies);
}
