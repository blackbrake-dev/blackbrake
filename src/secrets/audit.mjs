// Exposure audit: which secrets are in the transcripts, how many copies each one has, where the
// copies live and how the secret first got in. Values are never kept in the report: only a hash,
// the rule id and a masked shape.
import crypto from 'node:crypto';
import { fragmentsOf } from '../transcripts.mjs';
import { classifyOccurrence, classifySecret, isTestPath } from './context.mjs';
import { clean } from '../text.mjs';
import { scanText } from './engine.mjs';

// Only a well-known, public type prefix is shown (it names the service, reveals nothing secret);
// every other character is masked.
const PUBLIC_PREFIX = /^(?:github_pat_|gh[pousr]_|glpat-|sk-ant-(?:api\d+-|admin\d+-)?|sk-or-v1-|sk-proj-|sk_live_|pk_live_|rk_live_|sk-|gsk_|xai-|sbp_|whsec_|xox[abpr]-|AKIA|ASIA|AIza|npm_|hf_|lin_api_|lin_|SG\.)/;

export const mask = (s) => `${s.match(PUBLIC_PREFIX)?.[0] ?? ''}••••(${s.length})`;

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

// Streaming analyzer: onFile() for each transcript, onRecord() for each line, finish() at the end.
export function createSecretsAnalyzer(rules) {
  const secrets = new Map();
  // Only about a quarter of transcript text is unique (tool results are mirrored in the record and
  // repeated across lines). Each distinct text is scanned once; every copy is still counted.
  const scanned = new Map();
  let file = null;
  let toolCalls = new Map();

  const entry = (f) => {
    const key = hash(f.secret);
    let s = secrets.get(key);

    if (!s) {
      s = { key, ruleId: f.ruleId, masked: mask(f.secret), copies: 0, where: {}, sessions: new Set(), projects: new Set(), stores: new Set(), subagentCopies: 0, first: null, classes: [], seenInTestFile: false, inTranscripts: false, inConfig: false };
      secrets.set(key, s);
    }

    return s;
  };

  return {
    onFile(info) { file = info; toolCalls = new Map(); },
    // A plain file outside the transcripts (prompt history, file copies, configuration).
    onStoreFile({ store, kind, file: path, text }) {
      for (const f of scanText(rules, text)) {
        const s = entry(f);
        s.copies++;
        s.stores.add(store);
        s.where[`store:${store}`] = (s.where[`store:${store}`] ?? 0) + 1;

        if (kind === 'config') s.inConfig = true;

        if (isTestPath(path)) s.seenInTestFile = true;
        s.classes.push(classifyOccurrence({ secret: f.secret, text, index: f.index, filePath: path }));

        if (!s.first) s.first = { ts: Number.POSITIVE_INFINITY, origin: kind === 'config' ? `stored in ${store}` : `kept in ${store}` };
      }
    },
    onRecord(record) {
      for (const frag of fragmentsOf(record, toolCalls)) {
        const textKey = frag.text.length > 64 ? crypto.createHash('sha256').update(frag.text).digest('base64') : frag.text;
        let found = scanned.get(textKey);

        if (!found) {
          found = scanText(rules, frag.text);

          // Bounded memory: past this many distinct texts, start over (repeats are mostly local).
          if (scanned.size >= 250_000) scanned.clear();
          scanned.set(textKey, found);
        }

        for (const f of found) {
          const s = entry(f);
          s.copies++;
          s.inTranscripts = true;

          if (frag.kind === 'user') s.pasted = true;
          const place = frag.kind === 'tool-output' || frag.kind === 'tool-input' ? `${frag.kind}${frag.tool ? `:${clean(frag.tool, 80)}` : ''}` : frag.kind;
          s.where[place] = (s.where[place] ?? 0) + 1;
          s.sessions.add(file.session);
          s.projects.add(file.project);

          if (file.isSubagent) s.subagentCopies++;

          if (isTestPath(frag.filePath)) s.seenInTestFile = true;

          // Mirror copies stored in record metadata carry no context of their own: they count as
          // copies but do not vote on whether the value is real.
          if (frag.kind !== 'other') s.classes.push(classifyOccurrence({ secret: f.secret, text: frag.text, index: f.index, filePath: frag.filePath }));
          const ts = frag.ts ? Date.parse(frag.ts) : Number.POSITIVE_INFINITY;

          if (!s.first || ts < s.first.ts) s.first = { ts, origin: originOf(frag.kind, frag.tool) };
        }
      }
    },
    finish() {
      return [...secrets.values()].map((s) => ({
        key: s.key,
        ruleId: s.ruleId,
        // oxlint-disable-next-line anti-slop/no-shape-in-symbol-names -- "shape" is the documented key of the audit finding schema (also in --json); renaming it would change the output.
        shape: s.masked,
        classification: classifySecret(s.classes, { seenInTestFile: s.seenInTestFile, pastedByUser: s.pasted === true }),
        copies: s.copies,
        subagentCopies: s.subagentCopies,
        sessions: s.sessions.size,
        projects: [...s.projects].map((p) => clean(p, 120)),
        stores: [...s.stores],
        inTranscripts: s.inTranscripts,
        inConfig: s.inConfig,
        where: s.where,
        firstSeen: Number.isFinite(s.first.ts) ? new Date(s.first.ts).toISOString() : null,
        origin: s.first.origin,
      })).sort((a, b) => b.copies - a.copies);
    },
  };
}

// Convenience wrapper: run the secrets analyzer alone over a list of transcript files.
export async function auditSecrets({ root, files, rules }) {
  const { runAnalyzers } = await import('../run.mjs');
  const [secrets] = await runAnalyzers({ root, files, analyzers: [createSecretsAnalyzer(rules)] });

  return secrets;
}
