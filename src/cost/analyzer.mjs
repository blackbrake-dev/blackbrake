// Where the spend concentrates. Descriptive only: no savings estimates, no causal claims.
//
// Episode = one prompt written by the user plus all agent work until the next one. Subagent
// work is attributed to the episode that was open in the parent session when it started.
// Harness-injected messages (subagent hand-backs, skill bodies) do not open episodes.
import { isHarnessText } from '../transcripts.mjs';
import { priceFor, usageCost } from './prices.mjs';

const userPromptText = (msg) => {
  if (msg?.role !== 'user') return null;
  const blocks = Array.isArray(msg.content) ? msg.content : [{ type: 'text', text: msg.content }];
  if (blocks.some((b) => b?.type === 'tool_result')) return null;
  const text = blocks.filter((b) => b?.type === 'text' && typeof b.text === 'string').map((b) => b.text).join('\n').trim();
  return text && !isHarnessText(text) ? text : null;
};

export function createCostAnalyzer() {
  const sessions = new Map(); // session -> { project, episodes: [], turns, minInput, crSum, cost }
  const subagentRuns = [];    // { session, startTs, cost, turns, tools }
  const unknownModels = new Set();
  let file = null;
  let current = null;         // current file accumulator
  let episode = null;

  const session = (id, project) => {
    if (!sessions.has(id)) sessions.set(id, { id, project, episodes: [], turns: 0, minInput: Infinity, crSum: 0, cost: 0 });
    return sessions.get(id);
  };

  return {
    onFile(info) {
      file = info;
      episode = null;
      current = info.isSubagent ? { session: info.session, startTs: null, cost: 0, turns: 0, tools: 0 } : null;
      if (current) subagentRuns.push(current);
      else session(info.session, info.project);
    },
    onRecord(record) {
      const msg = record.message;
      if (!msg) return;
      const ts = record.timestamp ? Date.parse(record.timestamp) : null;
      if (current) {
        if (current.startTs === null && ts) current.startTs = ts;
        if (msg.role === 'assistant' && msg.usage) {
          current.cost += usageCost(msg.usage, msg.model);
          current.turns++;
          current.tools += (Array.isArray(msg.content) ? msg.content : []).filter((b) => b?.type === 'tool_use').length;
        }
        return;
      }
      const s = session(file.session, file.project);
      const prompt = userPromptText(msg);
      if (prompt) {
        episode = { session: s.id, project: s.project, start: ts, end: ts, cost: 0, turns: 0, tools: 0, subagents: 0 };
        s.episodes.push(episode);
        return;
      }
      if (msg.role !== 'assistant' || !msg.usage) return;
      const u = msg.usage;
      const p = priceFor(msg.model);
      // "<synthetic>" marks messages generated locally by the harness; they carry no cost.
      if (!p.known && msg.model && !msg.model.startsWith('<')) unknownModels.add(msg.model);
      const c = usageCost(u, msg.model);
      const input = (u.input_tokens || 0) + (u.cache_read_input_tokens || 0) + (u.cache_creation_input_tokens || 0);
      s.turns++;
      s.cost += c;
      s.crSum += p.cr;
      if (input > 0 && input < s.minInput) s.minInput = input;
      if (!episode) { episode = { session: s.id, project: s.project, start: ts, end: ts, cost: 0, turns: 0, tools: 0, subagents: 0 }; s.episodes.push(episode); }
      episode.cost += c;
      episode.turns++;
      episode.end = ts ?? episode.end;
      episode.tools += (Array.isArray(msg.content) ? msg.content : []).filter((b) => b?.type === 'tool_use').length;
    },
    finish() {
      // Attribute each subagent run to the parent episode open when it started.
      let unattributed = 0;
      for (const run of subagentRuns) {
        const eps = sessions.get(run.session)?.episodes ?? [];
        const target = [...eps].reverse().find((e) => e.start !== null && run.startTs !== null && e.start <= run.startTs);
        if (target) { target.cost += run.cost; target.tools += run.tools; target.subagents++; } else unattributed += run.cost;
      }
      const episodes = [...sessions.values()].flatMap((s) => s.episodes).filter((e) => e.turns > 0 || e.cost > 0);
      const costs = episodes.map((e) => e.cost).sort((a, b) => a - b);
      const total = costs.reduce((a, b) => a + b, 0) + unattributed;
      const q = (p) => (costs.length ? costs[Math.min(costs.length - 1, Math.floor(p * costs.length))] : 0);
      const topN = Math.max(1, Math.round(episodes.length * 0.1));
      const topShare = total ? costs.slice(-topN).reduce((a, b) => a + b, 0) / total : 0;
      const floors = [...sessions.values()].filter((s) => s.turns >= 3 && Number.isFinite(s.minInput));
      const floorCost = floors.reduce((a, s) => a + (s.minInput * s.crSum) / 1e6, 0);
      const mainCost = floors.reduce((a, s) => a + s.cost, 0);
      const sortedFloors = floors.map((s) => s.minInput).sort((a, b) => a - b);
      return {
        total,
        episodes: episodes.length,
        p50: q(0.5),
        p90: q(0.9),
        topShare,
        topN,
        worst: [...episodes].sort((a, b) => b.cost - a.cost).slice(0, 3).map((e) => ({
          cost: e.cost, turns: e.turns, tools: e.tools, subagents: e.subagents, project: e.project,
          date: e.start ? new Date(e.start).toISOString().slice(0, 10) : null,
          hours: e.start && e.end ? (e.end - e.start) / 3.6e6 : null,
        })),
        floor: {
          sessions: floors.length,
          medianTokens: sortedFloors.length ? sortedFloors[Math.floor(sortedFloors.length / 2)] : 0,
          share: mainCost ? floorCost / mainCost : 0,
        },
        unknownModels: [...unknownModels],
      };
    },
  };
}
