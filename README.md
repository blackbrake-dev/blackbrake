# blackbrake

**See what your AI coding agent has exposed. Locally, read-only, in one command.**

```
npx blackbrake audit
```

## What it does NOT do

Read this first. It is the reason you can run it.

- **No network.** blackbrake opens no connections: no telemetry, no update checks, no API calls.
  A test in this repository fails if any network module is ever imported.
- **No writes.** It only reads files. It does not modify, redact or delete your transcripts.
- **No secret values in the output.** Findings are shown as a rule name, a masked shape
  (`lin_…(48)`) and a short hash. Never the value, not even in `--json`.
- **No dependencies.** Zero runtime packages. What you install is the code in this repository.
- **No AI.** Detection is deterministic: regular expressions, entropy and context rules.

## What it does (v0)

One screen, three sections, from files Claude Code already keeps on your machine
(`~/.claude/projects/**/*.jsonl`, `~/.claude/`, `~/.claude.json`):

1. **Exposure** — secrets that ended up in your transcripts.
2. **What you load** — skills, agents, commands, plugins and MCP servers: how much of it is paid
   for on every turn, how much you ever use, and static patterns worth a look (nothing is executed).
3. **Spend** — where your agent spend concentrates: your costliest 10% of episodes, your typical
   and 90th-percentile episode, the fixed context you pay on every turn. Descriptive only: no
   "you could save X%" claims.

### Exposure

It reports **secrets that ended up in your transcripts**:

- which secrets look real, and which look like test fixtures, documented examples or local-dev values;
- how many copies of each one exist, and where (your messages, agent commands, tool output,
  subagents, file snapshots);
- how each one got in first: pasted by you, read from a file, printed by a command.

Everything in a transcript has already been sent to the model provider and sits in plain text on
your disk. A key pasted once can end up copied dozens of times.

```
EXPOSURE — secrets found in your agent transcripts
  1 secret looks real · 18 findings look like examples, tests or local-dev values

  Looks real — consider rotating these:
    linear-api-key           lin_…(48)    5 copies in 1 session
                             first pasted by you on 2026-09-18 · copies by: you 1 · agent 1 · other 3
```

### Why the classification matters

A scanner that ignores context confidently tells you to rotate keys that never existed. On the
author's own transcripts, a first version flagged 12 "real" secrets; after checking where each one
appeared, none were real (a deliberately fake token used to test a scanner, an AWS example key in a
test, `localhost` verification links). blackbrake only lists a secret under "consider rotating" when
most of its occurrences look real, and never when it was written into a test or fixture file.
It is still a heuristic: check where a finding appears before rotating anything. `--all` shows the
findings it considered not real, so you can disagree.

### What you load

```
WHAT YOU LOAD — skills, agents, plugins and MCP servers
  337 skills · 68 agents · 94 commands · 4 plugins enabled · 2 MCP servers
  353 items installed twice under the same name (counted once)
  Descriptions loaded into every turn: ~28.9k tokens (skills ~25.1k, agents ~3.9k; estimated)
  Skills used at least once: 17 of 337 (5%)
  Settings: the dangerous-mode confirmation prompt is turned off
  Patterns worth a look: 1 in executable code · 3 in documentation
```

Patterns are signals, not verdicts: security skills legitimately describe `curl | sh` in their
docs. Matches in executable files and hooks are listed first.

### Spend

```
SPEND — where your agent spend concentrates
  $960 across 136 episodes (API list prices; on a subscription this is a unit of effort, not a bill)
  Your costliest 10% of episodes account for 68% of it · typical episode $1.33 · 90th percentile $21.44
```

An *episode* is one prompt you wrote plus all the agent work until your next one. Messages the
harness injects into the conversation (subagent reports, skill bodies) do not count as prompts;
counting them splits expensive episodes into pieces and hides the concentration.

## Usage

```
blackbrake audit [--path <dir>] [--home <dir>] [--json] [--all]
```

| Option | Meaning |
|---|---|
| `--path <dir>` | Transcript folder. Default: `~/.claude/projects` |
| `--home <dir>` | Folder holding `.claude/` and `.claude.json`. Default: your home |
| `--json` | Machine-readable output. Secret values are never included |
| `--all` | Show every finding, including those classified as not real or found in documentation |

Requires Node.js 20 or later.

## Roadmap

A real-time `guard` that starts in observe-only mode (cost and damage brakes with session
context, built on [cc-safety-net](https://github.com/kenryu42/cc-safety-net) rather than
replacing it). Other agents (Codex, Cursor) after that.

## Credits

Secret detection rules come from [gitleaks](https://github.com/gitleaks/gitleaks) (MIT), converted
to run on JavaScript's regex engine. See [THIRD_PARTY_NOTICES](THIRD_PARTY_NOTICES).

## Security

Found a vulnerability? Please report it privately to **security@blackbrake.dev**. See [SECURITY.md](SECURITY.md).

## License

[Apache-2.0](LICENSE)
