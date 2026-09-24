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

It reads the session transcripts that Claude Code keeps on disk (`~/.claude/projects/**/*.jsonl`)
and reports **secrets that ended up in them**:

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

## Usage

```
blackbrake audit [--path <dir>] [--json] [--all]
```

| Option | Meaning |
|---|---|
| `--path <dir>` | Transcript folder. Default: `~/.claude/projects` |
| `--json` | Machine-readable output. Secret values are never included |
| `--all` | Also list findings classified as examples/tests or local-dev values |

Requires Node.js 20 or later.

## Roadmap

Planned, in order: risk review of installed skills/MCP servers/plugins (static, never executes
them); where your agent spend concentrates (your costliest 10% of episodes, measured against your
own baseline); a real-time `guard` that starts in observe-only mode. Other agents (Codex, Cursor)
after that.

## Credits

Secret detection rules come from [gitleaks](https://github.com/gitleaks/gitleaks) (MIT), converted
to run on JavaScript's regex engine. See [THIRD_PARTY_NOTICES](THIRD_PARTY_NOTICES).

## Security

Found a vulnerability? Please report it privately to **security@blackbrake.dev**. See [SECURITY.md](SECURITY.md).

## License

[Apache-2.0](LICENSE)
