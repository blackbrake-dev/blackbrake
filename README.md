# blackbrake

**See what your AI coding agent has exposed. Locally, read-only, in one command.**

```
npm install -g blackbrake
blackbrake
```

Install it once and open it from any folder by typing `blackbrake`, like `claude` or `gemini`. It
installs one package with no dependencies and no install scripts, published with npm provenance
(`npm audit signatures` verifies it). To try it without installing anything: `npx blackbrake`
(or `npx blackbrake audit` for the report alone). Update with `npm install -g blackbrake@latest`,
then run `blackbrake setup` so guard's own copy (`~/.blackbrake/app`) is refreshed too
(`blackbrake status` tells you if it is out of date). To remove it: `blackbrake uninstall` first
(add `--purge` to also delete `~/.blackbrake`: log, state and backups), then `npm uninstall -g blackbrake`.

## What it does NOT do

Read this first. It is the reason you can run it.

- **No network.** blackbrake opens no connections: no telemetry, no update checks, no API calls.
  A test in this repository fails if any network module is ever imported.
- **`audit` and `scan` are read-only.** They only read files; they never modify, redact or delete
  your transcripts or any tool's history. (guard, when you set it up, writes its own folder
  `~/.blackbrake`, its entries in each agent's hook config after a backup, and one login item; see
  "Protect in real time" below.)
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

## guard: blackbrake inside Claude Code

`blackbrake setup` installs guard as a Claude Code plugin (from a local marketplace it writes to
`~/.blackbrake/marketplace`). It never edits your Claude Code settings files.

| Event | observe (default) | protect |
|---|---|---|
| Your message contains a real-looking secret | warns: it was sent, rotate it | **blocks** the message before it is sent |
| The agent reads `.env`, SSH keys, cloud credentials; runs `printenv`, `echo $TOKEN` | warns | **asks** you first |
| The agent writes a secret into a file | warns | asks |
| A command prints a secret | warns | **hides it** from the model (replaces it with its masked shape) |
| Destructive command right after a compaction | warns | asks |
| The agent tries to switch guard off (mode, uninstall, plugin disable, `disableAllHooks`) | **denied** | **denied** |

- Switch with `blackbrake mode protect` / `blackbrake mode observe`. Lowering protection and
  uninstalling need your confirmation in an interactive terminal, which the agent does not have.
- The log (`~/.blackbrake/log`) keeps time, a hashed session id, event type and rule id. Never
  prompts, commands, file contents or secret values. `blackbrake status` and `blackbrake log` read it.
- If a check fails, guard stays out of the way (Claude Code continues) and, in protect mode, tells
  you that the step was not protected.
- **What guard cannot promise.** It runs as your user, like the agent. It denies the direct and
  common indirect ways to switch it off (tools, shell commands, MCP tools, editing Claude Code's
  settings, deleting its state, which then falls back to protect), but an agent able to run
  arbitrary code can still find another way. `blackbrake status` compares the code Claude Code runs
  with this package and tells you if it was changed. guard is a seatbelt, not a sandbox: for hard
  isolation use Claude Code's sandbox.
- **Limits, stated plainly.**
  - Confirmations prove a terminal, not a person: an agent that builds a pseudo-terminal and hides
    what it runs could still answer one. guard refuses the common forms (`script`, `expect`,
    `winpty`, `tmux send-keys`, variables next to `mode observe`/`uninstall`…), not every form.
  - Secrets are found as written, with invisible characters removed, percent-encoding undone and
    base64/hex decoded. A value the agent deliberately transforms (reversed, spaced out, encrypted)
    is not recognised.
  - Tool outputs and requests are checked up to 4 MB each; hook input above 32 MB is let through
    with a warning rather than blocking the agent.
  - Codex runs new hooks only after you trust them once in its `/hooks` screen. That is Codex's
    own safeguard; blackbrake does not bypass it.
  - Tools without hooks (Ollama, Hermes…) are watched from outside: blackbrake warns about secrets
    written to their history, it cannot stop them.
  - An agent can end processes by name (`taskkill /IM node.exe`): that stops the background
    watcher until the next login, and cannot be refused without breaking ordinary development work.
    The hooks inside each agent keep running.
- **Detection rules contain example keys.** `vendor/gitleaks.rules.json` includes gitleaks'
  global allowlist, which lists a few public example keys (such as Google's documentation keys)
  so they are never reported. They are upstream data, not credentials; secret scanners may flag them.
- Writes: guard writes only under `~/.blackbrake`; installing it also makes Claude Code record the
  plugin in its own files (`claude plugin install`).
- For destructive commands in general (`rm -rf`, `git reset --hard`…), use
  [cc-safety-net](https://github.com/kenryu42/cc-safety-net); guard complements it.
- `blackbrake claude [args]` starts Claude Code with guard on; `blackbrake uninstall` removes it.

### Other coding agents

`blackbrake setup` offers guard to every agent it finds; `blackbrake setup --agent codex,cursor`
(or `--agent all`) does it without asking. For these agents guard adds its entries to the agent's
own hook config, after a backup in `~/.blackbrake/backups`, and keeps every other entry as it is;
it refuses a config that is not valid JSON or that is a symbolic link. The hooks run a copy of guard
in `~/.blackbrake/app`, which `blackbrake status` checks against this package.

Each agent allows different things, and guard does the most each one allows:

| Agent | Message with a secret | Risky read or command | Secret in tool output | Config |
|---|---|---|---|---|
| Claude Code | blocked | asks | hidden | plugin |
| Codex | blocked | denied (Codex cannot ask) | hidden | `~/.codex/hooks.json`, then trust it in `/hooks` |
| Gemini CLI | blocked (and discarded) | denied (cannot ask) | hidden | `~/.gemini/settings.json` |
| Cursor | blocked | asks for commands and MCP; reads of files holding keys are denied | warned; hidden for MCP | `~/.cursor/hooks.json` |
| GitHub Copilot CLI | not possible (Copilot ignores that hook's answer) | asks | hidden | `~/.copilot/hooks/blackbrake.json` |
| Windsurf | blocked | denied (cannot ask) | not possible | `~/.codeium/windsurf/hooks.json` |

"Denied (cannot ask)" means that in protect mode guard says why and you run the step yourself, or
switch to observe. Observe mode never blocks in any agent.

### Live alerts

`blackbrake watch` (or "Live alerts" on the home screen) shows, as it happens, every event guard
logs in any agent, graded LOW, MEDIUM, HIGH or MAXIMUM, and the agents running right now. HIGH and
MAXIMUM also ring the terminal bell and raise a system notification (Windows toast, macOS
Notification Center, `notify-send`), at most one every five seconds. It reads only guard's log, so it
shows types and rule ids, never content.

When an agent session starts, guard opens a separate terminal window running `blackbrake watch`
(once per session, never if one is already open; Windows Terminal, conhost, Terminal.app or the
first terminal found on Linux, started from system folders without a shell).
`blackbrake window off` stops that; `blackbrake agents` lists where blackbrake runs, and
`blackbrake uninstall --agent <id>` removes it from one agent (you type the confirmation).

### Every AI harness, with or without hooks

`blackbrake setup` finds every AI harness on the machine. Those with hooks (Claude Code, Codex,
Gemini CLI, Cursor, Copilot CLI, Windsurf, Devin CLI) get guard inside. The others (Ollama, Hermes,
Grok, OpenCode, Qwen, Goose, Continue, Pi, Kimi, Cline, Aider, LM Studio, Amp) are watched from
outside by a hidden background watcher that starts at login: it notices when they run, follows
their history files as they grow and warns about secrets written there. It can warn, not stop.
`blackbrake background off` removes the login item (you type the confirmation). Before running at
login, the watcher checks its installed copy against the manifest written at install time.

`blackbrake scan [--agent <id>]` reads each harness's own files (history, sessions, config) and
lists the secrets found, masked, skipping each tool's own credential store (login tokens, keys).
`blackbrake agents` shows how each one is covered; `blackbrake help` lists the main commands.

### Fixing what it finds

After an audit or a scan, **Fix what was found** (or `blackbrake fix`) lists each problem with the
ways it can be fixed:

- **⚙ Here, automatically** — no AI, no network:
  - *Remove the copies of a key*: every copy in transcripts, prompt history or an AI tool's files is
    replaced by its masked shape (`[removed by blackbrake: github-pat ghp_••••(40)]`). A tool's own
    credential store is never touched. The originals are kept in `~/.blackbrake/backups`, readable
    only by you, and deleted after 7 days; `blackbrake fix --undo` puts them back until then.
    Removing copies does not make a key safe: rotate it too.
  - *Safe settings*: the Claude Code settings a precaution names (bypass-mode warning, default
    mode, deny reading `.env` and `~/.ssh`, shorter transcript retention, project MCP approval). You
    see the change first; the previous file is backed up.
- **✦ With your AI agent** — blackbrake writes a prompt with the problems (rule types, masked shapes,
  file paths; never a secret value) and rules for the agent (ask before each change, never print a
  key, do not touch blackbrake). It is saved in `~/.blackbrake/fixes/`. blackbrake then asks
  whether to open Claude Code, Codex or Gemini CLI with it, interactively: the agent asks you before
  each change. If you say no, the file stays and its path is shown. Opening the agent sends that
  prompt to your agent's provider, like anything you type there.

Fixing needs you at a terminal (the clean-up and the undo ask you to type a word); an agent cannot
run it.

### Language

The interface is in English and Spanish, following your system; `blackbrake lang es|en|auto` fixes
it (guard's messages inside the agents follow it too), and `--lang` sets it for one run. `--json`
output is always English.

## Usage

```
blackbrake                       # home screen, in an interactive terminal
blackbrake audit [--path <dir>] [--home <dir>] [--json] [--all]
blackbrake scan [--agent <id>]
blackbrake fix [--undo]
```

Run with no command in a terminal to get the home screen (arrow keys, Enter, `q` to quit). In a
pipe or script it prints this help instead of waiting for keys. Colour follows your terminal;
set `NO_COLOR=1` to turn it off.

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
to run on JavaScript's regex engine. See [THIRD_PARTY_NOTICES](THIRD_PARTY_NOTICES). The clean-up
with backup and undo follows the design of agentscrub and maskara (reimplemented, no code copied).

## Security

Found a vulnerability? Please report it privately to **security@blackbrake.dev**. See [SECURITY.md](SECURITY.md).

## License

[Apache-2.0](LICENSE)
