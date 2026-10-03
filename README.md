# blackbrake

**See what your AI coding agent has exposed. Locally, read-only, in one command.**

```
npm install -g blackbrake
blackbrake
```

Install it once and open it from any folder by typing `blackbrake`, like `claude` or `gemini`. It
installs one package with no dependencies and no install scripts, published with npm provenance.
Current stable: **v0.3.0** (published 2026-10-03; see [release notes](RELEASE-NOTES-0.3.0.md)). To try it without installing
anything: `npx blackbrake` (or `npx blackbrake audit` for the report alone). Update with
`npm install -g blackbrake@latest`, then run `blackbrake setup` so guard's own copy (`~/.blackbrake/app`)
is refreshed too (`blackbrake status` tells you if it is out of date).

**Verify the package (optional).** `npm audit signatures` does not work with `-g`, so check it in an
empty folder:

```
mkdir bb-check && cd bb-check
npm init -y
npm install blackbrake --ignore-scripts
npm audit signatures
```

Expected: 1 package with a verified registry signature and 1 with a verified attestation. That proves
the package was built from this public repository by its release workflow; it does not prove the code
is bug-free.

**Remove it.** Run `blackbrake uninstall` first (it asks you to type `remove`; `--purge` also deletes
`~/.blackbrake` — log, settings, backups, the copies "fix" kept for undo and saved reports — and asks for
`purge`), then `npm uninstall -g blackbrake`. npm runs no uninstall scripts: removing the package alone
leaves the protection installed and the watcher running. The home screen has the same option
(**Uninstall blackbrake…**), which lists what goes, what stays and what is left for you to do, and then
checks that nothing of blackbrake is still running.

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

## What it does

**Audit screen** — three sections, from files Claude Code already keeps on your machine
(`~/.claude/projects/**/*.jsonl`, `~/.claude/`, `~/.claude.json`):

1. **Exposure** — secrets that ended up in your transcripts.
2. **What you load** — skills, agents, commands, plugins and MCP servers: how much of it is paid
   for on every turn, how much you ever use, and static patterns worth a look (nothing is executed).
3. **Spend** — where your agent spend concentrates: your costliest 10% of episodes, your typical
   and 90th-percentile episode, the fixed context you pay on every turn. Descriptive only: no
   "you could save X%" claims.

**Home screen** — audit, live alerts, protection and settings, plus:
- **Pause all of blackbrake** — a full, reversible stop. The hooks stay installed but answer without
  checking anything; the watcher and the alerts window stop and the login item is removed until you
  resume. You type `pause` to confirm, in your own terminal (not inside an AI agent). While paused, the
  menu, `blackbrake status`, `agents`, the status line and every new Claude Code, Codex, Gemini or
  Devin session say so, and `setup`, `mode`, `window on`, `background on` and `permissions` refuse
  until you run `blackbrake resume`. Resuming needs no confirmation (it raises protection) and tells
  you if any hook was removed or any of guard's code changed while it was paused.
- **Uninstall blackbrake…** — see "Remove it" above.
- **Send feedback or report a problem…** / **Report a security issue…** — see "Reports" below.

**Reports (opt-in, nothing is sent by blackbrake).** `blackbrake report [product|security]` writes a
plain-text file in `~/.blackbrake/reports` from what you type, shows it to you whole, and lets you edit
it, check it again, delete it or send it yourself. Every line is checked against a strict "safe text"
format: no links, no HTML, no file paths, no user or computer names, nothing that looks like a secret.
You can add some numbers about your setup (version, OS, which agents, counts of what guard did); every
box starts unticked and shows the exact lines it would add. To send, blackbrake shows the address and
subject; only if you press "Open my mail app" does it show the whole message and, after you say yes,
open your mail app with it. It cannot tell whether you sent it. Reports expire after 30 days.
`report list`, `show <name>`, `check <name>`, `send <name>` and `delete <name>|--all` manage them.

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
| Destructive command (higher concern after compaction, or for irreversible damage) | warns | asks |
| Visible exfiltration, credential access, remote execution, persistence or permission bypass | warns | asks |
| The agent tries to switch guard off, including writing a sabotage script | **denied** | **denied** |
| A tool call cannot be checked (invalid input, inspection limit or recoverable hook error) | **denied**: the tamper check is mandatory | **denied** |

- Switch with `blackbrake mode protect` / `blackbrake mode observe`. Lowering protection and
  uninstalling need your confirmation in an interactive terminal, which the agent does not have.
- The log (`~/.blackbrake/log`) keeps time, a hashed session id, event type and rule id. Never
  prompts, commands, file contents or secret values. `blackbrake status` and `blackbrake log` read it.
- Spend brakes warn at your per-agent local p90 after 30 episodes (list-price estimate, not savings);
  live cost is currently available for Claude Code, while repeated-call warnings cover all seven agents.
  **You choose how soon each brake warns**: `blackbrake brakes` (or Protection → Spend brakes in the
  menu) shows them and changes them — episode cost at your p50/75/90/95/99 or at a fixed amount, episode
  tokens (Codex, Devin) at a percentile, repeated calls (2–10 times within 1–30 minutes), and Codex quota
  alerts (50–100%); any brake can be switched off. Making a brake warn sooner needs nothing; making it
  warn later or never lowers protection, so you type `loosen` in your own terminal. Values out of range
  or a damaged settings file fall back to the defaults.
- Recoverable errors refuse tool calls in both modes, and refuse prompts in protect where the
  agent supports it. Output that cannot be inspected is withheld where replacement is supported.
  A failure to write the log never cancels a denial. The hook times out incomplete stdin after five
  seconds; an agent killing the process earlier is a separate limit, described below.
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
  - Secret detection is heuristic: vendor patterns, entropy and value-based example filters are
    not a proof that a value is safe. Guard does not trust surrounding words such as "example" or
    source-context allowlists. Test-mode service credentials are still credentials. Audit keeps its
    separate retrospective context classifier.
  - Common invisible characters, percent/base64/hex encoding, literal concatenation and escapes
    are inspected. A recognised encoded secret that cannot be individually replaced causes the
    whole output to be withheld, where supported. Arbitrary transformations, encryption, fragments
    sent in separate calls and data read internally by an unknown tool can still escape detection.
  - Limits are explicit, not silent prefix scans: 32 MiB of raw hook input, approximately four
    million text characters, 64 nesting levels, 100,000 inspected nodes, 64 Ki characters per shell
    command and 128 candidate paths for filesystem resolution. Shell globs (`settings.jso[n]`,
    `.env*`) are matched against the disk with up to 256 folder reads and 200,000 names per
    command. Uncheckable tool calls are refused in **both** modes, so a command past these limits
    (for example a glob over hundreds of folders) is refused, not partly checked; split it into
    smaller steps. Protect blocks prompts and withholds output where the agent supports it.
    Decoding remains bounded (two percent-decoding passes, 64 encoded runs, 2 MiB decoded budget).
  - Shell analysis folds common literal concatenation, brace expansion and parameter replacement;
    it is not a shell interpreter. Previously defined aliases/functions, custom binaries, scripts
    run by filename, computed paths, runtime loaders,
    mounted-drive aliases and state across commands are not fully observable. A Git remote added
    in one step followed by a push, or `npm publish` of already-staged material, is not classified
    as exfiltration without visible sensitive material. Ordinary Git and package workflows stay usable.
  - A hook that never starts, fails during module loading, runs out of memory, or is killed or
    externally timed out cannot return a denial. The host agent decides what happens then; do not
    assume fail-closed behaviour across agent versions. Protocol tests do not replace native agent
    integration tests. Use OS isolation and independent network/credential controls for that boundary.
  - On Linux the background watcher starts at login through the desktop's autostart folder; a
    machine without a graphical session (a server, an SSH login) never runs it on its own.
    Guard protects the platform's login item and its containing folders from common move, delete
    and permission changes, but that cannot make a graphical login service exist on a server.
  - Local path checks cover common spellings, relocated configuration and existing local links,
    but are not an atomic filesystem sandbox. A same-user process can race a check, change a link
    after approval, or create another hard link. Remote links are not intentionally resolved.
  - Codex runs new hooks only after you trust them once in its `/hooks` screen. That is Codex's
    own safeguard; blackbrake does not bypass it.
  - Tools without hooks (Ollama, Hermes…) are watched from outside: blackbrake warns about secrets
    written to their history, it cannot stop them.
  - An agent can end processes by name (`taskkill /IM node.exe`): that stops the background
    watcher until the next login, and cannot be refused without breaking ordinary development work.
    The hooks inside each agent keep running.
  - Logs and watcher PID files are not authenticated against their owner. Malformed records, long
    lines and deleted logs are handled, and writes through planted parent links are refused, but
    valid-looking forged records, forged liveness, flooding and disabled notifications remain
    possible for a same-user attacker. `BLACKBRAKE_NO_WINDOW` is a test override, not an OS boundary.
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
| Devin CLI | blocked | denied (cannot ask) | warned, not hidden | user-level `devin/config.json` |

"Denied (cannot ask)" means that in protect mode guard says why and you run the step yourself, or
switch to observe. Observe warns about risk; sabotage and uncheckable tool calls are still denied.
A log entry only says "redacted" where the adapter supports replacing that output. Copilot's ignored
prompt hook is logged as a warning, never as a successful block.

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
blackbrake pause | resume
blackbrake brakes [<brake> <value> | reset]      # e.g. cost.percentile 95 · loop.repeats 4 · quota off
blackbrake report [product|security] | list | show <name> | check <name> | send <name> | delete <name>|--all
blackbrake uninstall [--agent <id>] [--purge]
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

Requires Node.js 20 or later; use 22 or 24 (LTS), since Node 20 has reached its end of life.

## Status and Roadmap

**v0.3.0 (published 2026-10-03):** pause and resume, uninstall from the menu with a
process sweep that checks nothing is left running, the alerts window opening once per session (not
over SSH, not for background agents, at most once every 10 minutes), Cursor's `sessionStart`, opt-in
local reports, and spend brakes you can adjust (episode cost and token alerts against your own history
or a fixed amount, repeated tool calls, Codex quota). Fixed on the way: Cursor on Windows sends its hook input with a byte order mark, which made
v0.2.3 refuse every Cursor step as "could not check" (found in a real `cursor-agent` session; whether
the Cursor editor does the same is still to be confirmed). Before publishing: independent security
review rounds, with every high and medium finding they reported fixed, and CI on Windows, macOS and Linux × Node
20/22/24. Still to do: a hands-on check on real macOS and Linux desktops.

**[PLANNED] Wave 2:** Cost and damage brakes with session context built on
[cc-safety-net](https://github.com/kenryu42/cc-safety-net) rather than replacing it. Full guard
in observe mode for all seven agents. Other features per monetization plan and user decision.

## Credits

Secret detection rules come from [gitleaks](https://github.com/gitleaks/gitleaks) (MIT), converted
to run on JavaScript's regex engine. See [THIRD_PARTY_NOTICES](THIRD_PARTY_NOTICES). The clean-up
with backup and undo follows the design of agentscrub and maskara (reimplemented, no code copied).

## Security

Found a vulnerability? Please report it privately to **security@blackbrake.dev**. See [SECURITY.md](SECURITY.md).

## License

[Apache-2.0](LICENSE)
