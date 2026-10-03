# blackbrake 0.3.0

Pause, clean uninstall, spend brakes and opt-in reports, plus a round of guard hardening.

## What's new

- **Pause all of blackbrake** (`blackbrake pause` / `resume`, or from the menu). A full, reversible
  stop: the hooks stay installed but answer without checking or logging anything, and the background
  watcher and alerts window stop. It always says clearly that nothing is protecting you until you
  resume, and on resume it tells you if a hook was removed or guard's code changed meanwhile. Pausing
  asks you to type `pause` in your own terminal, not inside an AI agent.
- **Uninstall from the menu.** It lists what will be removed and what will be kept, asks for a typed
  word (a different one if you also delete your data), then sweeps the process table and shows what
  is actually still running, not what it tried to stop.
- **Alerts window**: opens once per session, not over SSH, not for Cursor background agents, and at
  most once every 10 minutes.
- **Cursor `sessionStart`**: the window opens when a Cursor session starts, not at the first message.
- **Spend brakes**: alerts when an episode's cost or tokens run far above your own history, when the
  agent repeats the same tool call in a loop, and when Codex quota is running low. Live cost includes
  Claude Code subagents. Costs are API-price equivalents, not your bill; Codex costs in dollars are
  not shown because the model and tier of each response cannot be attributed reliably.
- **Opt-in reports** (`blackbrake report`): a plain-text draft on your computer that you read whole,
  edit, and send yourself from your mail app if you want. blackbrake sends nothing.

## Fixed

- Cursor on Windows sends its hook input with a byte order mark; 0.2.3 refused every Cursor step as
  "could not check". Found in a real `cursor-agent` session.
- Guard hardening from independent security reviews: shell tools recognised by shape, quoted and
  aliased ways of running blackbrake itself, unknown variable expansions and indirect bindings that
  could reach guard's folder, checks that stay on while paused, safer process identification for the
  watcher, real-path checks (UNC, NTFS suffixes, 8.3 names, junctions, hard links), bounded transcript
  reads, and invalid usage records discarded before cost accounting.

## How it was checked

- 555 tests: 552 pass, 0 fail, 3 skipped (platform-specific), run in a temporary home.
- CI on Windows, macOS and Linux × Node 20, 22 and 24: 9/9 green.
- Review rounds with independent agents; every high and medium finding they reported was fixed and
  re-checked.

## Known limits

- Desktop features (login item, notifications, alerts window) are tested in CI with temporary files
  and simulated signals, not yet on real macOS and Linux desktops.
- GitHub Copilot CLI's `sessionStart` is not wired yet: there was no host to capture its payload.
- Guard remains a same-user safety layer, not a sandbox. Read the
  [known limits](README.md#guard-blackbrake-inside-claude-code) before relying on it for sensitive work.
