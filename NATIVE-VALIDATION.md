# Native validation: macOS and Linux

This playbook closes the gap that CI cannot: a real desktop login, visible notifications and
terminals, and the native protocols of installed AI agents. It does not turn a hosted runner into
evidence of a human desktop session.

## Evidence levels

- **CI-native:** the code ran on a GitHub-hosted macOS/Linux machine. Suitable for filesystem,
  process-table, package and protocol checks.
- **Host-native:** a person ran it on a real logged-in desktop and recorded the result. Required for
  login startup, visible notifications/windows, terminal rendering and agent applications.
- **Not tested:** never infer a pass from static review or another operating system.

Record only versions, pass/fail/skip, timestamps and sanitized error classes. Never attach prompts,
transcripts, environment dumps, config contents or credential values.

## Safe host preparation

1. Use a disposable OS account or a host with current backups. Do not test against a production
   home directory or valuable agent history.
2. Record OS version and architecture, desktop environment, terminal, Node and npm versions, and
   the versions of the agents being tested.
3. Install the exact public package: `npm install -g blackbrake@0.2.2`, then check
   `blackbrake --version`. Verify the registry signature and provenance from an isolated npm
   project with `npm audit signatures`.
4. Run `blackbrake setup` interactively. Never lower protection or uninstall through an agent.

## macOS host-native checks

- Confirm `~/Library/LaunchAgents/dev.blackbrake.watch.plist` is a regular file owned by the user,
  is not group/other writable, and passes `plutil -lint`.
- Log out and back in. Confirm the blackbrake watcher starts without opening a shell or asking for
  credentials. `blackbrake status --json` must report the background watcher.
- With the alerts window closed, feed the installed hook a synthetic tamper request as **JSON data**
  (never execute its command). Confirm a visible macOS notification. With the window enabled,
  confirm the event appears there once and contains no prompt or secret value.
- Check the window and interactive CLI in Terminal.app and iTerm2, including `NO_COLOR=1` and
  reduced-motion/accessibility settings.
- Run the Claude Code sandbox once in its supported mode and record whether the hook is invoked and
  its decision is respected. Do not treat a protocol fixture as this check.

## Linux host-native checks

- Confirm `${XDG_CONFIG_HOME:-$HOME/.config}/autostart/blackbrake-watch.desktop` is a regular file
  owned by the user and is not group/other writable.
- Log out and back in under both an available GNOME and KDE session where possible. Confirm the
  watcher starts. Separately record a headless/SSH session as an expected limitation: XDG desktop
  autostart does not run there.
- With the alerts window closed, feed the installed hook a synthetic tamper request as JSON data.
  Confirm a visible `notify-send` notification through the current D-Bus session. Confirm the
  window opens only once.
- Check the CLI/window in GNOME Terminal and Konsole, including `NO_COLOR=1`, `TERM=dumb` and
  accessibility/reduced-motion settings.

## Native agent matrix

Run each installed agent in its normal application/CLI, not through a JSON fixture. Use only a
disposable repository and harmless files. Record four outcomes: configuration installed, startup
event observed, harmless tool allowed, and a request to alter blackbrake itself denied and respected.

| Agent | macOS | Linux | Notes |
|---|---|---|---|
| Claude Code | pending | pending | Plugin path; include macOS/Linux sandbox where supported |
| Codex | pending | pending | Native hook protocol |
| Gemini CLI | pending | pending | Native hook protocol |
| Cursor | pending | pending | Application and `cursor-agent` where available |
| GitHub Copilot CLI | pending | pending | Native hook protocol |
| Windsurf | pending | pending | Application protocol |
| Devin CLI | pending | pending | Native hook protocol |

Agents without supported hooks are watcher-only. For those, record process detection and growth of a
disposable history file; do not claim that blackbrake can block them.

## Cleanup and acceptance

Run `blackbrake uninstall` from a real terminal and confirm it removes only blackbrake's hook entries,
runtime copy and login item. A platform passes only when all required host-native rows above pass or
are explicitly marked as unavailable with the reason. CI-native success alone leaves the platform
pending.
