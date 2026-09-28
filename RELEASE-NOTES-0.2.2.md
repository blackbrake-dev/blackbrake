# blackbrake 0.2.2

This is a security-hardening release for guard.

## What changed

- Closes observe-mode sabotage paths involving escaped or split configuration names, shell globs,
  brace and parameter expansion, broad `launchctl` operations, moved or locked startup folders,
  path aliases, and linked agent folders.
- Strengthens credential-read detection for quoted, globbed, reversed, encoded and shell-expanded
  paths.
- Refuses malformed or uncheckable tool calls instead of silently inspecting only a prefix. Shell,
  decoding, nesting, node and filesystem limits are explicit and bounded.

## Compatibility and measurements

- The hook protocol and package suite pass on Windows, macOS and Linux with Node 20, 22 and 24
  (9 CI jobs). This does not mean native integration with all seven supported agents was exercised
  on every platform.
- Native Codex CLI 0.158.0 integration was exercised separately: an ordinary command ran, and
  sabotage was denied and not executed in both observe and protect modes.
- On the project Windows host, the complete hook measured about 150 ms p50. The measured hostile
  policy cases were about 30–38 ms p50. These are measurements from that host, not latency promises.

Guard remains a same-user safety layer, not a sandbox. Read the [known limits](README.md#guard-blackbrake-inside-claude-code)
before relying on it for sensitive work.
