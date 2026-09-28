# blackbrake 0.2.3

A bug-fix release for macOS and Linux.

## What changed

- `blackbrake uninstall` now stops the running background watcher on macOS and Linux. The watcher
  renames its process to `blackbrake watcher`, which on those systems replaces the command line that
  `/proc` and `ps` report; uninstall looked for the script path, did not recognise the process and
  left it running until the next logout. The login item itself was already removed.
- The check that allows uninstall to stop a process is stricter: the watcher's name must lead the
  command line, so a program that merely has those words as an argument is never stopped.

## How it was found and checked

- A new native test runs on GitHub-hosted macOS and Linux machines with Node 20, 22 and 24: it
  writes the real login item (`plutil`-validated plist or `.desktop`), starts the watcher from a
  temporary home, identifies it in the process table and stops it. It is skipped on Windows. All 9
  CI jobs pass.
- This is evidence from hosted CI machines, not from a desktop login: starting at login, visible
  notifications and native agent sessions on macOS and Linux are still being validated on real
  hosts ([playbook](NATIVE-VALIDATION.md)).

Guard remains a same-user safety layer, not a sandbox. Read the [known limits](README.md#guard-blackbrake-inside-claude-code)
before relying on it for sensitive work.
