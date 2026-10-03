# blackbrake report (product)
Version: 0.3.0, Date: 2026-09-30

## Summary
Guard denied a harmless build command

## What happened
I asked the agent to run the tests and guard denied the command.
The alert said the command could not be checked.

## What you expected
- the tests run
- no alert for a plain test command

## Setup
- blackbrake_version: 0.3.0
- os: linux
- arch: x64
- node_major: 22
- lang: en
- harnesses_detected: claude, codex
- harnesses_protected: claude
- mode: protect
- watcher: on
- window: on
- paused: no

## Guard activity in the last 7 days
- kind opaque-command: 3
- action deny: 3

## Problems blackbrake had
- error: 0
- tamper: 0
- integrity: 0
