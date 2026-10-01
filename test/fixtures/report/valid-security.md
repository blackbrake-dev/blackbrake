# blackbrake report (security)
Version: 0.3.0, Date: 2026-09-30

## Summary
A crafted command name can slip past the check

## Affected part
guard or hook

## Steps
Start a session with guard on protect mode.
Ask the agent to run a command whose name mixes upper and lower case.
Watch the alert: nothing is shown.

## Impact
The agent can run a command the guard was meant to stop.
