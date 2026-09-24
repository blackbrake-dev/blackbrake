# Security policy

## Reporting a vulnerability

Please report security issues **privately** by email to **security@blackbrake.dev**.
Do not open a public issue for vulnerabilities.

Include what you found, how to reproduce it, and the version (`blackbrake --version`).
You will get an acknowledgement within 3 working days.

## Scope

Especially relevant for this project:

- any way blackbrake could send data over the network;
- any way it could write to, modify or delete files;
- any way a secret value could appear in its output, logs or error messages;
- rule-handling issues that make it miss a class of secrets (false negatives).

## Supported versions

Only the latest published version receives fixes while the project is pre-1.0.
