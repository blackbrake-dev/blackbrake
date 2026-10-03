# Security policy

## Reporting a vulnerability

Please report security issues **privately** by email to **security@blackbrake.dev**.
Do not open a public issue for vulnerabilities.

Include what you found, how to reproduce it, and the version (`blackbrake --version`).
You will get an acknowledgement within 3 working days.

`blackbrake report security` can prepare the draft for you: it writes a plain-text file on your
computer, shows it, and only opens your mail app if you ask. It sends nothing by itself.

- **Do not include secrets**, tokens, file paths or working exploit code: describe the kind of problem
  and the steps to see it. The report format refuses anything that looks like a secret, a path or a
  link, but no filter catches everything.
- **Email is not end-to-end encrypted.** Once you send it, the message is in the hands of the mail
  providers on both sides.

## Scope

Especially relevant for this project:

- any way blackbrake could send data over the network;
- any way it could write to, modify or delete files;
- any way an AI agent could switch it off, pause it, lower its protection or make a report be sent
  without the person at the terminal;
- any way a secret value could appear in its output, logs or error messages;
- rule-handling issues that make it miss a class of secrets (false negatives).

## Supported versions

Only the latest published version receives fixes while the project is pre-1.0.
