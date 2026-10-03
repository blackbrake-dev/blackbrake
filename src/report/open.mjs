// Opens the person's mail app on a report's mailto: link, and only after they pressed for it
// (guard-design#6x §5.4). The link is checked again here (assertSafeMailto: fixed recipient, only
// subject and body, all percent-encoded, ≤ 1800 characters). The program comes from a system folder,
// never from PATH; its arguments are a list; no shell, no cmd, no editor. If nothing can open it, the
// caller prints the address instead.
import { spawn } from 'node:child_process';
import { systemProgram } from '../guard/window.mjs';
import { assertSafeMailto } from './mailto.mjs';

// { file, args } or null when this system has no program for it.
export function mailtoCommand(url, { platform = process.platform, find = (n) => systemProgram(n, { platform }) } = {}) {
  assertSafeMailto(url);

  if (platform === 'win32') {
    const file = find('rundll32.exe');

    return file ? { file, args: ['url.dll,FileProtocolHandler', url] } : null;
  }

  const file = find(platform === 'darwin' ? 'open' : 'xdg-open');

  return file ? { file, args: [url] } : null;
}

// true when the program was started (whether a mail app then opens is up to the system).
export function openMailto(url, { platform = process.platform, find = (n) => systemProgram(n, { platform }), run = spawn } = {}) {
  const c = mailtoCommand(url, { platform, find });

  if (!c) return false;

  try {
    const child = run(c.file, c.args, { detached: true, stdio: 'ignore', windowsHide: true, shell: false });
    child.on?.('error', () => { /* said by the caller: the address is printed anyway */ });
    child.unref?.();

    return true;
  } catch {
    return false;
  }
}
