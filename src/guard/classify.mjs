// Which processes are blackbrake's own: the background watcher or an alerts window. One answer
// for every place that needs it (the sweep that stops them, the check before killing a pid from the
// pid file, the "is a window already open" check), so the strictest rule is the only one.
//
// A process is ours only when it IS node running guard's watch-main.mjs: the program is node, and
// after node's own flags the first argument is a path ending in /src/guard/watch-main.mjs. A command
// line that merely mentions the file (a grep, an editor, `node tool.js --import …/watch-main.mjs`)
// is not (review C, 2026-10-01: the old check matched mentions, so uninstall or pause could stop an
// unrelated process and a decoy could keep the alerts window from opening).
// On Linux and macOS watch-main.mjs renames itself (process.title), and the process table shows
// exactly 'blackbrake watcher' or 'blackbrake watch': only those exact titles count.
//
// F6.12 round 2, V4: any node flag used to be skipped (only a few code-running ones were refused),
// and any folder ending in src/guard/watch-main.mjs counted. `node --input-type=module --eval=…`,
// `--check`, `--test`, `--loader=x`, `--import=x`… before the path passed for ours, so the sweep
// could stop another process and a decoy could pass for the window. Now:
//   - only an allow-list of node flags may come before the script (blackbrake itself passes none);
//   - the script must be guard's own copy: <home>/app/src/guard/watch-main.mjs, the marketplace
//     copy <home>/marketplace/blackbrake/app/…, or this package's checkout (where this file is),
//     compared whole, with separators normalised and, on Windows, without case.
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { guardHome } from './state.mjs';

const WATCHER_TITLE = /^blackbrake watcher\s*$/;

const WINDOW_TITLE = /^blackbrake watch\s*$/;

const NODE = /(?:^|[\\/])node(?:js)?(?:\.exe)?$/i;

const ALLOWED_FLAG = /^(?:--no-warnings|--max-old-space-size=\d+|--stack-size=\d+|--inspect(?:=[\w.:[\]-]+)?)$/;

// The checkout this file belongs to (an installed copy: <home>/app).
const PACKAGE = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');

const TAIL = '/src/guard/watch-main.mjs';

const norm = (p) => String(p).replace(/\\/g, '/').replace(/\/+/g, '/').replace(/\/$/, '');

// Command-line words, keeping double-quoted ones (Windows quotes paths with spaces) together.
const words = (cmd) => [...cmd.matchAll(/"([^"]*)"|(\S+)/g)].map((m) => m[1] ?? m[2]);

// The exact script paths that are guard's own for this home.
const ownScripts = (home) => {
  const h = norm(home);

  return h ? [`${h}/app${TAIL}`, `${h}/marketplace/blackbrake/app${TAIL}`, `${norm(PACKAGE)}${TAIL}`] : [`${norm(PACKAGE)}${TAIL}`];
};

// 'watcher', 'window' or null for one command line. `home` is guard's folder (default: the one
// this process uses); `platform` decides whether case counts.
export function classify(cmd, { home = guardHome(), platform = process.platform } = {}) {
  const c = String(cmd ?? '').replace(/\0+/g, ' ').trim();

  if (WATCHER_TITLE.test(c)) return 'watcher';

  if (WINDOW_TITLE.test(c)) return 'window';
  const argv = words(c);

  if (!NODE.test(argv[0] ?? '')) return null;
  let i = 1;

  while (i < argv.length && argv[i].startsWith('-')) {
    if (!ALLOWED_FLAG.test(argv[i])) return null;
    i++;
  }

  const fold = (s) => (platform === 'win32' ? s.toLowerCase() : s);
  const script = fold(norm(argv[i] ?? ''));

  if (!script || !ownScripts(home).some((s) => fold(s) === script)) return null;

  return argv.slice(i + 1).includes('--background') ? 'watcher' : 'window';
}
