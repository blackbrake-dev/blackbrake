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
const WATCHER_TITLE = /^blackbrake watcher\s*$/;

const WINDOW_TITLE = /^blackbrake watch\s*$/;

const NODE = /(?:^|[\\/])node(?:js)?(?:\.exe)?$/i;

const SCRIPT = /[\\/]src[\\/]guard[\\/]watch-main\.mjs$/i;

// node flags that take code or a module instead of running a script file.
const NOT_A_SCRIPT_RUN = /^(-e|-p|-r|--eval|--print|--require|--import|--loader|--experimental-loader)$/;

// Command-line words, keeping double-quoted ones (Windows quotes paths with spaces) together.
const words = (cmd) => [...cmd.matchAll(/"([^"]*)"|(\S+)/g)].map((m) => m[1] ?? m[2]);

// 'watcher', 'window' or null for one command line.
export function classify(cmd) {
  const c = String(cmd ?? '').replace(/\0+/g, ' ').trim();

  if (WATCHER_TITLE.test(c)) return 'watcher';

  if (WINDOW_TITLE.test(c)) return 'window';
  const argv = words(c);

  if (!NODE.test(argv[0] ?? '')) return null;
  let i = 1;

  while (i < argv.length && argv[i].startsWith('-')) {
    if (NOT_A_SCRIPT_RUN.test(argv[i])) return null;
    i++;
  }

  if (!SCRIPT.test(argv[i] ?? '')) return null;

  return argv.slice(i + 1).includes('--background') ? 'watcher' : 'window';
}
