// F6.12 round 2, finding V4 (medium): classify() took any node flag before the script, so decoys
// such as `node --eval=… …/watch-main.mjs` or `node --import=x …/watch-main.mjs` counted as
// blackbrake's watcher or window, and any folder ending in src/guard/watch-main.mjs did too. The
// sweep could stop somebody else's process, and a decoy could pass for the window. Now only a short
// list of node flags is accepted, and the script must be guard's own: <home>/app/src/guard (or the
// marketplace copy) or this package's checkout. All command lines here are synthetic: no process
// table is read and nothing is signalled.
import assert from 'node:assert/strict';
import path from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { classify } from '../src/guard/classify.mjs';
import { isWatcherProcess } from '../src/guard/autostart.mjs';
import { findWatchers, stopKind } from '../src/guard/procs.mjs';
import { liveWindowRunning } from '../src/guard/window.mjs';

const BS = '\x5c';

const HOME = '/home/ana/.blackbrake';

const SCRIPT = `${HOME}/app/src/guard/watch-main.mjs`;

const WHOME = `C:${BS}Users${BS}ana${BS}.blackbrake`;

const WSCRIPT = `${WHOME}${BS}app${BS}src${BS}guard${BS}watch-main.mjs`;

const PKG = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

test('V4: node flags that run other code before the script are never ours', () => {
  for (const flags of [
    '--eval=setInterval(()=>{},1e3)',
    '--print=1',
    '--check',
    '--test',
    '-c',
    '--loader=x',
    '--loader x',
    '--import=x',
    '--import x',
    '-r x',
    '--require x',
    '--require=x',
    '--experimental-loader=x',
    '--input-type=module --eval=1',
    '--env-file=.env',
    '--watch',
    '--inspect-brk',
    '--inspect=0.0.0.0:9229 --require x',
    '--max-old-space-size=abc',
    '--no-warnings --import=x',
  ]) {
    for (const tail of ['--background', '']) {
      const cmd = `/usr/bin/node ${flags} ${SCRIPT} ${tail}`.trim();

      assert.equal(classify(cmd, { home: HOME }), null, cmd);
    }
  }
});

test('V4: the allowed node flags still let the real watcher and window through', () => {
  for (const flags of ['', '--no-warnings', '--max-old-space-size=256', '--stack-size=2048', '--inspect', '--inspect=127.0.0.1:9229', '--no-warnings --max-old-space-size=4096']) {
    assert.equal(classify(`/usr/bin/node ${flags} ${SCRIPT} --background`, { home: HOME }), 'watcher', flags);
    assert.equal(classify(`/usr/bin/node ${flags} ${SCRIPT}`, { home: HOME }), 'window', flags);
  }
});

test('V4: the script must be guard\'s own copy, not any folder ending in src/guard', () => {
  for (const cmd of [
    '/usr/bin/node /tmp/x/src/guard/watch-main.mjs --background',
    '/usr/bin/node /home/eve/.blackbrake/app/src/guard/watch-main.mjs --background',
    `/usr/bin/node ${HOME}/app/src/guard/../../../../tmp/src/guard/watch-main.mjs --background`,
    `/usr/bin/node ${HOME}/evil/src/guard/watch-main.mjs --background`,
    `/usr/bin/node ${HOME}/app/x/src/guard/watch-main.mjs`,
  ]) assert.equal(classify(cmd, { home: HOME }), null, cmd);
});

test('V4: installed copy, marketplace copy and the package checkout are recognised', () => {
  assert.equal(classify(`/usr/bin/node ${SCRIPT} --background`, { home: HOME }), 'watcher');
  assert.equal(classify(`/usr/bin/node ${HOME}/marketplace/blackbrake/app/src/guard/watch-main.mjs --background`, { home: HOME }), 'watcher');
  assert.equal(classify(`/usr/bin/node ${HOME}/app/src/guard/watch-main.mjs`, { home: `${HOME}/` }), 'window', 'a trailing separator on home');
  const own = path.join(PKG, 'src', 'guard', 'watch-main.mjs');

  assert.equal(classify(`"${process.execPath}" "${own}" --background`, { home: HOME }), 'watcher', 'this package\'s own checkout');
});

test('V4: on Windows the comparison ignores case and separator style', () => {
  const node = `"C:${BS}Program Files${BS}nodejs${BS}node.exe"`;

  assert.equal(classify(`${node} "${WSCRIPT}" --background`, { home: WHOME, platform: 'win32' }), 'watcher');
  assert.equal(classify(`${node} "${WSCRIPT.toUpperCase()}" --background`, { home: WHOME, platform: 'win32' }), 'watcher');
  assert.equal(classify(`${node} C:/Users/ana/.blackbrake/app/src/guard/watch-main.mjs`, { home: WHOME, platform: 'win32' }), 'window');
  assert.equal(classify(`${node} "C:${BS}Users${BS}eve${BS}.blackbrake${BS}app${BS}src${BS}guard${BS}watch-main.mjs" --background`, { home: WHOME, platform: 'win32' }), null);
  assert.equal(classify(`/usr/bin/node ${SCRIPT.toUpperCase()} --background`, { home: HOME, platform: 'linux' }), null, 'case matters off Windows');
});

test('V4: the sweep uses the home it is given', () => {
  const list = () => [
    { pid: 11, cmd: `/usr/bin/node ${SCRIPT} --background` },
    { pid: 12, cmd: `/usr/bin/node --eval=1 ${SCRIPT} --background` },
    { pid: 13, cmd: '/usr/bin/node /tmp/src/guard/watch-main.mjs --background' },
  ];

  assert.deepEqual(findWatchers({ list, home: HOME }), [11]);
});

test('V4: the process titles are unchanged', () => {
  assert.equal(classify('blackbrake watcher', { home: HOME }), 'watcher');
  assert.equal(classify('blackbrake watch', { home: HOME }), 'window');
});

test('V4: pid verification and window deduplication use the supplied installation', () => {
  const watcher = (cmd) => isWatcherProcess(42, { home: HOME, platform: 'linux', read: () => cmd });
  const window = (cmd) => liveWindowRunning({ home: WHOME, platform: 'win32', find: () => 'powershell.exe', run: () => ({ stdout: `42\t${cmd}` }) });

  assert.equal(watcher(`/usr/bin/node ${SCRIPT} --background`), true);
  assert.equal(watcher(`/usr/bin/node --check ${SCRIPT} --background`), false);
  assert.equal(watcher('/usr/bin/node /tmp/src/guard/watch-main.mjs --background'), false);
  assert.equal(window(`node "${WSCRIPT.toUpperCase()}" watch`), true);
  assert.equal(window(`node --eval=1 "${WSCRIPT}" watch`), false);
  assert.equal(window('node C:/tmp/src/guard/watch-main.mjs watch'), false);
});

test('V4: the sweep rechecks the supplied home and refuses a pid replaced by a decoy', () => {
  const killed = [];

  const r = stopKind('watcher', {
    home: HOME,
    platform: 'linux',
    list: () => [{ pid: 42, cmd: `/usr/bin/node ${SCRIPT} --background` }],
    commandOf: () => `/usr/bin/node --test ${SCRIPT} --background`,
    kill: (pid) => killed.push(pid),
    graceMs: 0,
    sleep() {},
  });

  assert.deepEqual(killed, []);
  assert.deepEqual(r, { found: [42], remaining: [42] });
});
