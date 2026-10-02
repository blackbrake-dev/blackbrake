// Which processes are blackbrake's watcher or alerts window (src/guard/classify.mjs). Review C
// (2026-10-01): the old check counted any command line that merely MENTIONED watch-main.mjs (a grep,
// an editor, `node tool.js --import …/watch-main.mjs`), so uninstall or pause could stop it and a
// decoy could keep the alerts window from opening. Now the process must BE node running that file.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { classify } from '../src/guard/classify.mjs';

test('real watchers and windows, as the process tables show them on each system', () => {
  for (const [cmd, kind] of [
    ['"C:\\Program Files\\nodejs\\node.exe"  "C:\\Users\\ana\\.blackbrake\\app\\src\\guard\\watch-main.mjs" --background', 'watcher'],
    ['"C:\\Program Files\\nodejs\\node.exe" C:\\Users\\ana\\.blackbrake\\app\\src\\guard\\watch-main.mjs watch', 'window'],
    ['/usr/bin/node /home/ana/.blackbrake/app/src/guard/watch-main.mjs --background', 'watcher'],
    ['node /Users/ana/.blackbrake/app/src/guard/watch-main.mjs', 'window'],
    ['/opt/homebrew/bin/node --no-warnings /Users/ana/.blackbrake/app/src/guard/watch-main.mjs --background', 'watcher'],
    ['blackbrake watcher', 'watcher'],
    ['blackbrake watch', 'window'],
    ['blackbrake watcher   ', 'watcher'],
  ]) assert.equal(classify(cmd), kind, cmd);
});

test('a command line that only mentions the file, or a look-alike title, is not ours', () => {
  for (const cmd of [
    'grep -r "node x/src/guard/watch-main.mjs" .',
    'grep -r node x/src/guard/watch-main.mjs --background',
    'node C:/other/tool.js --import C:/proj/src/guard/watch-main.mjs',
    'node tool.js --foo=C:/proj/src/guard/watch-main.mjs --background',
    'node -e "setInterval(()=>{},1e3)" x/src/guard/watch-main.mjs --background',
    'less /home/ana/.blackbrake/app/src/guard/watch-main.mjs',
    'git log --grep watch-main.mjs',
    'claude -p "kill node /x/src/guard/watch-main.mjs"',
    'sleep 1e6 watch-main.mjs',
    'blackbrake watcher evil',
    'blackbrake watch --background',
    'blackbrake watcherx',
    'nodemon /x/src/guard/watch-main.mjs --background',
    'node /x/src/guard/watch-main.mjs.bak --background',
    'node /x/src/guard/not-watch-main.mjs --background',
    '',
    null,
  ]) assert.equal(classify(cmd), null, String(cmd));
});
