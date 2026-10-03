// F6.12 round 2, finding V5: the real-installation lock (src/guard/safety.mjs) compared text only.
// A device or UNC spelling (\\?\C:\…, \\.\C:\…, \\localhost\C$\…), a stream suffix
// (::$INDEX_ALLOCATION, :$I30, :stream), a trailing dot, an 8.3 short name (BLACKB~1, ALUCE~1), a
// junction or symlink into a real place, a hard link to a real file or different case on macOS all
// reached the real installation while the text said "elsewhere".
//
// These tests NEVER touch the real folders: every "real home" here is a folder made by mkdtemp (or a
// made-up path that does not exist), and the lock is only asked whether it would allow a change
// (mayChange throws or returns); nothing is written through the links it is asked about.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { isRealPlace, mayChange } from '../src/guard/safety.mjs';

const WIN = process.platform === 'win32';

const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'bb-v5-'));

// A stand-in real home inside a fresh temporary folder, with a real-looking guard folder in it.
function sandbox() {
  const root = tmp();
  const real = path.join(root, 'real');
  const bb = path.join(real, '.blackbrake');
  fs.mkdirSync(bb, { recursive: true });
  fs.writeFileSync(path.join(bb, 'state.json'), '{"mode":"protect"}');
  assert.ok(real.startsWith(os.tmpdir()), 'the stand-in lives in the temporary folder');

  return { root, real, bb };
}

const refused = (target, real, extra = {}) => assert.throws(() => mayChange(target, { realHome: real, declared: false, ...extra }), /refused to change/, target);

const allowed = (target, real, extra = {}) => assert.doesNotThrow(() => mayChange(target, { realHome: real, declared: false, ...extra }), target);

test('V5: device and UNC spellings are refused outright (fail closed)', { skip: !WIN && 'Windows path syntax' }, () => {
  const real = path.join(path.parse(os.tmpdir()).root, 'Users', 'someone');
  const drive = path.parse(os.tmpdir()).root.slice(0, 1);
  const rest = real.slice(3);

  for (const target of [
    `\\\\?\\${real}\\.blackbrake\\state.json`,
    `\\\\.\\${real}\\.blackbrake`,
    `//?/${real}/.blackbrake`,
    `\\\\localhost\\${drive}$\\${rest}\\.blackbrake`,
    `\\\\127.0.0.1\\${drive}$\\${rest}\\.claude\\settings.json`,
    `\\\\?\\UNC\\localhost\\${drive}$\\${rest}\\.blackbrake`,
    `\\\\[::1]\\${drive}$\\${rest}\\.blackbrake`,
    `\\\\${os.hostname()}\\${drive}$\\${rest}\\.blackbrake`,
    `\\\\?\\${tmp()}\\anything`,
  ]) refused(target, real);
});

test('V5: stream suffixes and trailing dots or spaces name the same real place', { skip: !WIN && 'NTFS streams' }, () => {
  const real = path.join(path.parse(os.tmpdir()).root, 'Users', 'someone');

  for (const target of [
    path.join(real, '.blackbrake::$INDEX_ALLOCATION', 'state.json'),
    path.join(real, '.blackbrake:$I30:$INDEX_ALLOCATION', 'state.json'),
    path.join(real, '.claude.json:evil'),
    path.join(real, '.claude.json::$DATA'),
    path.join(real, '.blackbrake.', 'state.json'),
    path.join(real, '.blackbrake ', 'state.json'),
    path.join(real, '.blackbrake. .', 'state.json'),
  ]) refused(target, real);

  assert.equal(isRealPlace(path.join(real, '.claude.json:x'), real), true);
});

test('V5: an 8.3 short name reaches the real place (target or real home spelled short)', { skip: !WIN && '8.3 names are Windows only' }, (t) => {
  const { root, real, bb } = sandbox();
  const shortBb = path.join(real, 'BLACKB~1');

  if (!fs.existsSync(shortBb)) return t.skip('8.3 names are off on this volume');
  const shortStat = fs.statSync(shortBb, { bigint: true });
  const longStat = fs.statSync(bb, { bigint: true });

  assert.equal(shortStat.dev, longStat.dev);
  assert.equal(shortStat.ino, longStat.ino, 'both spellings identify the same directory');
  refused(path.join(shortBb, 'state.json'), real);
  refused(path.join(shortBb, 'not-yet.json'), real);

  // The real home itself spelled short (USERPROFILE = C:\Users\ALUCE~1): long target, short home.
  const longHome = path.join(root, 'longer-home-name');
  fs.mkdirSync(path.join(longHome, '.claude'), { recursive: true });
  const shortHome = path.join(root, 'LONGER~1');

  if (!fs.existsSync(shortHome)) return t.skip('8.3 names are off on this volume');
  refused(path.join(longHome, '.claude', 'settings.json'), shortHome);
  refused(path.join(shortHome, '.claude', 'settings.json'), longHome);
  refused(path.join(shortHome, '.blackbrake', 'state.json'), longHome, {});
  allowed(path.join(shortHome, 'projects', 'x'), longHome);
});

test('V5: a junction into the real guard folder is refused, even before the folder exists', { skip: !WIN && 'junctions are Windows only' }, () => {
  const { root, real, bb } = sandbox();
  const j = path.join(root, 'innocent');
  fs.symlinkSync(bb, j, 'junction');
  refused(path.join(j, 'state.json'), real);
  refused(j, real);

  // Dangling: the real .codex does not exist yet; writing through the junction would create it.
  const dangling = path.join(root, 'later');
  fs.symlinkSync(path.join(real, '.codex'), dangling, 'junction');
  assert.equal(fs.existsSync(dangling), false);
  refused(path.join(dangling, 'config.toml'), real);

  // A junction to the home itself, then down into a real place.
  const home = path.join(root, 'home-link');
  fs.symlinkSync(real, home, 'junction');
  refused(path.join(home, '.blackbrake', 'state.json'), real);
  allowed(path.join(home, 'projects', 'x'), real);
});

test('V5: a symlink into a real place is refused', (t) => {
  const { root, real, bb } = sandbox();
  const file = path.join(root, 'file-link');
  const dir = path.join(root, 'dir-link');

  try {
    fs.symlinkSync(path.join(bb, 'state.json'), file, 'file');
    fs.symlinkSync(bb, dir, 'dir');
    fs.symlinkSync(path.join(real, '.gemini', 'settings.json'), path.join(root, 'dangling'), 'file');
  } catch (e) {
    if (e.code === 'EPERM' || e.code === 'EACCES') return t.skip('no permission to create symlinks here');
    throw e;
  }

  refused(file, real);
  refused(path.join(dir, 'state.json'), real);
  refused(path.join(root, 'dangling'), real);
});

test('V5: a hard link to a real file is refused (any file with more than one link, fail closed)', () => {
  const { root, real, bb } = sandbox();
  const h = path.join(root, 'state-copy.json');
  fs.linkSync(path.join(bb, 'state.json'), h);
  refused(h, real);

  const plain = path.join(root, 'plain.json');
  fs.writeFileSync(plain, '{}');
  allowed(plain, real);
});

test('V5: on macOS the real places are matched without regard to case', () => {
  const real = path.join(path.parse(os.tmpdir()).root, 'Users', 'someone');
  refused(path.join(real, '.BlackBrake', 'state.json'), real, { platform: 'darwin' });
  refused(path.join(real, '.CLAUDE', 'settings.json'), real, { platform: 'darwin' });
  assert.equal(isRealPlace(path.join(real, '.Codex', 'x'), real, { platform: 'darwin' }), true);
});

test('V5: ordinary temporary paths, existing or not, and the program itself stay fine', () => {
  const { root, real } = sandbox();
  allowed(path.join(root, 'elsewhere', '.blackbrake', 'state.json'), real);
  allowed(path.join(root, '.blackbrake-old'), real);
  fs.mkdirSync(path.join(root, 'exists'));
  allowed(path.join(root, 'exists'), real);
  assert.doesNotThrow(() => mayChange(path.join(real, '.blackbrake', 'state.json'), { realHome: real, declared: true }));
});

test('V5: dot segments are resolved before comparing the protected places', () => {
  const { root, real } = sandbox();

  refused(`${real}${path.sep}projects${path.sep}..${path.sep}.blackbrake${path.sep}state.json`, real);
  allowed(`${real}${path.sep}.blackbrake${path.sep}..${path.sep}projects${path.sep}state.json`, real);
  allowed(path.join(root, 'safe'), real);
});
