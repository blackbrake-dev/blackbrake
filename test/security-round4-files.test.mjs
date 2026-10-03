// Independent F6.12 review. Only fresh mkdtemp stand-ins; never change real installation.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { mayChange, realHome } from '../src/guard/safety.mjs';

const temp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'bb-r4-files-'));

test('R4 safety refuses a recursive deletion target containing a protected place', () => {
  const real = temp();
  fs.mkdirSync(path.join(real, '.blackbrake'));
  // Pure authorization check: no removal or destructive function is called.
  assert.throws(() => mayChange(real, { realHome: real, declared: false }), /refused to change/);
});

test('R4 account lookup failure cannot replace protected home with redirected HOME', (t) => {
  const real = temp();
  const redirected = temp();
  fs.mkdirSync(path.join(real, '.blackbrake'));
  t.mock.method(os, 'userInfo', () => { throw new Error('account lookup unavailable'); });
  t.mock.method(os, 'homedir', () => redirected);
  // A lookup failure must refuse instead of trusting environment-dependent homedir.
  assert.throws(() => mayChange(path.join(real, '.blackbrake'), { realHome: realHome(), declared: false }), /refused|account|home/i);
});
