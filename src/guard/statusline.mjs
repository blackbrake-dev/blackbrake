#!/usr/bin/env node
// Claude Code status bar entry: reads the session JSON on stdin, prints one line. Local only.
import fs from 'node:fs';
import { createPainter } from '../ui/term.mjs';
import { statusLineText } from './cli.mjs';
import { declareProgram } from './safety.mjs';

declareProgram();

let input = {};

try { const buf = fs.readFileSync(0);

 if (buf.length <= 1024 * 1024) input = JSON.parse(buf.toString('utf8') || '{}'); } catch { /* no session data: show mode only */ }

process.stdout.write(`${statusLineText(createPainter(3), input)}\n`);
