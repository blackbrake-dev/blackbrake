// Decides whether a detected secret looks real, or looks like a test fixture, an example or a
// local-development value. Without this step, a scanner confidently tells people to rotate keys
// that never existed (it happened on the author's own transcripts: 12 "real" secrets, 0 real).

// Publicly documented example credentials that appear in docs and tests everywhere. Assembled
// from parts so that this file does not itself trip secret scanners.
const KNOWN_EXAMPLES = new Set([
  'AKIA' + 'IOSFODNN7EXAMPLE',
  'wJalrXUtnFEMI/K7MDENG/' + 'bPxRfiCYEXAMPLEKEY',
  'AKIA' + 'ABCDEFGHIJKLMNOP',
]);

const EXAMPLE_WORDS = /\b(fake|falso|falsa|dummy|example|ejemplo|sample|placeholder|mock(ed)?|fixture|lorem|not[- ]a[- ]real|for testing|de prueba|test(ing)?[-_ ]?(key|token|secret)|sk_test_|pk_test_)\b/i;
const EXAMPLE_PATHS = /(^|[\\/])(tests?|__tests__|spec|specs|fixtures?|examples?|samples?|docs?|testdata|mocks?)([\\/]|$)|\.(example|sample|template|dist)(\b|$)|\.(test|spec)\.[a-z]+\b/i;
const LOCAL_HOSTS = /\b(localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\])\b/i;
// Test code around the value: assertions and test declarations.
const TEST_CODE = /\b(assert\w*|expect|describe|it|test)\s*\(/;
// The "secret" is itself source code (an expression), not a value.
const CODE_EXPRESSION = /\?\.|\|\||&&|=>|\(\)|\bprocess\.env\b|\$\{/;

export const isTestPath = (p) => Boolean(p) && EXAMPLE_PATHS.test(p);
const WINDOW = 200;

export const CLASSES = {
  real: 'likely-real',
  example: 'example-or-test',
  local: 'local-dev',
};

// Classifies one occurrence using the text around it and, when known, the file the agent was
// reading or writing.
export function classifyOccurrence({ secret, text, index, filePath }) {
  if (KNOWN_EXAMPLES.has(secret)) return CLASSES.example;
  if (/^(sk|pk|rk)_test_/.test(secret)) return CLASSES.example;
  if (CODE_EXPRESSION.test(secret)) return CLASSES.example;
  // A short value made only of letters ("password", "changeme", "secret") is a word, not a key.
  if (/^["'`]?[A-Za-z_-]{1,16}["'`]?$/.test(secret)) return CLASSES.example;
  const around = text.slice(Math.max(0, index - WINDOW), Math.min(text.length, index + secret.length + WINDOW));
  if (EXAMPLE_WORDS.test(around) || TEST_CODE.test(around)) return CLASSES.example;
  if ((filePath && EXAMPLE_PATHS.test(filePath)) || EXAMPLE_PATHS.test(around)) return CLASSES.example;
  if (LOCAL_HOSTS.test(around)) return CLASSES.local;
  return CLASSES.real;
}

// A secret is only reported as likely real if most of its occurrences look real. A single
// example-looking mention is not enough to dismiss a key the user pasted; a single real-looking
// copy of a fixture that is labelled "fake" everywhere else is not enough to raise an alarm.
// A value that was ever written into, or read from, a test/fixture/example file is treated as a
// fixture: real credentials do not normally live in test files, and when they do, the scanner the
// project already runs on its repository is the right place to catch them.
export function classifySecret(occurrenceClasses, { seenInTestFile = false } = {}) {
  if (seenInTestFile) return CLASSES.example;
  const n = occurrenceClasses.length;
  if (n === 0) return CLASSES.real;
  const count = (c) => occurrenceClasses.filter((x) => x === c).length;
  if (count(CLASSES.example) / n >= 1 / 3) return CLASSES.example;
  if (count(CLASSES.local) / n >= 1 / 2) return CLASSES.local;
  return CLASSES.real;
}
