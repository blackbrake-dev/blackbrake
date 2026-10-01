// The mailto: link for a report (guard-design#6x §5.4, §5.5). Fixed recipient, only subject and body,
// everything percent-encoded, at most 1800 characters, and V9: the body is validated again and the
// link is built from that same string.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { loadRules } from '../src/secrets/engine.mjs';
import { assertSafeMailto, buildMailto, MAX_URL, percentEncode, RECIPIENTS, subjectFor } from '../src/report/mailto.mjs';

const FIXTURES = path.resolve(path.dirname(fileURLToPath(import.meta.url)), 'fixtures/report');

const rules = loadRules();

const identity = { home: 'C:/Users/zzuser-q7', user: 'zzuser-q7', host: 'zzhost-k9' };

const fixture = (name) => fs.readFileSync(path.join(FIXTURES, name), 'utf8').replace(/\r\n/g, '\n');

const args = (over = {}) => ({ kind: 'product', version: '0.3.0', text: fixture('valid-minimal.md'), rules, identity, ...over });

// n short words wrapped at 20 per line, inside a minimal valid report.
const words = (n) => Array.from({ length: Math.ceil(n / 20) }, (_, i) => 'ab '.repeat(Math.min(20, n - i * 20)).trim()).join('\n');

const reportWith = (body) => `# blackbrake report (product)
Version: 0.3.0, Date: 2026-09-30

## Summary
${body}
`;

test('percentEncode: everything except unreserved bytes, UTF-8, CRLF line breaks', () => {
  assert.equal(percentEncode('AZaz09-._~'), 'AZaz09-._~');
  assert.equal(percentEncode(' &=?#%+/:@!*\'()'), '%20%26%3D%3F%23%25%2B%2F%3A%40%21%2A%27%28%29');
  assert.equal(percentEncode('ñ¿'), '%C3%B1%C2%BF');
  assert.equal(percentEncode('a\nb'), 'a%0D%0Ab');
  assert.equal(percentEncode('a\r\nb'), 'a%0D%0Ab');
});

test('subjectFor is fixed text plus kind and version', () => {
  assert.equal(subjectFor('product', '0.3.0'), 'blackbrake report (product) v0.3.0');
  assert.equal(subjectFor('security', '10.20.30'), 'blackbrake report (security) v10.20.30');
  assert.throws(() => subjectFor('other', '0.3.0'), TypeError);
  assert.throws(() => subjectFor('product', '0.3.0\r\nBcc: x'), TypeError);
  assert.throws(() => subjectFor('product', '0.3'), TypeError);
});

test('a small report goes into the link, with a fixed recipient and only subject and body', () => {
  const r = buildMailto(args());
  assert.equal(r.ok, true, JSON.stringify(r.problems));
  assert.equal(r.includesBody, true);
  assert.ok(r.url.length <= MAX_URL);
  assert.ok(r.url.startsWith(`mailto:${RECIPIENTS.product}?subject=blackbrake%20report%20%28product%29%20v0.3.0&body=`));
  assert.equal(r.to, RECIPIENTS.product);
  assert.equal(r.subject, 'blackbrake report (product) v0.3.0');
  assert.equal(r.body, fixture('valid-minimal.md'));
  assert.ok(r.url.includes('%0D%0A'));
  assert.equal(/%0A/.test(r.url.replace(/%0D%0A/g, '')), false);
  // The decoded message is what a person is shown before anything opens.
  assert.equal(decodeURIComponent(r.url.split('&body=')[1]).replace(/\r\n/g, '\n'), r.body);
  assertSafeMailto(r.url);
});

test('security reports go to the security address', () => {
  const r = buildMailto(args({ kind: 'security', text: fixture('valid-security.md') }));
  assert.equal(r.ok, true, JSON.stringify(r.problems));
  assert.ok(r.url.startsWith(`mailto:${RECIPIENTS.security}?subject=`));
  assert.notEqual(RECIPIENTS.security, RECIPIENTS.product);
});

test('a report that does not fit sends only the subject and says so', () => {
  const r = buildMailto(args({ text: reportWith(words(400)) }));
  assert.equal(r.ok, true, JSON.stringify(r.problems));
  assert.equal(r.includesBody, false);
  assert.equal(r.url, `mailto:${RECIPIENTS.product}?subject=blackbrake%20report%20%28product%29%20v0.3.0`);
  assert.equal(r.body, null);
  assert.ok(r.url.length <= MAX_URL);
  assertSafeMailto(r.url);
  assert.equal(MAX_URL, 1800);
});

test('the limit is on the whole URL, and the last report that fits still goes in', () => {
  const base = buildMailto(args());
  let lastFit = null;

  // Grow a one-line report until its body no longer fits.
  for (let n = 1; n < 400; n++) {
    const r = buildMailto(args({ text: reportWith(words(n)) }));

    assert.equal(r.ok, true);
    assert.ok(r.url.length <= MAX_URL);

    if (!r.includesBody) break;
    lastFit = r;
  }

  assert.ok(lastFit, 'some body must fit');
  assert.ok(lastFit.url.length > MAX_URL - 10, `the last fitting URL should be near the limit, was ${lastFit.url.length}`);
  assert.ok(base.url.length < lastFit.url.length);
});

test('V9: a body that is not a valid report never becomes a link, and nothing is echoed', () => {
  const evil = fixture('valid-minimal.md') + 'Bcc: attacker <b>x</b>\n';
  const r = buildMailto(args({ text: evil }));
  assert.equal(r.ok, false);
  assert.equal(r.url, undefined);
  assert.equal(JSON.stringify(r).includes('attacker'), false);
  // The link is built from the string that was validated: editing it afterwards means asking again.
  const edited = buildMailto(args({ text: fixture('valid-minimal.md').replace('Nothing else to add', 'Edited after review') }));
  assert.equal(edited.ok, true);
  assert.ok(edited.body.includes('Edited after review'));
  assert.equal(buildMailto(args({ kind: 'security' })).ok, false, 'a product report is not a security report');
});

test('injection through the body cannot add a header or an attachment', () => {
  const tries = ['x\r\nBcc: a', 'x%0D%0Acc=b', 'x&cc=a', 'x?attach=/etc/hosts', 'x&attach=C:/x'];

  for (const line of tries) {
    const r = buildMailto(args({ text: fixture('valid-minimal.md').replace('Nothing else to add', line) }));

    if (!r.ok) continue;
    assertSafeMailto(r.url);
    assert.equal(/[?&](?!subject=|body=)[a-z]+=/i.test(r.url.slice(r.url.indexOf('?'))), false, r.url);
  }
});

test('assertSafeMailto rejects anything but the fixed shape', () => {
  const to = RECIPIENTS.product;
  const good = `mailto:${to}?subject=x`;
  assertSafeMailto(good);
  assertSafeMailto(`${good}&body=a%0D%0Ab`);

  for (const bad of [
    'mailto:other@example.test?subject=x', `mailto:${to}`, `${good}&cc=a`, `${good}&bcc=a`, `${good}&attach=a`, `${good}&body=a\nb`, `${good}&body=a b`, `mailto:${to}?body=a&subject=x`,
    `mailto:${to},${RECIPIENTS.security}?subject=x`, `${good}&body=${'a'.repeat(MAX_URL)}`, `MAILTO:${to}?subject=x`, `${good}&body=a%0Ab`, `${good}&body=a%0Db`,
    `${good}&body=a&body=b`, `${good}#frag`, 'https://x.test/?subject=x', 42,
  ]) assert.throws(() => assertSafeMailto(bad), /unsafe mailto/, String(bad).slice(0, 60));
});
