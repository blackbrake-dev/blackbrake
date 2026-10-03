// The mailto: link for a report (guard-design#6x §5.4, §5.5). Fixed recipient per kind, only
// `subject` and `body`, everything percent-encoded, at most 1800 characters (ShellExecute and Outlook
// stop near 2048). No cc, bcc, from or attach: RFC 6068 only calls subject, keywords and body safe,
// and CVE-2022-4055 is an `attach` slipped in through a URL.
//
// V9: the body is validated again here and the link is built from that same validated string, so
// there is no window between "reviewed" and "sent". If it does not fit, only the subject goes in and
// the caller says to copy the text or attach the file by hand.
import { assertKind, META_LINE, validateReport } from './validate.mjs';
import { isText } from '../kinds.mjs';

export const RECIPIENTS = Object.freeze({ product: 'hello@blackbrake.dev', security: 'security@blackbrake.dev' });

export const MAX_URL = 1800;

const VERSION = /^\d{1,3}\.\d{1,3}\.\d{1,3}$/;

const UNRESERVED = /[A-Za-z0-9\-._~]/;

// Every byte except the unreserved set; line breaks are CRLF, as RFC 6068 asks for a body.
export function percentEncode(text) {
  let out = '';

  for (const byte of Buffer.from(String(text).replace(/\r?\n/g, '\r\n'), 'utf8')) {
    const ch = String.fromCharCode(byte);
    out += byte < 0x80 && UNRESERVED.test(ch) ? ch : `%${byte.toString(16).toUpperCase().padStart(2, '0')}`;
  }

  return out;
}

export function subjectFor(kind, version) {
  assertKind(kind);

  if (!VERSION.test(String(version))) throw new TypeError('version must look like 0.3.0');

  return `blackbrake report (${kind}) v${version}`;
}

// The last line of defence, also used by the tests and by the cross-review: the exact shape and
// nothing else. It never repeats the URL in its error.
export function assertSafeMailto(url) {
  const fail = (why) => { throw new Error(`unsafe mailto: ${why}`); };

  if (!isText(url) || url.length > MAX_URL) fail('size or type');
  const m = /^mailto:(hello@blackbrake\.dev|security@blackbrake\.dev)\?subject=([A-Za-z0-9%._~-]+)(?:&body=([A-Za-z0-9%._~-]*))?$/.exec(url);

  if (!m) fail('shape');
  const [, , subject, body = ''] = m;

  if (/%(?![0-9A-F]{2})/.test(subject) || /%(?![0-9A-F]{2})/.test(body)) fail('encoding');

  if (/%0[AD]/.test(subject) || /%0[AD]/.test(body.replace(/%0D%0A/g, ''))) fail('line breaks');

  return true;
}

// { ok: true, url, to, subject, body | null, includesBody } or { ok: false, problems }.
export function buildMailto({ kind, version, text, rules, identity }) {
  assertKind(kind);
  const subject = subjectFor(kind, version);
  const checked = validateReport(text, { kind, rules, identity });

  if (!checked.ok) return { ok: false, problems: checked.problems };

  if (META_LINE.exec(checked.text.split('\n')[1])?.[1] !== version) return { ok: false, problems: [{ rule: 'V9', code: 'version-mismatch', line: 2 }] };
  const to = RECIPIENTS[kind];
  const base = `mailto:${to}?subject=${percentEncode(subject)}`;
  const full = `${base}&body=${percentEncode(checked.text)}`;
  const includesBody = full.length <= MAX_URL;
  const url = includesBody ? full : base;

  assertSafeMailto(url);

  return { ok: true, url, to, subject, body: includesBody ? checked.text : null, includesBody, problems: [] };
}
