import crypto from 'node:crypto';

const canonical = (value, seen = new Set()) => {
  if (value === null) return ['null'];
  // oxlint-disable-next-line anti-slop/no-runtime-typeof -- Canonicalization intentionally preserves every JavaScript input type.
  const type = typeof value;

  if (type === 'string') return ['string', value.normalize('NFC')];

  if (type === 'number') return ['number', Number.isFinite(value) ? value : String(value)];

  if (type === 'boolean') return ['boolean', value];

  if (type === 'undefined') return ['undefined'];

  if (type === 'bigint') return ['bigint', String(value)];

  if (type !== 'object') return [type, String(value)];

  if (seen.has(value)) throw new TypeError('Cyclic tool arguments');

  seen.add(value);

  const out = Array.isArray(value)
    ? ['array', value.map((item) => canonical(item, seen))]
    : ['object', Object.keys(value).sort().map((key) => [key.normalize('NFC'), canonical(value[key], seen)])];

  seen.delete(value);

  return out;
};

export const callFingerprint = (secret, tool, args) => crypto.createHmac('sha256', secret)
  .update(JSON.stringify(['tool', String(tool).normalize('NFC'), canonical(args)]))
  .digest('hex');

export function createLoopDetector({ secret, windowSize = 8, windowMs = 120_000, threshold = 3, snapshot = null } = {}) {
  if (!secret) throw new TypeError('Loop detector secret is required');
  let calls = Array.isArray(snapshot?.calls) ? snapshot.calls.filter((call) => Number.isFinite(call?.at) && /^[a-f0-9]{64}$/.test(call?.fingerprint)).slice(-windowSize) : [];
  const alerted = new Set(Array.isArray(snapshot?.alerted) ? snapshot.alerted.filter((fingerprint) => /^[a-f0-9]{64}$/.test(fingerprint)) : []);

  return {
    record(tool, args, at = Date.now()) {
      calls = calls.filter((call) => at - call.at <= windowMs).slice(-(windowSize - 1));
      const present = new Set(calls.map((call) => call.fingerprint));

      for (const fingerprint of alerted) if (!present.has(fingerprint)) alerted.delete(fingerprint);
      const fingerprint = callFingerprint(secret, tool, args);
      calls.push({ at, fingerprint });
      const count = calls.filter((call) => call.fingerprint === fingerprint).length;
      const alert = count >= threshold && !alerted.has(fingerprint);

      if (alert) alerted.add(fingerprint);

      return { fingerprint, count, alert };
    },
    reset() {
      calls = [];
      alerted.clear();
    },
    snapshot() {
      return { calls: calls.map(({ at, fingerprint }) => ({ at, fingerprint })), alerted: [...alerted] };
    },
  };
}
