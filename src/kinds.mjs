// The one place that tells the primitive kinds of untrusted values apart (parsed JSON, transcript
// records, caller input). Everything else asks a question in domain terms instead of repeating
// `typeof` at each use.
/* oxlint-disable anti-slop/no-runtime-typeof -- this module is the boundary the rule asks for */

export const isText = (v) => typeof v === 'string';

export const isCount = (v) => typeof v === 'number';

export const isFlag = (v) => typeof v === 'boolean';

// A non-null object (array included, as with `typeof`); use Array.isArray first to tell them apart.
export const isObject = (v) => Boolean(v) && typeof v === 'object';

// A plain JSON-like record: an object that is not an array.
export const isRecord = (v) => isObject(v) && !Array.isArray(v);

export const isFunction = (v) => typeof v === 'function';
