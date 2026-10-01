// Persist and load report aggregates: scanAggregates, auditAggregates with SAFE_KEY validation.
// Reports stored under BLACKBRAKE_HOME/reports/ with secure permissions.
import fs from 'node:fs';
import path from 'node:path';
import { validateReport } from './validate.mjs';
import { aggregateReport } from './aggregate.mjs';

const SAFE_KEY = /^[a-z0-9-]+$/i; // Alphanumeric + hyphen, no path separators

function validateAggregateKey(key) {
  if (typeof key !== 'string') return false;
  if (key.length === 0 || key.length > 64) return false;
  return SAFE_KEY.test(key);
}

export function scanAggregates(home, rules) {
  // List all report aggregate files in ~/.blackbrake/reports/ and load their aggregated data.
  // Returns { [key]: aggregateData, … } or empty object if none.
  const reportsDir = path.join(home, '.blackbrake', 'reports');
  const aggregates = {};

  try {
    if (!fs.existsSync(reportsDir)) return aggregates;

    const entries = fs.readdirSync(reportsDir);

    for (const entry of entries) {
      // Look for aggregate JSON files: product-aggregates.json, security-aggregates.json
      const match = /^(product|security)-aggregates\.json$/.exec(entry);
      if (!match) continue;

      const kind = match[1];
      const filePath = path.join(reportsDir, entry);

      try {
        const data = JSON.parse(fs.readFileSync(filePath, 'utf8'));
        if (data && typeof data === 'object') {
          aggregates[kind] = data;
        }
      } catch (e) {
        // Silently skip corrupted files
      }
    }
  } catch (e) {
    // Silently skip read errors
  }

  return aggregates;
}

export function auditAggregates(home, reports, rules) {
  // Validate and aggregate multiple reports, returning { [kind]: aggregateData, errors: [] }
  // Each report is validated; aggregation combines those that pass.
  const aggregates = {};
  const errors = [];

  for (const report of reports) {
    if (typeof report !== 'object' || !report.content) {
      errors.push({ report, reason: 'invalid-report' });
      continue;
    }

    // Validate the report markdown
    const validated = validateReport(report.content, rules, report.kind);
    if (!validated.ok) {
      errors.push({ report: report.name || 'unknown', reason: 'validation-failed', problems: validated.problems });
      continue;
    }

    // Determine kind
    const kind = report.kind || (report.name ? report.name.split('-')[0] : 'product');
    if (!['product', 'security'].includes(kind)) {
      errors.push({ report: report.name || 'unknown', reason: 'unknown-kind' });
      continue;
    }

    // Aggregate
    if (!aggregates[kind]) aggregates[kind] = {};
    const agg = aggregateReport(report.content, report.kind);
    if (agg) {
      // Merge aggregates (overwrite or accumulate)
      Object.assign(aggregates[kind], agg);
    }
  }

  return { aggregates, errors };
}

export function persistAggregates(home, kind, aggregateData) {
  // Save aggregates to ~/.blackbrake/reports/<kind>-aggregates.json with secure permissions.
  if (!validateAggregateKey(kind)) {
    throw new TypeError(`Invalid aggregate kind: ${kind}`);
  }

  const reportsDir = path.join(home, '.blackbrake', 'reports');
  const filePath = path.join(reportsDir, `${kind}-aggregates.json`);

  try {
    fs.mkdirSync(reportsDir, { recursive: true });
  } catch (e) {
    throw new Error(`Cannot create reports directory: ${e.message}`);
  }

  try {
    fs.writeFileSync(filePath, JSON.stringify(aggregateData, null, 2), { mode: 0o600 });
    return { ok: true, path: filePath };
  } catch (e) {
    throw new Error(`Cannot write aggregates: ${e.message}`);
  }
}

export function loadAggregate(home, kind) {
  // Load a single aggregate or return empty object.
  if (!validateAggregateKey(kind)) return {};

  const filePath = path.join(home, '.blackbrake', 'reports', `${kind}-aggregates.json`);

  try {
    const data = JSON.parse(fs.readFileSync(filePath, 'utf8'));
    return data && typeof data === 'object' ? data : {};
  } catch (e) {
    return {};
  }
}

export function deleteAggregates(home, kind) {
  // Delete the aggregate file for a kind.
  if (!validateAggregateKey(kind)) {
    return { ok: false, reason: 'invalid-key' };
  }

  const filePath = path.join(home, '.blackbrake', 'reports', `${kind}-aggregates.json`);

  try {
    fs.unlinkSync(filePath);
    return { ok: true };
  } catch (e) {
    if (e.code === 'ENOENT') return { ok: true }; // Already gone
    return { ok: false, reason: 'delete-failed', error: e.message };
  }
}
