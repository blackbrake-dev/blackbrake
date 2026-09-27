// Which Claude Code version wrote the most recent transcript line (each line records it).
export function createVersionAnalyzer() {
  let latest = null;

  return {
    onFile() {},
    onRecord(record) {
      const version = /^\d+\.\d+\.\d+/.exec(String(record.version ?? ''))?.[0];
      const ts = Date.parse(record.timestamp ?? '');

      if (!version || !Number.isFinite(ts)) return;

      if (!latest || ts > latest.ts) latest = { ts, version };
    },
    finish() {
      return latest ? { version: latest.version, seen: new Date(latest.ts).toISOString().slice(0, 10) } : null;
    },
  };
}
