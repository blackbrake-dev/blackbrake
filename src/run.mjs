// Reads every transcript once and feeds each record to all analyzers.
import { describeFile, readTranscript } from './transcripts.mjs';

export async function runAnalyzers({ root, files, analyzers }) {
  for (const file of files) {
    const info = { file, ...describeFile(root, file) };
    for (const a of analyzers) a.onFile(info);
    for await (const { record } of readTranscript(file)) {
      for (const a of analyzers) a.onRecord(record);
    }
  }
  return analyzers.map((a) => a.finish());
}
