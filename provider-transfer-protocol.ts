/** Pure offset parsers shared by provider adapters and tests; offsets are exclusive byte positions. */
export function parseOneDriveNextOffset(ranges: unknown, totalBytes: number, fallback = 0): number {
  if (!Array.isArray(ranges) || ranges.length === 0) return fallback;
  const match = String(ranges[0]).match(/^(\d+)-/);
  if (!match) throw new Error('OneDrive returned an invalid nextExpectedRanges value');
  const offset = Number(match[1]);
  if (!Number.isSafeInteger(offset) || offset < 0 || offset > totalBytes) throw new Error('OneDrive returned an out-of-range nextExpectedRanges offset');
  return offset;
}

export function parseGoogleRangeOffset(rangeHeader: unknown, totalBytes: number): number {
  if (rangeHeader == null || rangeHeader === '') return 0;
  if (typeof rangeHeader !== 'string') throw new Error('Google Drive returned a non-string Range acknowledgement');
  const match = rangeHeader.match(/^bytes=0-(\d+)$/);
  if (!match) throw new Error('Google Drive returned an invalid Range acknowledgement');
  const offset = Number(match[1]) + 1;
  if (!Number.isSafeInteger(offset) || offset < 0 || offset > totalBytes) throw new Error('Google Drive returned an out-of-range Range offset');
  return offset;
}


/** Per-process FIFO mutex. Rejected operations do not poison the queue. */
const sessionQueues = new Map<string, Promise<unknown>>();
export async function withSessionLock<T>(sessionId: string, operation: () => Promise<T>): Promise<T> {
  const previous = sessionQueues.get(sessionId) || Promise.resolve();
  let release!: () => void;
  const gate = new Promise<void>(resolve => { release = resolve; });
  const queued = previous.catch(() => undefined).then(() => gate);
  sessionQueues.set(sessionId, queued);
  await previous.catch(() => undefined);
  try { return await operation(); }
  finally { release(); if (sessionQueues.get(sessionId) === queued) sessionQueues.delete(sessionId); }
}

export function chunkSha256(data: Uint8Array): string {
  // Runtime-neutral deterministic FNV-1a digest for protocol bookkeeping; production callers
  // should persist a cryptographic SHA-256 digest computed by node:crypto.
  let hash = 2166136261;
  for (const byte of data) hash = Math.imul(hash ^ byte, 16777619);
  return (hash >>> 0).toString(16).padStart(8, '0');
}
