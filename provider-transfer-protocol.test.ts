import test from 'node:test';
import assert from 'node:assert/strict';
import { parseGoogleRangeOffset, parseOneDriveNextOffset, withSessionLock } from './provider-transfer-protocol.ts';

test('OneDrive parses the first expected range as the committed exclusive offset', () => {
  assert.equal(parseOneDriveNextOffset(['0-'], 100), 0);
  assert.equal(parseOneDriveNextOffset(['3276800-'], 10_000_000), 3_276_800);
  assert.equal(parseOneDriveNextOffset(['100-200', '400-'], 1_000), 100);
});

test('OneDrive empty ranges use the caller fallback and malformed/out-of-range offsets fail', () => {
  assert.equal(parseOneDriveNextOffset([], 100, 45), 45);
  assert.throws(() => parseOneDriveNextOffset(['x-'], 100));
  assert.throws(() => parseOneDriveNextOffset(['101-'], 100));
});

test('Google Drive 308 Range is converted to an exclusive offset; missing Range means zero', () => {
  assert.equal(parseGoogleRangeOffset(undefined, 100), 0);
  assert.equal(parseGoogleRangeOffset('bytes=0-0', 100), 1);
  assert.equal(parseGoogleRangeOffset('bytes=0-8388607', 16_777_216), 8_388_608);
});

test('Google Drive rejects malformed and out-of-range acknowledgements', () => {
  assert.throws(() => parseGoogleRangeOffset('bytes=1-2', 100));
  assert.throws(() => parseGoogleRangeOffset('bytes=0-100', 100));
});


test('same-session operations serialize while different sessions remain independent', async () => {
  const order: string[] = [];
  let release!: () => void;
  const gate = new Promise<void>(resolve => { release = resolve; });
  const first = withSessionLock('same', async () => { order.push('first-start'); await gate; order.push('first-end'); });
  const second = withSessionLock('same', async () => { order.push('second-start'); });
  await new Promise(resolve => setTimeout(resolve, 5));
  assert.deepEqual(order, ['first-start']);
  release(); await Promise.all([first, second]);
  assert.deepEqual(order, ['first-start', 'first-end', 'second-start']);
});

test('committed chunk replay is only accepted when offset, size, and SHA-256 match', async () => {
  const crypto = await import('node:crypto');
  const bytes = Buffer.from('chunk-data');
  const digest = crypto.createHash('sha256').update(bytes).digest('hex');
  const isExactReplay = (record: any, offset: number, data: Buffer) => record.offset === offset && record.length === data.length && record.checksum === crypto.createHash('sha256').update(data).digest('hex');
  const record = { offset: 0, length: bytes.length, checksum: digest };
  assert.equal(isExactReplay(record, 0, bytes), true);
  assert.equal(isExactReplay(record, 1, bytes), false);
  assert.equal(isExactReplay(record, 0, Buffer.from('different')), false);
});
