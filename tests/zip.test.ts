import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildZip } from '../src/lib/zip.ts';

async function bytes(blob: Blob): Promise<Uint8Array> {
  return new Uint8Array(await blob.arrayBuffer());
}

function readU32(buf: Uint8Array, at: number): number {
  return new DataView(buf.buffer, buf.byteOffset + at, 4).getUint32(0, true);
}

test('zip structure: signatures, entry count, terminator', async () => {
  const now = Math.floor(Date.now() / 1000);
  const buf = await bytes(
    buildZip([
      { name: 'a.md', content: '# Note A', mtime: now },
      { name: 'b.md', content: 'unicode café 日本語', mtime: now },
    ]),
  );
  assert.equal(readU32(buf, 0), 0x04034b50); // first local file header
  const eocdAt = buf.length - 22;
  assert.equal(readU32(buf, eocdAt), 0x06054b50); // end of central directory
  const entryCount = buf[eocdAt + 10] | (buf[eocdAt + 11] << 8);
  assert.equal(entryCount, 2);
  // Central directory offset in EOCD points at a central header signature.
  const cdOffset = readU32(buf, eocdAt + 16);
  assert.equal(readU32(buf, cdOffset), 0x02014b50);
});

test('zip stores contents verbatim (method 0)', async () => {
  const content = 'stored, not deflated';
  const buf = await bytes(buildZip([{ name: 'n.md', content, mtime: 0 }]));
  const text = new TextDecoder().decode(buf);
  assert.ok(text.includes(content));
  assert.ok(text.includes('n.md'));
});

test('empty archive is still well-formed', async () => {
  const buf = await bytes(buildZip([]));
  assert.equal(buf.length, 22);
  assert.equal(readU32(buf, 0), 0x06054b50);
});
