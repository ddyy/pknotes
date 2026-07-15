import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  b64uDecode,
  b64uEncode,
  decryptNote,
  encryptNote,
  generateMasterKeyBytes,
  generateRecoveryCode,
  importMasterKey,
  kekFromPrf,
  recoveryKeysFromCode,
  unwrapMasterKey,
  wrapMasterKey,
} from '../src/lib/crypto.ts';

const enc = new TextEncoder();

test('master key wrap/unwrap round trip', async () => {
  const prf = crypto.getRandomValues(new Uint8Array(32));
  const kek = await kekFromPrf(prf.buffer);
  const mk = generateMasterKeyBytes();
  const unwrapped = await unwrapMasterKey(kek, await wrapMasterKey(kek, mk));
  assert.deepEqual(unwrapped, mk);
});

test('unwrap with a different PRF output fails', async () => {
  const kekA = await kekFromPrf(crypto.getRandomValues(new Uint8Array(32)).buffer);
  const kekB = await kekFromPrf(crypto.getRandomValues(new Uint8Array(32)).buffer);
  const wrapped = await wrapMasterKey(kekA, generateMasterKeyBytes());
  await assert.rejects(unwrapMasterKey(kekB, wrapped));
});

test('note encrypt/decrypt round trip', async () => {
  const key = await importMasterKey(generateMasterKeyBytes());
  const id = crypto.randomUUID();
  const text = '# Hello\n\nSome *markdown* — with unicode: café, 日本語, 🎉';
  assert.equal(await decryptNote(key, await encryptNote(key, text, id), id), text);
});

test('ciphertext bound to another note id is rejected (AAD)', async () => {
  const key = await importMasterKey(generateMasterKeyBytes());
  const ct = await encryptNote(key, 'secret plans', crypto.randomUUID());
  await assert.rejects(decryptNote(key, ct, crypto.randomUUID()));
});

test('tampered ciphertext is rejected', async () => {
  const key = await importMasterKey(generateMasterKeyBytes());
  const id = crypto.randomUUID();
  const blob = b64uDecode(await encryptNote(key, 'integrity matters', id));
  blob[blob.length - 1] ^= 0x01;
  await assert.rejects(decryptNote(key, b64uEncode(blob), id));
});

test('legacy blob without AAD still decrypts (fallback)', async () => {
  const mk = generateMasterKeyBytes();
  const key = await importMasterKey(mk);
  // Independently build a pre-AAD blob: iv || AES-GCM ciphertext, no additionalData.
  const legacyKey = await crypto.subtle.importKey('raw', mk, 'AES-GCM', false, ['encrypt']);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(
    await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, legacyKey, enc.encode('written before AAD')),
  );
  const blob = new Uint8Array(iv.length + ct.length);
  blob.set(iv);
  blob.set(ct, iv.length);
  assert.equal(await decryptNote(key, b64uEncode(blob), crypto.randomUUID()), 'written before AAD');
});

test('recovery code has the documented shape', () => {
  const code = generateRecoveryCode();
  assert.match(code, /^([A-Z2-7]{4}-){7}[A-Z2-7]{4}$/);
  assert.notEqual(code, generateRecoveryCode());
});

test('recovery derivation is deterministic and normalizes formatting', async () => {
  const code = generateRecoveryCode();
  const a = await recoveryKeysFromCode(code);
  const b = await recoveryKeysFromCode(code.toLowerCase().replaceAll('-', ' '));
  assert.equal(a.verifier, b.verifier);
  const mk = generateMasterKeyBytes();
  assert.deepEqual(await unwrapMasterKey(b.kek, await wrapMasterKey(a.kek, mk)), mk);
});

test('different recovery codes derive different verifiers', async () => {
  const a = await recoveryKeysFromCode(generateRecoveryCode());
  const b = await recoveryKeysFromCode(generateRecoveryCode());
  assert.notEqual(a.verifier, b.verifier);
});

test('malformed recovery codes are rejected', async () => {
  await assert.rejects(recoveryKeysFromCode('too-short'));
  await assert.rejects(recoveryKeysFromCode('1111-1111-1111-1111-1111-1111-1111-1111')); // 0/1 not in base32
});
