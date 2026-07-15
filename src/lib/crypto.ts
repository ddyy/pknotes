// All encryption happens in this module, entirely client-side. The server
// only ever receives: wrapped (encrypted) master keys, note ciphertext, and
// the recovery verifier. It can never derive the master key from any of them.

const enc = new TextEncoder();
const dec = new TextDecoder();

// Fixed PRF evaluation input. The PRF output is keyed per-credential inside
// the authenticator, so a shared app-level input is safe — and it's what lets
// usernameless login work (no per-credential salt lookup needed before get()).
export const APP_PRF_SALT = enc.encode('pknotes/prf-eval/v1');

export function b64uEncode(bytes: Uint8Array): string {
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function b64uDecode(str: string): Uint8Array {
  const bin = atob(str.replace(/-/g, '+').replace(/_/g, '/'));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function randomBytes(n: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(n));
}

async function hkdf(ikm: Uint8Array, salt: string, info: string): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey('raw', ikm as BufferSource, 'HKDF', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: enc.encode(salt), info: enc.encode(info) },
    key,
    256,
  );
  return new Uint8Array(bits);
}

async function importAesKey(raw: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey('raw', raw as BufferSource, 'AES-GCM', false, ['encrypt', 'decrypt']);
}

async function aesEncrypt(key: CryptoKey, plaintext: Uint8Array, aad?: Uint8Array): Promise<string> {
  const iv = randomBytes(12);
  const params: AesGcmParams = { name: 'AES-GCM', iv: iv as BufferSource };
  if (aad) params.additionalData = aad as BufferSource;
  const ct = new Uint8Array(await crypto.subtle.encrypt(params, key, plaintext as BufferSource));
  const out = new Uint8Array(iv.length + ct.length);
  out.set(iv);
  out.set(ct, iv.length);
  return b64uEncode(out);
}

async function aesDecrypt(key: CryptoKey, blob: string, aad?: Uint8Array): Promise<Uint8Array> {
  const data = b64uDecode(blob);
  const iv = data.slice(0, 12);
  const ct = data.slice(12);
  const params: AesGcmParams = { name: 'AES-GCM', iv: iv as BufferSource };
  if (aad) params.additionalData = aad as BufferSource;
  return new Uint8Array(await crypto.subtle.decrypt(params, key, ct as BufferSource));
}

// ---------- Master key ----------

export function generateMasterKeyBytes(): Uint8Array {
  return randomBytes(32);
}

export async function importMasterKey(raw: Uint8Array): Promise<CryptoKey> {
  return importAesKey(raw);
}

/** Derive the key-encryption key from a passkey's PRF output. */
export async function kekFromPrf(prfOutput: ArrayBuffer): Promise<CryptoKey> {
  return importAesKey(await hkdf(new Uint8Array(prfOutput), 'pknotes/kek/v1', 'passkey-kek'));
}

export async function wrapMasterKey(kek: CryptoKey, masterKey: Uint8Array): Promise<string> {
  return aesEncrypt(kek, masterKey);
}

export async function unwrapMasterKey(kek: CryptoKey, wrapped: string): Promise<Uint8Array> {
  return aesDecrypt(kek, wrapped);
}

// ---------- Notes ----------

// The note id is bound to the ciphertext as AES-GCM additional data, so a
// malicious server can't swap ciphertexts between notes undetected. (It can
// still replay an older version of the same note — detecting that would need
// client-side version state.)
function noteAad(noteId: string): Uint8Array {
  return enc.encode(`pknotes/note/v1:${noteId}`);
}

export async function encryptNote(masterKey: CryptoKey, markdown: string, noteId: string): Promise<string> {
  return aesEncrypt(masterKey, enc.encode(markdown), noteAad(noteId));
}

export async function decryptNote(masterKey: CryptoKey, ciphertext: string, noteId: string): Promise<string> {
  try {
    return dec.decode(await aesDecrypt(masterKey, ciphertext, noteAad(noteId)));
  } catch {
    // Blobs written before AAD binding have no additional data; they get
    // rewritten in the bound format on their next save (or on key rotation).
    return dec.decode(await aesDecrypt(masterKey, ciphertext));
  }
}

// ---------- Recovery codes ----------
// 160 bits of entropy, base32-encoded as 8 groups of 4 (e.g. A3F9-KM2P-...).
// High entropy means HKDF is sufficient — no slow password hashing needed.

const B32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

function base32Encode(bytes: Uint8Array): string {
  let bits = 0;
  let value = 0;
  let out = '';
  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += B32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += B32_ALPHABET[(value << (5 - bits)) & 31];
  return out;
}

function base32Decode(str: string): Uint8Array {
  let bits = 0;
  let value = 0;
  const out: number[] = [];
  for (const ch of str) {
    const idx = B32_ALPHABET.indexOf(ch);
    if (idx < 0) throw new Error('Invalid recovery code');
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return new Uint8Array(out);
}

export function generateRecoveryCode(): string {
  const raw = base32Encode(randomBytes(20));
  return raw.match(/.{1,4}/g)!.join('-');
}

function recoveryCodeBytes(code: string): Uint8Array {
  const cleaned = code.toUpperCase().replace(/[^A-Z2-7]/g, '');
  if (cleaned.length !== 32) throw new Error('Recovery code should be 32 characters (8 groups of 4)');
  return base32Decode(cleaned);
}

/**
 * Derive both halves from a recovery code: the KEK (stays client-side, unwraps
 * the master key) and the verifier (sent to the server, which stores only its
 * hash). Knowing the verifier does not reveal the KEK.
 */
export async function recoveryKeysFromCode(code: string): Promise<{ kek: CryptoKey; verifier: string }> {
  const bytes = recoveryCodeBytes(code);
  const kekBytes = await hkdf(bytes, 'pknotes/recovery/v1', 'kek');
  const verifierBytes = await hkdf(bytes, 'pknotes/recovery/v1', 'verifier');
  return { kek: await importAesKey(kekBytes), verifier: b64uEncode(verifierBytes) };
}
