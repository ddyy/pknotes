import { env } from 'cloudflare:test';
import { app } from './index';
import { b64uEncode, signToken, type SessionPayload } from './session';

// The rotation/session concurrency logic operates on opaque key blobs, so tests
// craft valid-shaped (but meaningless) material and directly-signed cookies —
// no WebAuthn ceremony required.

export const SECRET = 'test-secret-not-a-real-key';

let seq = 0;
/** A distinct, valid base64url blob (the server b64-decodes some of these). */
export function blob(tag = 'x'): string {
  seq += 1;
  const bytes = new Uint8Array(33);
  bytes[0] = seq & 0xff;
  bytes[1] = (seq >> 8) & 0xff;
  bytes.fill(tag.charCodeAt(0) & 0xff, 2);
  return b64uEncode(bytes);
}

export async function cookie(userId: string, opts: Partial<SessionPayload> = {}): Promise<string> {
  const nowS = Math.floor(Date.now() / 1000);
  const row = await env.DB.prepare('SELECT session_epoch FROM users WHERE id = ?')
    .bind(userId)
    .first<{ session_epoch: number }>();
  const payload: SessionPayload = {
    sub: userId,
    scope: 'session',
    exp: nowS + 3600,
    epoch: row?.session_epoch ?? 0,
    iat: nowS,
    ...opts,
  };
  return `pknotes_sess=${await signToken(payload, SECRET)}`;
}

export async function req(path: string, cookieHeader: string, body: unknown): Promise<Response> {
  return app.request(
    path,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Cookie: cookieHeader },
      body: JSON.stringify(body),
    },
    env,
  );
}

/** Seed a user with one credential and N notes; returns ids + versions. */
export async function seedUser(noteCount: number): Promise<{
  userId: string;
  credentialId: string;
  notes: { id: string; version: number }[];
}> {
  const userId = crypto.randomUUID();
  const credentialId = crypto.randomUUID();
  const ts = Math.floor(Date.now() / 1000);
  await env.DB.batch([
    env.DB.prepare('INSERT INTO users (id, username, created_at) VALUES (?, ?, ?)').bind(
      userId,
      'u' + userId.slice(0, 8),
      ts,
    ),
    env.DB.prepare(
      'INSERT INTO credentials (id, user_id, public_key, counter, transports, wrapped_mk, prf_salt, created_at) VALUES (?, ?, ?, 0, ?, ?, ?, ?)',
    ).bind(credentialId, userId, blob('pk'), '[]', blob('mk'), blob('salt'), ts),
  ]);
  const notes: { id: string; version: number }[] = [];
  for (let i = 0; i < noteCount; i++) {
    const id = crypto.randomUUID();
    await env.DB.prepare(
      'INSERT INTO notes (id, user_id, ciphertext, version, created_at, updated_at) VALUES (?, ?, ?, 1, ?, ?)',
    )
      .bind(id, userId, blob('ct'), ts, ts)
      .run();
    notes.push({ id, version: 1 });
  }
  return { userId, credentialId, notes };
}

export async function noteRow(id: string): Promise<{
  ciphertext: string;
  version: number;
  pending: string | null;
} | null> {
  return env.DB.prepare('SELECT ciphertext, version, pending_ciphertext AS pending FROM notes WHERE id = ?')
    .bind(id)
    .first();
}
