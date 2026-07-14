import { Hono } from 'hono';
import type { Context } from 'hono';
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from '@simplewebauthn/server';
import type {
  AuthenticationResponseJSON,
  AuthenticatorTransportFuture,
  RegistrationResponseJSON,
} from '@simplewebauthn/server';
import { isoBase64URL } from '@simplewebauthn/server/helpers';
import {
  type AppEnv,
  b64uDecode,
  b64uEncode,
  clearSessionCookie,
  readChallengeCookie,
  requireAuth,
  setChallengeCookie,
  setSessionCookie,
} from './session';

const RP_NAME = 'pknotes';
const USERNAME_RE = /^[a-zA-Z0-9._-]{3,32}$/;
// Wrapped master key: 12-byte IV + 32-byte key + 16-byte GCM tag, base64url ≈ 80 chars.
const MAX_WRAPPED_KEY_LEN = 256;

interface CredentialRow {
  id: string;
  user_id: string;
  public_key: string;
  counter: number;
  transports: string | null;
  wrapped_mk: string;
  prf_salt: string;
  username?: string;
}

export const auth = new Hono<AppEnv>();

function rp(c: Context<AppEnv>) {
  const url = new URL(c.req.url);
  return { rpID: url.hostname, origin: url.origin };
}

function now() {
  return Math.floor(Date.now() / 1000);
}

function isValidKeyBlob(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0 && value.length <= MAX_WRAPPED_KEY_LEN;
}

function parseTransports(raw: string | null): AuthenticatorTransportFuture[] {
  try {
    return raw ? (JSON.parse(raw) as AuthenticatorTransportFuture[]) : [];
  } catch {
    return [];
  }
}

// ---------- Registration ----------

auth.post('/register/options', async (c) => {
  const { username } = await c.req.json<{ username?: string }>().catch(() => ({ username: undefined }));
  if (!username || !USERNAME_RE.test(username)) {
    return c.json({ error: 'Username must be 3-32 characters (letters, digits, . _ -)' }, 400);
  }
  const existing = await c.env.DB.prepare('SELECT id FROM users WHERE username = ?').bind(username).first();
  if (existing) return c.json({ error: 'Username already taken' }, 409);

  const userId = crypto.randomUUID();
  const options = await generateRegistrationOptions({
    rpName: RP_NAME,
    rpID: rp(c).rpID,
    userName: username,
    userID: new Uint8Array(new TextEncoder().encode(userId)),
    attestationType: 'none',
    authenticatorSelection: { residentKey: 'required', userVerification: 'required' },
  });
  await setChallengeCookie(c, { challenge: options.challenge, username, userId });
  return c.json(options);
});

auth.post('/register/verify', async (c) => {
  const body = await c.req.json<{ response: RegistrationResponseJSON; prfSalt: string; wrappedMk: string }>();
  if (!isValidKeyBlob(body.prfSalt) || !isValidKeyBlob(body.wrappedMk)) {
    return c.json({ error: 'Missing key material' }, 400);
  }
  const chal = await readChallengeCookie(c);
  if (!chal?.username || !chal.userId) return c.json({ error: 'No pending registration' }, 400);

  const { rpID, origin } = rp(c);
  let verified = false;
  let registrationInfo;
  try {
    const result = await verifyRegistrationResponse({
      response: body.response,
      expectedChallenge: chal.challenge,
      expectedOrigin: origin,
      expectedRPID: rpID,
      requireUserVerification: true,
    });
    verified = result.verified;
    registrationInfo = result.registrationInfo;
  } catch (err) {
    console.log(JSON.stringify({ msg: 'registration verification failed', error: String(err) }));
  }
  if (!verified || !registrationInfo) return c.json({ error: 'Passkey verification failed' }, 400);

  const { credential } = registrationInfo;
  const ts = now();
  try {
    await c.env.DB.batch([
      c.env.DB.prepare('INSERT INTO users (id, username, created_at) VALUES (?, ?, ?)').bind(
        chal.userId,
        chal.username,
        ts,
      ),
      c.env.DB.prepare(
        'INSERT INTO credentials (id, user_id, public_key, counter, transports, wrapped_mk, prf_salt, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
      ).bind(
        credential.id,
        chal.userId,
        isoBase64URL.fromBuffer(credential.publicKey),
        credential.counter,
        JSON.stringify(credential.transports ?? []),
        body.wrappedMk,
        body.prfSalt,
        ts,
      ),
    ]);
  } catch {
    return c.json({ error: 'Username already taken' }, 409);
  }
  await setSessionCookie(c, chal.userId);
  return c.json({ ok: true, username: chal.username });
});

// ---------- Login (usernameless: any resident passkey for this RP) ----------

auth.post('/login/options', async (c) => {
  const options = await generateAuthenticationOptions({ rpID: rp(c).rpID, userVerification: 'required' });
  await setChallengeCookie(c, { challenge: options.challenge });
  return c.json(options);
});

auth.post('/login/verify', async (c) => {
  const { response } = await c.req.json<{ response: AuthenticationResponseJSON }>();
  const chal = await readChallengeCookie(c);
  if (!chal) return c.json({ error: 'No pending login' }, 400);

  const row = await c.env.DB.prepare(
    'SELECT c.*, u.username FROM credentials c JOIN users u ON u.id = c.user_id WHERE c.id = ?',
  )
    .bind(response.id)
    .first<CredentialRow>();
  if (!row) return c.json({ error: 'Unknown passkey' }, 400);

  const { rpID, origin } = rp(c);
  let verified = false;
  let newCounter = row.counter;
  try {
    const result = await verifyAuthenticationResponse({
      response,
      expectedChallenge: chal.challenge,
      expectedOrigin: origin,
      expectedRPID: rpID,
      requireUserVerification: true,
      credential: {
        id: row.id,
        publicKey: isoBase64URL.toBuffer(row.public_key),
        counter: row.counter,
        transports: parseTransports(row.transports),
      },
    });
    verified = result.verified;
    newCounter = result.authenticationInfo.newCounter;
  } catch (err) {
    console.log(JSON.stringify({ msg: 'authentication verification failed', error: String(err) }));
  }
  if (!verified) return c.json({ error: 'Passkey verification failed' }, 400);

  await c.env.DB.prepare('UPDATE credentials SET counter = ? WHERE id = ?').bind(newCounter, row.id).run();
  await setSessionCookie(c, row.user_id);
  return c.json({
    username: row.username,
    credentialId: row.id,
    wrappedMk: row.wrapped_mk,
    prfSalt: row.prf_salt,
  });
});

// ---------- Recovery ----------

// Store the recovery-wrapped master key (called right after registration).
auth.post('/recovery/setup', requireAuth(['session']), async (c) => {
  const { verifier, wrappedMk } = await c.req.json<{ verifier: string; wrappedMk: string }>();
  if (!isValidKeyBlob(verifier) || !isValidKeyBlob(wrappedMk)) {
    return c.json({ error: 'Missing key material' }, 400);
  }
  const hash = new Uint8Array(await crypto.subtle.digest('SHA-256', b64uDecode(verifier)));
  await c.env.DB.prepare(
    'INSERT OR REPLACE INTO recovery (user_id, verifier_hash, wrapped_mk, created_at) VALUES (?, ?, ?, ?)',
  )
    .bind(c.get('userId'), b64uEncode(hash), wrappedMk, now())
    .run();
  return c.json({ ok: true });
});

// Redeem a recovery code: returns the recovery-wrapped master key and a
// short-lived recovery session that only permits registering a new passkey.
auth.post('/recovery/redeem', async (c) => {
  const { username, verifier } = await c.req.json<{ username: string; verifier: string }>();
  if (typeof username !== 'string' || !isValidKeyBlob(verifier)) {
    return c.json({ error: 'Invalid request' }, 400);
  }
  const row = await c.env.DB.prepare(
    'SELECT r.user_id, r.verifier_hash, r.wrapped_mk FROM recovery r JOIN users u ON u.id = r.user_id WHERE u.username = ?',
  )
    .bind(username)
    .first<{ user_id: string; verifier_hash: string; wrapped_mk: string }>();

  const provided = new Uint8Array(await crypto.subtle.digest('SHA-256', b64uDecode(verifier)));
  // Compare against a dummy when the user doesn't exist so both paths do the same work.
  const stored = row ? b64uDecode(row.verifier_hash) : new Uint8Array(32);
  const match = stored.length === provided.length && crypto.subtle.timingSafeEqual(stored, provided);
  if (!row || !match) return c.json({ error: 'Invalid username or recovery code' }, 400);

  await setSessionCookie(c, row.user_id, 'recovery');
  return c.json({ wrappedMk: row.wrapped_mk });
});

// ---------- Add a passkey (new device, or re-establishing after recovery) ----------

auth.post('/credentials/options', requireAuth(['session', 'recovery']), async (c) => {
  const userId = c.get('userId');
  const user = await c.env.DB.prepare('SELECT username FROM users WHERE id = ?')
    .bind(userId)
    .first<{ username: string }>();
  if (!user) return c.json({ error: 'Unauthorized' }, 401);
  const existing = await c.env.DB.prepare('SELECT id, transports FROM credentials WHERE user_id = ?')
    .bind(userId)
    .all<{ id: string; transports: string | null }>();

  const options = await generateRegistrationOptions({
    rpName: RP_NAME,
    rpID: rp(c).rpID,
    userName: user.username,
    userID: new Uint8Array(new TextEncoder().encode(userId)),
    attestationType: 'none',
    authenticatorSelection: { residentKey: 'required', userVerification: 'required' },
    excludeCredentials: existing.results.map((cred) => ({
      id: cred.id,
      transports: parseTransports(cred.transports),
    })),
  });
  await setChallengeCookie(c, { challenge: options.challenge, userId });
  return c.json(options);
});

auth.post('/credentials/verify', requireAuth(['session', 'recovery']), async (c) => {
  const body = await c.req.json<{ response: RegistrationResponseJSON; prfSalt: string; wrappedMk: string }>();
  if (!isValidKeyBlob(body.prfSalt) || !isValidKeyBlob(body.wrappedMk)) {
    return c.json({ error: 'Missing key material' }, 400);
  }
  const chal = await readChallengeCookie(c);
  const userId = c.get('userId');
  if (!chal || chal.userId !== userId) return c.json({ error: 'No pending passkey registration' }, 400);

  const { rpID, origin } = rp(c);
  let verified = false;
  let registrationInfo;
  try {
    const result = await verifyRegistrationResponse({
      response: body.response,
      expectedChallenge: chal.challenge,
      expectedOrigin: origin,
      expectedRPID: rpID,
      requireUserVerification: true,
    });
    verified = result.verified;
    registrationInfo = result.registrationInfo;
  } catch (err) {
    console.log(JSON.stringify({ msg: 'add-credential verification failed', error: String(err) }));
  }
  if (!verified || !registrationInfo) return c.json({ error: 'Passkey verification failed' }, 400);

  const { credential } = registrationInfo;
  await c.env.DB.prepare(
    'INSERT INTO credentials (id, user_id, public_key, counter, transports, wrapped_mk, prf_salt, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
  )
    .bind(
      credential.id,
      userId,
      isoBase64URL.fromBuffer(credential.publicKey),
      credential.counter,
      JSON.stringify(credential.transports ?? []),
      body.wrappedMk,
      body.prfSalt,
      now(),
    )
    .run();
  // Upgrade a recovery session to a full one now that a passkey exists again.
  await setSessionCookie(c, userId);
  return c.json({ ok: true });
});

// ---------- Session ----------

auth.get('/me', requireAuth(['session']), async (c) => {
  const user = await c.env.DB.prepare('SELECT username FROM users WHERE id = ?')
    .bind(c.get('userId'))
    .first<{ username: string }>();
  if (!user) return c.json({ error: 'Unauthorized' }, 401);
  return c.json({ username: user.username });
});

auth.post('/logout', (c) => {
  clearSessionCookie(c);
  return c.json({ ok: true });
});
