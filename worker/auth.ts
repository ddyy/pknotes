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
import { rateLimit } from './ratelimit';
import {
  type AppEnv,
  b64uDecode,
  b64uEncode,
  clearSessionCookie,
  readChallengeCookie,
  LIVE_LOCK_SQL,
  NO_ACTIVE_ROTATION_SQL,
  RECENT_AUTH_WINDOW,
  requireAuth,
  ROTATION_LOCK_TTL,
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

const strict = rateLimit((env) => env.STRICT_LIMITER);
const standard = rateLimit((env) => env.AUTH_LIMITER);

// Personal instances can close signup after creating their account:
//   npx wrangler secret put ALLOW_REGISTRATION   (value: false)
// Read as an optional secret rather than a config var so it survives deploys
// and stays out of the committed config.
function registrationClosed(env: Env): boolean {
  return (env as { ALLOW_REGISTRATION?: string }).ALLOW_REGISTRATION === 'false';
}

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

auth.post('/register/options', strict, async (c) => {
  if (registrationClosed(c.env)) return c.json({ error: 'Registration is closed on this instance.' }, 403);
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

auth.post('/register/verify', strict, async (c) => {
  if (registrationClosed(c.env)) return c.json({ error: 'Registration is closed on this instance.' }, 403);
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

auth.post('/login/options', standard, async (c) => {
  const options = await generateAuthenticationOptions({ rpID: rp(c).rpID, userVerification: 'required' });
  await setChallengeCookie(c, { challenge: options.challenge });
  return c.json(options);
});

auth.post('/login/verify', standard, async (c) => {
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
auth.post('/recovery/setup', standard, requireAuth(['session']), async (c) => {
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
// Codes are single-use: the first redemption starts a grace window (so an
// interrupted recovery can retry), after which the code is dead. A completed
// recovery replaces the row with a fresh code via /recovery/setup.
const REDEEM_GRACE = 60 * 10; // matches the recovery session TTL

auth.post('/recovery/redeem', strict, async (c) => {
  const { username, verifier } = await c.req.json<{ username: string; verifier: string }>();
  if (typeof username !== 'string' || !isValidKeyBlob(verifier)) {
    return c.json({ error: 'Invalid request' }, 400);
  }
  const row = await c.env.DB.prepare(
    'SELECT r.user_id, r.verifier_hash, r.wrapped_mk, r.redeemed_at FROM recovery r JOIN users u ON u.id = r.user_id WHERE u.username = ?',
  )
    .bind(username)
    .first<{ user_id: string; verifier_hash: string; wrapped_mk: string; redeemed_at: number | null }>();

  const provided = new Uint8Array(await crypto.subtle.digest('SHA-256', b64uDecode(verifier)));
  // Compare against a dummy when the user doesn't exist so both paths do the same work.
  const stored = row ? b64uDecode(row.verifier_hash) : new Uint8Array(32);
  const match = stored.length === provided.length && crypto.subtle.timingSafeEqual(stored, provided);
  if (!row || !match) return c.json({ error: 'Invalid username or recovery code' }, 400);

  const ts = now();
  if (row.redeemed_at && ts - row.redeemed_at > REDEEM_GRACE) {
    return c.json({ error: 'This recovery code has already been used. Each code works once.' }, 400);
  }
  if (!row.redeemed_at) {
    await c.env.DB.prepare('UPDATE recovery SET redeemed_at = ? WHERE user_id = ?').bind(ts, row.user_id).run();
  }

  await setSessionCookie(c, row.user_id, 'recovery');
  return c.json({ wrappedMk: row.wrapped_mk });
});

// ---------- Add a passkey (new device, or re-establishing after recovery) ----------

auth.post('/credentials/options', standard, requireAuth(['session', 'recovery']), async (c) => {
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

auth.post('/credentials/verify', standard, requireAuth(['session', 'recovery']), async (c) => {
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
  // Refuse while a rotation is active: the new credential would wrap the OLD
  // master key and be silently invalidated by the rotation. Gated in-SQL.
  const added = await c.env.DB.prepare(
    `INSERT INTO credentials (id, user_id, public_key, counter, transports, wrapped_mk, prf_salt, created_at) SELECT ?, ?, ?, ?, ?, ?, ?, ? WHERE ${NO_ACTIVE_ROTATION_SQL}`,
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
      userId,
    )
    .run();
  if (added.meta.changes === 0) {
    return c.json({ error: 'A key rotation is in progress — try again shortly' }, 409);
  }
  // Upgrade a recovery session to a full one now that a passkey exists again.
  await setSessionCookie(c, userId);
  return c.json({ ok: true });
});

// ---------- Passkey management & master key rotation ----------

auth.get('/credentials', requireAuth(['session']), async (c) => {
  const { results } = await c.env.DB.prepare(
    'SELECT id, transports, created_at FROM credentials WHERE user_id = ? ORDER BY created_at ASC',
  )
    .bind(c.get('userId'))
    .all<{ id: string; transports: string | null; created_at: number }>();
  return c.json({
    credentials: results.map((row) => ({
      id: row.id,
      transports: parseTransports(row.transports),
      created_at: row.created_at,
    })),
  });
});

// Removing a credential blocks future logins with it, but a stolen device may
// already hold decrypted data or the master key — full revocation is /rotate.
auth.delete('/credentials/:id', standard, requireAuth(['session']), async (c) => {
  const userId = c.get('userId');
  // Count and delete in one statement so two concurrent deletes can't both
  // pass a separate count check and remove the last two passkeys. Also gated on
  // no active rotation: rotation re-wraps this exact credential set, so a
  // concurrent delete could leave the vault with no key holder.
  const result = await c.env.DB.prepare(
    `DELETE FROM credentials WHERE id = ? AND user_id = ? AND (SELECT COUNT(*) FROM credentials WHERE user_id = ?) > 1 AND ${NO_ACTIVE_ROTATION_SQL}`,
  )
    .bind(c.req.param('id'), userId, userId, userId)
    .run();
  if (result.meta.changes === 0) {
    if (await activeRotationHeld(c, userId)) return c.json({ error: 'A key rotation is in progress — try again shortly' }, 409);
    // Either the credential is gone or it was the last one.
    const remaining = await c.env.DB.prepare('SELECT COUNT(*) AS n FROM credentials WHERE user_id = ?')
      .bind(userId)
      .first<{ n: number }>();
    if (remaining && remaining.n <= 1) return c.json({ error: 'Cannot remove the last passkey' }, 400);
    return c.json({ error: 'Passkey not found' }, 404);
  }
  return c.json({ ok: true });
});

// True if the user holds a live rotation lock (for post-write error messaging).
async function activeRotationHeld(c: Context<AppEnv>, userId: string): Promise<boolean> {
  const row = await c.env.DB.prepare(`SELECT 1 FROM users WHERE id = ? AND ${LIVE_LOCK_SQL}`).bind(userId).first();
  return !!row;
}

// Rotate the master key: the client re-encrypts every note under a fresh key
// and re-wraps it for the ONE passkey it is holding (wrapping for others is
// impossible — their KEKs only exist during a ceremony on those devices), so
// all other credentials are deleted and the recovery code is replaced. This
// is the real revocation path after a device compromise.
//
// The protocol is staged so it stays correct at any vault size and can't
// half-apply a key:
//   begin  — validate the note set is complete (no note can be orphaned) and
//            clear any stale staging.
//   stage  — upload re-encrypted ciphertext into notes.pending_ciphertext in
//            chunks; the live ciphertext (old key) stays readable throughout.
//   commit — verify every note is staged and unchanged, then ONE atomic batch
//            swaps pending→live, replaces the keys, deletes other credentials,
//            and bumps session_epoch (revoking other devices).
// A single D1 batch is capped by the per-invocation query limit (50 Free), so
// the bulk work happens in stage (chunked, non-atomic, but harmless — it only
// writes the staging column) and commit is a handful of statements.
// Bounded so the whole begin→stage→commit sequence completes well inside the
// lease and recent-auth windows: 2000 notes is ~50 stage requests of 40.
const MAX_ROTATE_NOTES = 2_000;
const ROTATE_STAGE_CHUNK = 40; // keep each stage batch under the Free query limit

// Sensitive credential/recovery operations must be backed by a recent
// authentication, not just any live session cookie.
function requireRecentAuth(c: Context<AppEnv>): boolean {
  return now() - c.get('authIat') <= RECENT_AUTH_WINDOW;
}

// The active rotation id if the user currently holds a live (non-expired) lock.
// Freshness uses DB time so it can't disagree with the in-SQL write guards.
async function activeRotation(c: Context<AppEnv>, userId: string): Promise<string | null> {
  const row = await c.env.DB.prepare(`SELECT active_rotation FROM users WHERE id = ? AND ${LIVE_LOCK_SQL}`)
    .bind(userId)
    .first<{ active_rotation: string }>();
  return row?.active_rotation ?? null;
}

auth.post('/rotate/begin', standard, requireAuth(['session']), async (c) => {
  if (!requireRecentAuth(c)) return c.json({ error: 'Re-authenticate before rotating' }, 401);
  const body = await c.req
    .json<{ credentialId: string; notes: { id: string; version: number }[] }>()
    .catch(() => null);
  if (
    !body ||
    typeof body.credentialId !== 'string' ||
    !Array.isArray(body.notes) ||
    body.notes.length > MAX_ROTATE_NOTES ||
    body.notes.some((n) => typeof n.id !== 'string' || typeof n.version !== 'number')
  ) {
    return c.json({ error: 'Invalid rotation payload' }, 400);
  }
  const userId = c.get('userId');

  const cred = await c.env.DB.prepare('SELECT id FROM credentials WHERE id = ? AND user_id = ?')
    .bind(body.credentialId, userId)
    .first();
  if (!cred) return c.json({ error: 'Unknown passkey' }, 400);

  // Acquire the per-user rotation lock atomically, all in DB time. The UPDATE
  // only succeeds if no live lock is held (or the prior one expired), so a
  // second concurrent rotation is refused here and note writes are blocked for
  // the lock's duration.
  const rotationId = crypto.randomUUID();
  const acquired = await c.env.DB.prepare(
    `UPDATE users SET active_rotation = ?, rotation_started = unixepoch() WHERE id = ? AND (active_rotation IS NULL OR rotation_started <= unixepoch() - ${ROTATION_LOCK_TTL})`,
  )
    .bind(rotationId, userId)
    .run();
  if (acquired.meta.changes === 0) {
    return c.json({ error: 'A rotation is already in progress — try again shortly' }, 409);
  }

  // With the lock held, validate the client's note set against the DB: exact id
  // set AND version equality. A version mismatch means another device changed a
  // note since this client loaded it, so the client's plaintext is stale —
  // reject rather than relabel stale text with the current version. On any
  // mismatch, release the lock so the client can re-fetch and retry.
  const { results: current } = await c.env.DB.prepare('SELECT id, version FROM notes WHERE user_id = ?')
    .bind(userId)
    .all<{ id: string; version: number }>();
  const dbVersion = new Map(current.map((r) => [r.id, r.version]));
  const clientVersion = new Map(body.notes.map((n) => [n.id, n.version]));
  const consistent =
    current.length === body.notes.length && [...dbVersion].every(([id, v]) => clientVersion.get(id) === v);
  if (!consistent) {
    await releaseLock(c, userId, rotationId);
    return c.json({ error: 'Notes changed during rotation — try again' }, 409);
  }

  // Clear staging from any abandoned prior attempt (belt-and-braces; this
  // rotation tags its own rows).
  await c.env.DB.prepare(
    'UPDATE notes SET pending_ciphertext = NULL, pending_rotation = NULL WHERE user_id = ?',
  )
    .bind(userId)
    .run();
  return c.json({ ok: true, rotationId });
});

// Release the lock only if we still own it (defensive against a reclaimed lock).
async function releaseLock(c: Context<AppEnv>, userId: string, rotationId: string): Promise<void> {
  await c.env.DB.prepare(
    'UPDATE users SET active_rotation = NULL, rotation_started = NULL WHERE id = ? AND active_rotation = ?',
  )
    .bind(userId, rotationId)
    .run();
}

auth.post('/rotate/stage', standard, requireAuth(['session']), async (c) => {
  if (!requireRecentAuth(c)) return c.json({ error: 'Re-authenticate before rotating' }, 401);
  const body = await c.req
    .json<{ rotationId: string; notes: { id: string; ciphertext: string; version: number }[] }>()
    .catch(() => null);
  if (
    !body ||
    typeof body.rotationId !== 'string' ||
    !Array.isArray(body.notes) ||
    body.notes.length === 0 ||
    body.notes.length > ROTATE_STAGE_CHUNK ||
    body.notes.some(
      (n) =>
        typeof n.id !== 'string' ||
        typeof n.ciphertext !== 'string' ||
        n.ciphertext.length === 0 ||
        n.ciphertext.length > 1_000_000 ||
        typeof n.version !== 'number',
    )
  ) {
    return c.json({ error: 'Invalid rotation payload' }, 400);
  }
  const userId = c.get('userId');
  // Guarded renewal IS the authoritative freshness check: verify a live lease
  // for this rotation and refresh it in one atomic statement. A separate
  // check-then-renew could revive a lease that expired in between — letting a
  // concurrent note write land and its stale pending ciphertext survive to
  // commit. Zero rows means the lease is gone; abort before staging.
  const renewed = await c.env.DB.prepare(
    `UPDATE users SET rotation_started = unixepoch() WHERE id = ? AND active_rotation = ? AND rotation_started > unixepoch() - ${ROTATION_LOCK_TTL}`,
  )
    .bind(userId, body.rotationId)
    .run();
  if ((renewed.meta.changes ?? 0) === 0) {
    return c.json({ error: 'Rotation is no longer active — try again' }, 409);
  }
  // Stage ciphertext tagged with THIS rotation id, pinned to the version the
  // client validated at begin. Tagging prevents a concurrent rotation from
  // committing this ciphertext under a different key.
  const results = await c.env.DB.batch(
    body.notes.map((n) =>
      c.env.DB.prepare(
        'UPDATE notes SET pending_ciphertext = ?, pending_rotation = ? WHERE id = ? AND user_id = ? AND version = ?',
      ).bind(n.ciphertext, body.rotationId, n.id, userId, n.version),
    ),
  );
  const staged = results.reduce((sum, r) => sum + (r.meta.changes ?? 0), 0);
  return c.json({ staged });
});

auth.post('/rotate/commit', standard, requireAuth(['session']), async (c) => {
  if (!requireRecentAuth(c)) return c.json({ error: 'Re-authenticate before rotating' }, 401);
  const body = await c.req
    .json<{
      rotationId: string;
      credentialId: string;
      wrappedMk: string;
      recovery: { verifier: string; wrappedMk: string };
    }>()
    .catch(() => null);
  if (
    !body ||
    typeof body.rotationId !== 'string' ||
    typeof body.credentialId !== 'string' ||
    !isValidKeyBlob(body.wrappedMk) ||
    !isValidKeyBlob(body.recovery?.verifier) ||
    !isValidKeyBlob(body.recovery?.wrappedMk)
  ) {
    return c.json({ error: 'Invalid rotation payload' }, 400);
  }
  const userId = c.get('userId');
  if ((await activeRotation(c, userId)) !== body.rotationId) {
    return c.json({ error: 'Rotation is no longer active — try again' }, 409);
  }

  const cred = await c.env.DB.prepare('SELECT id FROM credentials WHERE id = ? AND user_id = ?')
    .bind(body.credentialId, userId)
    .first();
  if (!cred) return c.json({ error: 'Unknown passkey' }, 400);

  // Every note must be staged under THIS rotation. The lock has blocked note
  // writes since begin, so this state is stable through the commit batch — no
  // create/update can slip in between this check and the swap.
  const notStaged = await c.env.DB.prepare(
    'SELECT COUNT(*) AS n FROM notes WHERE user_id = ? AND (pending_ciphertext IS NULL OR pending_rotation IS NOT ?)',
  )
    .bind(userId, body.rotationId)
    .first<{ n: number }>();
  if (notStaged && notStaged.n > 0) {
    return c.json({ error: 'Notes changed during rotation — try again' }, 409);
  }

  const ts = now();
  const verifierHash = new Uint8Array(await crypto.subtle.digest('SHA-256', b64uDecode(body.recovery.verifier)));
  // Atomic cutover. `unixepoch()` ('now') is fixed per-statement, not per
  // transaction, so statements in one batch can observe times a second apart.
  // To stop the lease from expiring BETWEEN statements, the batch's FIRST
  // statement is a guarded lease renewal: it sets rotation_started to now iff
  // we still hold a live lease for this rotation and the surviving credential
  // exists. Every later statement is guarded on the same live-lease predicate,
  // which now compares against the just-renewed rotation_started — giving the
  // whole cutover a fresh 5-minute window, so the guards can't disagree
  // mid-batch. If the renewal changes zero rows we never owned a live lease:
  // every later guard then also fails, so nothing applies and we return 409.
  const guard = `EXISTS (SELECT 1 FROM users WHERE id = ? AND active_rotation = ? AND rotation_started > unixepoch() - ${ROTATION_LOCK_TTL})`;
  const guardBind = [userId, body.rotationId];
  const credExists = 'EXISTS (SELECT 1 FROM credentials WHERE id = ? AND user_id = ?)';
  const results = await c.env.DB.batch([
    // [0] Guarded lease renewal — the gate for the whole batch.
    c.env.DB.prepare(
      `UPDATE users SET rotation_started = unixepoch() WHERE id = ? AND active_rotation = ? AND rotation_started > unixepoch() - ${ROTATION_LOCK_TTL} AND ${credExists}`,
    ).bind(userId, body.rotationId, body.credentialId, userId),
    c.env.DB.prepare(`DELETE FROM credentials WHERE user_id = ? AND id != ? AND ${guard} AND ${credExists}`).bind(
      userId,
      body.credentialId,
      ...guardBind,
      body.credentialId,
      userId,
    ),
    c.env.DB.prepare(`UPDATE credentials SET wrapped_mk = ? WHERE id = ? AND user_id = ? AND ${guard}`).bind(
      body.wrappedMk,
      body.credentialId,
      userId,
      ...guardBind,
    ),
    c.env.DB.prepare(
      `INSERT OR REPLACE INTO recovery (user_id, verifier_hash, wrapped_mk, created_at) SELECT ?, ?, ?, ? WHERE ${guard} AND ${credExists}`,
    ).bind(userId, b64uEncode(verifierHash), body.recovery.wrappedMk, ts, ...guardBind, body.credentialId, userId),
    c.env.DB.prepare(
      `UPDATE notes SET ciphertext = pending_ciphertext, pending_ciphertext = NULL, pending_rotation = NULL, version = version + 1, updated_at = ? WHERE user_id = ? AND pending_rotation = ? AND ${guard} AND ${credExists}`,
    ).bind(ts, userId, body.rotationId, ...guardBind, body.credentialId, userId),
    // Revoke every other device (old epoch) and release the lock — self-guarded
    // on the live lease AND the surviving credential still existing.
    c.env.DB.prepare(
      `UPDATE users SET session_epoch = session_epoch + 1, active_rotation = NULL, rotation_started = NULL WHERE id = ? AND active_rotation = ? AND rotation_started > unixepoch() - ${ROTATION_LOCK_TTL} AND ${credExists}`,
    ).bind(userId, body.rotationId, body.credentialId, userId),
  ]);
  // The renewal (index 0) changing zero rows means we never owned a live lease
  // at batch start; every later guard then also failed, so nothing applied. The
  // final lock-release (index 5) must also have fired. Either miss → 409.
  if ((results[0].meta.changes ?? 0) === 0 || (results[5].meta.changes ?? 0) === 0) {
    return c.json({ error: 'Rotation is no longer active — try again' }, 409);
  }
  // Re-issue this device's cookie with the new epoch so it stays signed in.
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
