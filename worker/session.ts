import type { Context, Next } from 'hono';
import { getCookie, setCookie, deleteCookie } from 'hono/cookie';

const enc = new TextEncoder();
const dec = new TextDecoder();

export const SESSION_COOKIE = 'pknotes_sess';
export const CHALLENGE_COOKIE = 'pknotes_chal';
const SESSION_TTL = 60 * 60 * 12;
const RECOVERY_TTL = 60 * 10;
const CHALLENGE_TTL = 60 * 5;

export type AuthScope = 'session' | 'recovery';

/** Shared Hono env for all routes: bindings plus the auth variables set by requireAuth. */
export type AppEnv = { Bindings: Env; Variables: { userId: string; authScope: AuthScope; authIat: number } };

export interface SessionPayload {
  sub: string;
  scope: AuthScope;
  exp: number;
  /** users.session_epoch when issued; rotation bumps it to revoke old sessions. */
  epoch: number;
  /** Issued-at (seconds). Used to require recent auth for sensitive operations. */
  iat: number;
}

/** A sensitive operation must have been authenticated within this window. */
export const RECENT_AUTH_WINDOW = 5 * 60;

/** A rotation lock older than this (seconds) is abandoned and reclaimable. */
export const ROTATION_LOCK_TTL = 5 * 60;

// Lease freshness is evaluated with DB time (unixepoch()), never a value
// computed in the Worker. Because D1 runs a database's queries serially, a
// note write and a rotation commit that straddle the expiry instant then
// compare the same rotation_started against a single monotonic clock — they
// can't both decide "expired" and "live" in opposite directions and slip a
// note past the rotation. SQL fragment for "still a live lock":
export const LIVE_LOCK_SQL = `active_rotation IS NOT NULL AND rotation_started > unixepoch() - ${ROTATION_LOCK_TTL}`;

/**
 * SQL fragment that is true when the user (bound param: user id) does NOT hold
 * a live rotation lock. Gates note/credential writes against a rotation's
 * check-then-commit window.
 */
export const NO_ACTIVE_ROTATION_SQL = `NOT EXISTS (SELECT 1 FROM users WHERE id = ? AND ${LIVE_LOCK_SQL})`;

export interface ChallengePayload {
  challenge: string;
  username?: string;
  userId?: string;
  exp: number;
}

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

async function hmacKey(secret: string): Promise<CryptoKey> {
  return crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, [
    'sign',
    'verify',
  ]);
}

export async function signToken(payload: object, secret: string): Promise<string> {
  const body = b64uEncode(enc.encode(JSON.stringify(payload)));
  const key = await hmacKey(secret);
  const sig = new Uint8Array(await crypto.subtle.sign('HMAC', key, enc.encode(body)));
  return `${body}.${b64uEncode(sig)}`;
}

export async function verifyToken<T extends { exp: number }>(
  token: string | undefined,
  secret: string,
): Promise<T | null> {
  if (!token) return null;
  const dot = token.lastIndexOf('.');
  if (dot < 0) return null;
  const body = token.slice(0, dot);
  try {
    const key = await hmacKey(secret);
    const ok = await crypto.subtle.verify('HMAC', key, b64uDecode(token.slice(dot + 1)), enc.encode(body));
    if (!ok) return null;
    const payload = JSON.parse(dec.decode(b64uDecode(body))) as T;
    if (payload.exp < Date.now() / 1000) return null;
    return payload;
  } catch {
    return null;
  }
}

function cookieOpts(c: Context, maxAge: number) {
  return {
    httpOnly: true,
    sameSite: 'Strict' as const,
    secure: new URL(c.req.url).protocol === 'https:',
    path: '/',
    maxAge,
  };
}

export async function setSessionCookie(c: Context<AppEnv>, userId: string, scope: AuthScope = 'session') {
  const ttl = scope === 'recovery' ? RECOVERY_TTL : SESSION_TTL;
  // Stamp the user's current session_epoch so a later rotation can revoke this
  // cookie. A missing row (shouldn't happen for a just-authenticated user)
  // falls back to epoch 0.
  const row = await c.env.DB.prepare('SELECT session_epoch FROM users WHERE id = ?')
    .bind(userId)
    .first<{ session_epoch: number }>();
  const nowS = Math.floor(Date.now() / 1000);
  const payload: SessionPayload = {
    sub: userId,
    scope,
    exp: nowS + ttl,
    epoch: row?.session_epoch ?? 0,
    iat: nowS,
  };
  setCookie(c, SESSION_COOKIE, await signToken(payload, c.env.SESSION_SECRET), cookieOpts(c, ttl));
}

export function clearSessionCookie(c: Context) {
  deleteCookie(c, SESSION_COOKIE, { path: '/' });
}

export async function setChallengeCookie(
  c: Context<AppEnv>,
  data: Omit<ChallengePayload, "exp">,
) {
  const payload: ChallengePayload = { ...data, exp: Math.floor(Date.now() / 1000) + CHALLENGE_TTL };
  setCookie(c, CHALLENGE_COOKIE, await signToken(payload, c.env.SESSION_SECRET), cookieOpts(c, CHALLENGE_TTL));
}

export async function readChallengeCookie(c: Context<AppEnv>): Promise<ChallengePayload | null> {
  const payload = await verifyToken<ChallengePayload>(getCookie(c, CHALLENGE_COOKIE), c.env.SESSION_SECRET);
  deleteCookie(c, CHALLENGE_COOKIE, { path: '/' });
  return payload;
}

export function requireAuth(scopes: AuthScope[]) {
  return async (c: Context<AppEnv>, next: Next) => {
    const session = await verifyToken<SessionPayload>(getCookie(c, SESSION_COOKIE), c.env.SESSION_SECRET);
    if (!session || !scopes.includes(session.scope)) {
      return c.json({ error: 'Unauthorized' }, 401);
    }
    // Sessions are stateless, so a signed cookie outlives account deletion
    // (e.g. the demo wipe) and credential revocation. Confirm the user exists
    // AND the token's epoch still matches: master-key rotation bumps
    // session_epoch, which invalidates every other device's cookie here. The
    // client treats any 401 as "lock the vault".
    const user = await c.env.DB.prepare('SELECT session_epoch FROM users WHERE id = ?')
      .bind(session.sub)
      .first<{ session_epoch: number }>();
    if (!user || (session.epoch ?? 0) !== user.session_epoch) {
      clearSessionCookie(c);
      return c.json({ error: 'Unauthorized' }, 401);
    }
    c.set('userId', session.sub);
    c.set('authScope', session.scope);
    c.set('authIat', session.iat ?? 0);
    await next();
  };
}
