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
export type AppEnv = { Bindings: Env; Variables: { userId: string; authScope: AuthScope } };

export interface SessionPayload {
  sub: string;
  scope: AuthScope;
  exp: number;
}

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
  const payload: SessionPayload = { sub: userId, scope, exp: Math.floor(Date.now() / 1000) + ttl };
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
    c.set('userId', session.sub);
    c.set('authScope', session.scope);
    await next();
  };
}
