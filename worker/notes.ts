import { Hono } from 'hono';
import { LIVE_LOCK_SQL, NO_ACTIVE_ROTATION_SQL, requireAuth, type AppEnv } from './session';

// Ciphertext blobs are opaque to the server; cap size to keep rows well under D1 limits.
const MAX_CIPHERTEXT_LEN = 1_000_000;

const nowS = () => Math.floor(Date.now() / 1000);

// True if the user currently holds a live rotation lock (DB-time freshness).
// Note writes are also gated in-SQL (so the check is atomic with the write);
// this is only for producing the right error after a write reports zero changes.
async function rotationLocked(c: { env: Env }, userId: string): Promise<boolean> {
  const row = await c.env.DB.prepare(`SELECT 1 FROM users WHERE id = ? AND ${LIVE_LOCK_SQL}`)
    .bind(userId)
    .first();
  return !!row;
}

const ROTATION_BUSY = { error: 'A key rotation is in progress — try again shortly' } as const;

interface NoteRow {
  id: string;
  ciphertext: string;
  version: number;
  created_at: number;
  updated_at: number;
}

export const notes = new Hono<AppEnv>();

notes.use('*', requireAuth(['session']));

function isValidCiphertext(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0 && value.length <= MAX_CIPHERTEXT_LEN;
}

notes.get('/', async (c) => {
  const { results } = await c.env.DB.prepare(
    'SELECT id, ciphertext, version, created_at, updated_at FROM notes WHERE user_id = ? ORDER BY updated_at DESC',
  )
    .bind(c.get('userId'))
    .all<NoteRow>();
  return c.json({ notes: results });
});

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

// Optional per-user note cap for shared/demo instances:
//   npx wrangler secret put MAX_NOTES_PER_USER   (e.g. 100)
// Unset means unlimited. Applies to creation only — editing existing notes
// is never blocked, so autosave can't hit it.
function maxNotesPerUser(env: Env): number | null {
  const raw = (env as { MAX_NOTES_PER_USER?: string }).MAX_NOTES_PER_USER;
  const n = raw ? Number.parseInt(raw, 10) : NaN;
  return Number.isFinite(n) && n > 0 ? n : null;
}

notes.post('/', async (c) => {
  // The client picks the id so it can bind it into the ciphertext (AES-GCM
  // additional data) before the note exists server-side.
  const { id, ciphertext } = await c.req.json<{ id?: string; ciphertext: string }>();
  if (!isValidCiphertext(ciphertext)) return c.json({ error: 'Invalid note payload' }, 400);

  const limit = maxNotesPerUser(c.env);
  const noteId = typeof id === 'string' && UUID_RE.test(id) ? id : crypto.randomUUID();
  const ts = nowS();
  const userId = c.get('userId');
  try {
    // Gate the INSERT in-SQL on two conditions so neither can be raced: no live
    // rotation lock, and (if set) the per-user cap. A conditional INSERT ...
    // SELECT is one atomic statement, so it can't slip between a rotation's
    // lock acquisition and its snapshot.
    const cap = limit !== null ? ' AND (SELECT COUNT(*) FROM notes WHERE user_id = ?) < ?' : '';
    const sql =
      'INSERT INTO notes (id, user_id, ciphertext, version, created_at, updated_at) SELECT ?, ?, ?, 1, ?, ? WHERE ' +
      NO_ACTIVE_ROTATION_SQL +
      cap;
    const binds: unknown[] = [noteId, userId, ciphertext, ts, ts, userId];
    if (limit !== null) binds.push(userId, limit);
    const result = await c.env.DB.prepare(sql)
      .bind(...binds)
      .run();
    if (result.meta.changes === 0) {
      if (await rotationLocked(c, userId)) return c.json(ROTATION_BUSY, 409);
      if (limit !== null) return c.json({ error: `Note limit reached (${limit} per account on this instance)` }, 403);
      return c.json({ error: 'Could not create note' }, 409);
    }
  } catch {
    // Global primary key: a colliding id (vanishingly unlikely for honest
    // clients) is rejected rather than overwritten.
    return c.json({ error: 'Note id already exists' }, 409);
  }
  return c.json({ id: noteId, version: 1, created_at: ts, updated_at: ts }, 201);
});

notes.put('/:id', async (c) => {
  const id = c.req.param('id');
  const { ciphertext, version } = await c.req.json<{ ciphertext: string; version: number }>();
  if (!isValidCiphertext(ciphertext) || typeof version !== 'number') {
    return c.json({ error: 'Invalid note payload' }, 400);
  }
  const ts = nowS();
  const userId = c.get('userId');
  // Gate on the rotation lock in the same statement so a save can't land
  // between a rotation's validation and its commit.
  const result = await c.env.DB.prepare(
    'UPDATE notes SET ciphertext = ?, version = version + 1, updated_at = ? WHERE id = ? AND user_id = ? AND version = ? AND ' +
      NO_ACTIVE_ROTATION_SQL,
  )
    .bind(ciphertext, ts, id, userId, version, userId)
    .run();

  if (result.meta.changes === 0) {
    if (await rotationLocked(c, userId)) return c.json(ROTATION_BUSY, 409);
    // Either the note is gone or someone else saved first — return the current
    // server copy so the client can resolve the conflict.
    const current = await c.env.DB.prepare(
      'SELECT id, ciphertext, version, created_at, updated_at FROM notes WHERE id = ? AND user_id = ?',
    )
      .bind(id, userId)
      .first<NoteRow>();
    if (!current) return c.json({ error: 'Note not found' }, 404);
    return c.json({ error: 'Version conflict', current }, 409);
  }
  return c.json({ id, version: version + 1, updated_at: ts });
});

notes.delete('/:id', async (c) => {
  const userId = c.get('userId');
  const result = await c.env.DB.prepare(
    'DELETE FROM notes WHERE id = ? AND user_id = ? AND ' + NO_ACTIVE_ROTATION_SQL,
  )
    .bind(c.req.param('id'), userId, userId)
    .run();
  if (result.meta.changes === 0) {
    if (await rotationLocked(c, userId)) return c.json(ROTATION_BUSY, 409);
    return c.json({ error: 'Note not found' }, 404);
  }
  return c.json({ ok: true });
});
