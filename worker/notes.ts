import { Hono } from 'hono';
import { requireAuth, type AppEnv } from './session';

// Ciphertext blobs are opaque to the server; cap size to keep rows well under D1 limits.
const MAX_CIPHERTEXT_LEN = 1_000_000;

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

notes.post('/', async (c) => {
  // The client picks the id so it can bind it into the ciphertext (AES-GCM
  // additional data) before the note exists server-side.
  const { id, ciphertext } = await c.req.json<{ id?: string; ciphertext: string }>();
  if (!isValidCiphertext(ciphertext)) return c.json({ error: 'Invalid note payload' }, 400);
  const noteId = typeof id === 'string' && UUID_RE.test(id) ? id : crypto.randomUUID();
  const ts = Math.floor(Date.now() / 1000);
  try {
    await c.env.DB.prepare(
      'INSERT INTO notes (id, user_id, ciphertext, version, created_at, updated_at) VALUES (?, ?, ?, 1, ?, ?)',
    )
      .bind(noteId, c.get('userId'), ciphertext, ts, ts)
      .run();
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
  const ts = Math.floor(Date.now() / 1000);
  const result = await c.env.DB.prepare(
    'UPDATE notes SET ciphertext = ?, version = version + 1, updated_at = ? WHERE id = ? AND user_id = ? AND version = ?',
  )
    .bind(ciphertext, ts, id, c.get('userId'), version)
    .run();

  if (result.meta.changes === 0) {
    // Either the note is gone or someone else saved first — return the current
    // server copy so the client can resolve the conflict.
    const current = await c.env.DB.prepare(
      'SELECT id, ciphertext, version, created_at, updated_at FROM notes WHERE id = ? AND user_id = ?',
    )
      .bind(id, c.get('userId'))
      .first<NoteRow>();
    if (!current) return c.json({ error: 'Note not found' }, 404);
    return c.json({ error: 'Version conflict', current }, 409);
  }
  return c.json({ id, version: version + 1, updated_at: ts });
});

notes.delete('/:id', async (c) => {
  const result = await c.env.DB.prepare('DELETE FROM notes WHERE id = ? AND user_id = ?')
    .bind(c.req.param('id'), c.get('userId'))
    .run();
  if (result.meta.changes === 0) return c.json({ error: 'Note not found' }, 404);
  return c.json({ ok: true });
});
