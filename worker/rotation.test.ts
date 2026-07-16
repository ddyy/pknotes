import { env } from 'cloudflare:test';
import { beforeEach, describe, expect, it } from 'vitest';
import { blob, cookie, noteRow, req, seedUser } from './test-helpers';

// Fresh data per test.
beforeEach(async () => {
  await env.DB.batch([
    env.DB.prepare('DELETE FROM notes'),
    env.DB.prepare('DELETE FROM credentials'),
    env.DB.prepare('DELETE FROM recovery'),
    env.DB.prepare('DELETE FROM users'),
  ]);
});

const recovery = () => ({ verifier: blob('ver'), wrappedMk: blob('rmk') });

async function fullRotate(userId: string, credentialId: string, notes: { id: string; version: number }[]) {
  const c = await cookie(userId);
  const begin = await req('/api/auth/rotate/begin', c, { credentialId, notes });
  if (!begin.ok) return { begin };
  const { rotationId } = await begin.json<{ rotationId: string }>();
  const stage = await req('/api/auth/rotate/stage', c, {
    rotationId,
    notes: notes.map((n) => ({ id: n.id, ciphertext: blob('new'), version: n.version })),
  });
  const commit = await req('/api/auth/rotate/commit', c, {
    rotationId,
    credentialId,
    wrappedMk: blob('nmk'),
    recovery: recovery(),
  });
  return { begin, stage, commit, rotationId };
}

describe('rotation happy path', () => {
  it('re-encrypts every note, swaps the key, and clears staging', async () => {
    const { userId, credentialId, notes } = await seedUser(3);
    const before = await Promise.all(notes.map((n) => noteRow(n.id)));
    const { commit } = await fullRotate(userId, credentialId, notes);
    expect(commit?.status).toBe(200);
    for (let i = 0; i < notes.length; i++) {
      const after = await noteRow(notes[i].id);
      expect(after?.ciphertext).not.toBe(before[i]?.ciphertext); // re-encrypted
      expect(after?.pending).toBeNull(); // staging cleared
      expect(after?.version).toBe(2); // bumped once
    }
  });

  it('bumps session_epoch so old cookies are revoked', async () => {
    const { userId, credentialId, notes } = await seedUser(1);
    const oldCookie = await cookie(userId); // epoch 0
    await fullRotate(userId, credentialId, notes);
    const after = await req('/api/notes', oldCookie, {}); // GET-ish; wrong method ok, auth runs first
    // The old-epoch cookie must be rejected by requireAuth.
    const check = await app_get('/api/notes', oldCookie);
    expect(check.status).toBe(401);
    void after;
  });
});

// Helper for GET requests.
async function app_get(path: string, cookieHeader: string): Promise<Response> {
  const { app } = await import('./index');
  return app.request(path, { headers: { Cookie: cookieHeader } }, env);
}

describe('#1 stale plaintext (version mismatch)', () => {
  it('rejects begin when the client sends a stale version', async () => {
    const { userId, credentialId, notes } = await seedUser(2);
    // Simulate another device having saved note 0 (version now 2 in DB).
    await env.DB.prepare('UPDATE notes SET version = 2 WHERE id = ?').bind(notes[0].id).run();
    const c = await cookie(userId);
    const begin = await req('/api/auth/rotate/begin', c, {
      credentialId,
      notes, // still claims version 1 for note 0 — stale
    });
    expect(begin.status).toBe(409);
  });
});

describe('#2 concurrent rotations must not cross-wire', () => {
  it('rejects a second begin while one rotation is in progress', async () => {
    const { userId, credentialId, notes } = await seedUser(2);
    const c = await cookie(userId);
    const a = await req('/api/auth/rotate/begin', c, { credentialId, notes });
    expect(a.status).toBe(200);
    const b = await req('/api/auth/rotate/begin', c, { credentialId, notes });
    expect(b.status).toBe(409); // locked
  });

  it("does not let rotation B's ciphertext commit under rotation A's key", async () => {
    const { userId, credentialId, notes } = await seedUser(1);
    const c = await cookie(userId);
    const a = await req('/api/auth/rotate/begin', c, { credentialId, notes });
    const { rotationId: idA } = await a.json<{ rotationId: string }>();
    // A second concurrent rotation attempt must fail to begin...
    const b = await req('/api/auth/rotate/begin', c, { credentialId, notes });
    expect(b.status).toBe(409);
    // ...and staging/committing with a foreign rotationId must be rejected.
    const stageForeign = await req('/api/auth/rotate/stage', c, {
      rotationId: 'not-the-active-one',
      notes: [{ id: notes[0].id, ciphertext: blob('evil'), version: 1 }],
    });
    expect(stageForeign.status).toBe(409);
    const commitForeign = await req('/api/auth/rotate/commit', c, {
      rotationId: 'not-the-active-one',
      credentialId,
      wrappedMk: blob('nmk'),
      recovery: recovery(),
    });
    expect(commitForeign.status).toBe(409);
    void idA;
  });
});

describe('#3 note writes during rotation are blocked', () => {
  it('rejects note create while a rotation lock is held', async () => {
    const { userId, credentialId, notes } = await seedUser(1);
    const c = await cookie(userId);
    await req('/api/auth/rotate/begin', c, { credentialId, notes });
    const create = await req('/api/notes', c, { id: crypto.randomUUID(), ciphertext: blob('x') });
    expect(create.status).toBe(409); // rotation in progress
  });

  it('rejects note update while a rotation lock is held', async () => {
    const { userId, credentialId, notes } = await seedUser(1);
    const c = await cookie(userId);
    await req('/api/auth/rotate/begin', c, { credentialId, notes });
    const put = await app_put(`/api/notes/${notes[0].id}`, c, { ciphertext: blob('x'), version: 1 });
    expect(put.status).toBe(409);
  });
});

async function app_put(path: string, cookieHeader: string, body: unknown): Promise<Response> {
  const { app } = await import('./index');
  return app.request(
    path,
    { method: 'PUT', headers: { 'Content-Type': 'application/json', Cookie: cookieHeader }, body: JSON.stringify(body) },
    env,
  );
}

async function app_delete(path: string, cookieHeader: string): Promise<Response> {
  const { app } = await import('./index');
  return app.request(path, { method: 'DELETE', headers: { Cookie: cookieHeader } }, env);
}

describe('rotation lock releases', () => {
  it('allows note writes again after a completed rotation', async () => {
    const { userId, credentialId, notes } = await seedUser(1);
    await fullRotate(userId, credentialId, notes);
    const c = await cookie(userId); // fresh cookie with new epoch
    const create = await req('/api/notes', c, { id: crypto.randomUUID(), ciphertext: blob('x') });
    expect(create.status).toBe(201);
  });

  it('reclaims an abandoned (expired) lock on the next begin', async () => {
    const { userId, credentialId, notes } = await seedUser(1);
    // Simulate an abandoned rotation: lock set, started long ago.
    await env.DB.prepare('UPDATE users SET active_rotation = ?, rotation_started = ? WHERE id = ?')
      .bind('dead-rotation', 1, userId)
      .run();
    const c = await cookie(userId);
    const begin = await req('/api/auth/rotate/begin', c, { credentialId, notes });
    expect(begin.status).toBe(200); // stale lock reclaimed
  });
});

describe('commit safety', () => {
  it('refuses to commit when a note was left unstaged', async () => {
    const { userId, credentialId, notes } = await seedUser(2);
    const c = await cookie(userId);
    const begin = await req('/api/auth/rotate/begin', c, { credentialId, notes });
    const { rotationId } = await begin.json<{ rotationId: string }>();
    // Stage only ONE of the two notes.
    await req('/api/auth/rotate/stage', c, {
      rotationId,
      notes: [{ id: notes[0].id, ciphertext: blob('new'), version: 1 }],
    });
    const commit = await req('/api/auth/rotate/commit', c, {
      rotationId,
      credentialId,
      wrappedMk: blob('nmk'),
      recovery: recovery(),
    });
    expect(commit.status).toBe(409);
    // The vault must be untouched: original ciphertext intact, nothing pending.
    const row = await noteRow(notes[1].id);
    expect(row?.pending).toBeNull();
  });

  it('requires recent authentication to rotate', async () => {
    const { userId, credentialId, notes } = await seedUser(1);
    // A cookie whose auth is older than the recent-auth window.
    const stale = await cookie(userId, { iat: Math.floor(Date.now() / 1000) - 3600 });
    const begin = await req('/api/auth/rotate/begin', stale, { credentialId, notes });
    expect(begin.status).toBe(401);
  });

  it('commit no-ops (does not install the key) if the lock was lost mid-commit', async () => {
    const { userId, credentialId, notes } = await seedUser(1);
    const c = await cookie(userId);
    const begin = await req('/api/auth/rotate/begin', c, { credentialId, notes });
    const { rotationId } = await begin.json<{ rotationId: string }>();
    await req('/api/auth/rotate/stage', c, {
      rotationId,
      notes: [{ id: notes[0].id, ciphertext: blob('new'), version: 1 }],
    });
    // Simulate the lease being reclaimed by another rotation between the
    // pre-batch checks and the batch: overwrite the active_rotation.
    const keyBefore = await env.DB.prepare('SELECT wrapped_mk FROM credentials WHERE id = ?')
      .bind(credentialId)
      .first<{ wrapped_mk: string }>();
    await env.DB.prepare("UPDATE users SET active_rotation = 'someone-else', rotation_started = ? WHERE id = ?")
      .bind(Math.floor(Date.now() / 1000), userId)
      .run();
    // Committing a rotation this user no longer owns must not install the key.
    // (The endpoint pre-check catches this case; the in-batch ownership guard
    // is the belt to that suspenders for the check-to-batch window.)
    const commit = await req('/api/auth/rotate/commit', c, {
      rotationId,
      credentialId,
      wrappedMk: blob('nmk'),
      recovery: recovery(),
    });
    expect(commit.status).toBe(409);
    const keyAfter = await env.DB.prepare('SELECT wrapped_mk FROM credentials WHERE id = ?')
      .bind(credentialId)
      .first<{ wrapped_mk: string }>();
    expect(keyAfter?.wrapped_mk).toBe(keyBefore?.wrapped_mk); // key never installed
  });

  it('does not swap notes when the lock was lost (no partial rotation)', async () => {
    const { userId, credentialId, notes } = await seedUser(2);
    const c = await cookie(userId);
    const begin = await req('/api/auth/rotate/begin', c, { credentialId, notes });
    const { rotationId } = await begin.json<{ rotationId: string }>();
    await req('/api/auth/rotate/stage', c, {
      rotationId,
      notes: notes.map((n) => ({ id: n.id, ciphertext: blob('new'), version: 1 })),
    });
    const noteBefore = await noteRow(notes[0].id);
    // Reclaim ownership (another rotation) but leave this rotation's pending
    // rows in place — the exact partial-rotation window.
    await env.DB.prepare("UPDATE users SET active_rotation = 'other', rotation_started = ? WHERE id = ?")
      .bind(Math.floor(Date.now() / 1000), userId)
      .run();
    const commit = await req('/api/auth/rotate/commit', c, {
      rotationId,
      credentialId,
      wrappedMk: blob('nmk'),
      recovery: recovery(),
    });
    expect(commit.status).toBe(409);
    // Notes must be UNCHANGED — not swapped to the staged ciphertext.
    const noteAfter = await noteRow(notes[0].id);
    expect(noteAfter?.ciphertext).toBe(noteBefore?.ciphertext);
    expect(noteAfter?.version).toBe(noteBefore?.version);
  });

  it('commit no-ops entirely when our own lease has expired', async () => {
    const { userId, credentialId, notes } = await seedUser(1);
    const c = await cookie(userId);
    const begin = await req('/api/auth/rotate/begin', c, { credentialId, notes });
    const { rotationId } = await begin.json<{ rotationId: string }>();
    await req('/api/auth/rotate/stage', c, {
      rotationId,
      notes: [{ id: notes[0].id, ciphertext: blob('new'), version: 1 }],
    });
    const keyBefore = await env.DB.prepare('SELECT wrapped_mk FROM credentials WHERE id = ?')
      .bind(credentialId)
      .first<{ wrapped_mk: string }>();
    const noteBefore = await noteRow(notes[0].id);
    // Our own lease, but aged past expiry (rotation_started far in the past).
    await env.DB.prepare('UPDATE users SET rotation_started = 1 WHERE id = ?').bind(userId).run();
    const commit = await req('/api/auth/rotate/commit', c, {
      rotationId,
      credentialId,
      wrappedMk: blob('nmk'),
      recovery: recovery(),
    });
    expect(commit.status).toBe(409);
    const keyAfter = await env.DB.prepare('SELECT wrapped_mk FROM credentials WHERE id = ?')
      .bind(credentialId)
      .first<{ wrapped_mk: string }>();
    const noteAfter = await noteRow(notes[0].id);
    expect(keyAfter?.wrapped_mk).toBe(keyBefore?.wrapped_mk); // key not installed
    expect(noteAfter?.ciphertext).toBe(noteBefore?.ciphertext); // notes not swapped
  });

  it('stage refuses to revive an expired lease', async () => {
    const { userId, credentialId, notes } = await seedUser(1);
    const c = await cookie(userId);
    const begin = await req('/api/auth/rotate/begin', c, { credentialId, notes });
    const { rotationId } = await begin.json<{ rotationId: string }>();
    // Age our own lease past expiry before staging.
    await env.DB.prepare('UPDATE users SET rotation_started = 1 WHERE id = ?').bind(userId).run();
    const stage = await req('/api/auth/rotate/stage', c, {
      rotationId,
      notes: [{ id: notes[0].id, ciphertext: blob('new'), version: 1 }],
    });
    expect(stage.status).toBe(409);
    // The expired lease must NOT have been revived, so note writes are allowed.
    const stillExpired = await env.DB.prepare(
      `SELECT 1 FROM users WHERE id = ? AND active_rotation IS NOT NULL AND rotation_started > unixepoch() - 300`,
    )
      .bind(userId)
      .first();
    expect(stillExpired).toBeNull();
  });

  it('blocks removing a passkey while a rotation is active', async () => {
    const { userId, credentialId, notes } = await seedUser(1);
    // Give the user a second passkey so removal is otherwise allowed.
    const other = crypto.randomUUID();
    await env.DB.prepare(
      'INSERT INTO credentials (id, user_id, public_key, counter, transports, wrapped_mk, prf_salt, created_at) VALUES (?, ?, ?, 0, ?, ?, ?, ?)',
    )
      .bind(other, userId, blob('pk'), '[]', blob('mk'), blob('salt'), Math.floor(Date.now() / 1000))
      .run();
    const c = await cookie(userId);
    await req('/api/auth/rotate/begin', c, { credentialId, notes });
    const del = await app_delete(`/api/auth/credentials/${other}`, c);
    expect(del.status).toBe(409); // rotation in progress
  });

  it('handles a larger vault across multiple stage chunks', async () => {
    const { userId, credentialId, notes } = await seedUser(90); // > 2 chunks of 40
    const c = await cookie(userId);
    const begin = await req('/api/auth/rotate/begin', c, { credentialId, notes });
    const { rotationId } = await begin.json<{ rotationId: string }>();
    for (let i = 0; i < notes.length; i += 40) {
      const chunk = notes.slice(i, i + 40).map((n) => ({ id: n.id, ciphertext: blob('c'), version: 1 }));
      const stage = await req('/api/auth/rotate/stage', c, { rotationId, notes: chunk });
      expect(stage.status).toBe(200);
    }
    const commit = await req('/api/auth/rotate/commit', c, {
      rotationId,
      credentialId,
      wrappedMk: blob('nmk'),
      recovery: recovery(),
    });
    expect(commit.status).toBe(200);
    const remaining = await env.DB.prepare(
      'SELECT COUNT(*) AS n FROM notes WHERE user_id = ? AND pending_ciphertext IS NOT NULL',
    )
      .bind(userId)
      .first<{ n: number }>();
    expect(remaining?.n).toBe(0); // all committed, none left pending
  });
});
