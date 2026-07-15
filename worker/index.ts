import { Hono } from 'hono';
import { auth } from './auth';
import { notes } from './notes';

const app = new Hono<{ Bindings: Env }>();

app.onError((err, c) => {
  console.error(JSON.stringify({ msg: 'unhandled error', path: new URL(c.req.url).pathname, error: String(err) }));
  return c.json({ error: 'Internal error' }, 500);
});

// Instance metadata for the client — currently just whether this is a
// demo-mode deployment (banner + wipe warning).
app.get('/api/meta', (c) =>
  c.json({ demo: (c.env as { DEMO_MODE?: string }).DEMO_MODE === 'true' }),
);

app.route('/api/auth', auth);
app.route('/api/notes', notes);
app.all('/api/*', (c) => c.json({ error: 'Not found' }, 404));

// Demo-instance daily note wipe. Accounts are kept indefinitely so returning
// visitors' passkeys always work; account rows are tiny and registration is
// rate-limited, so growth stays manageable. Double-gated: a cron trigger only
// exists when the demo deploy config adds one, AND the handler refuses to run
// without the DEMO_MODE secret — so a stray cron on a personal instance can
// never delete user data.
async function scheduled(_event: ScheduledController, env: Env): Promise<void> {
  if ((env as { DEMO_MODE?: string }).DEMO_MODE !== 'true') {
    console.log(JSON.stringify({ msg: 'scheduled: DEMO_MODE not set, refusing to wipe' }));
    return;
  }
  const result = await env.DB.prepare('DELETE FROM notes').run();
  console.log(JSON.stringify({ msg: 'demo wipe complete', notesDeleted: result.meta.changes ?? 0 }));
}

export default { fetch: app.fetch, scheduled };
