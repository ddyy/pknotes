import { Hono } from 'hono';
import { auth } from './auth';
import { notes } from './notes';

const app = new Hono<{ Bindings: Env }>();

app.onError((err, c) => {
  console.error(JSON.stringify({ msg: 'unhandled error', path: new URL(c.req.url).pathname, error: String(err) }));
  return c.json({ error: 'Internal error' }, 500);
});

app.route('/api/auth', auth);
app.route('/api/notes', notes);
app.all('/api/*', (c) => c.json({ error: 'Not found' }, 404));

export default app;
