// Creates .dev.vars with a random dev SESSION_SECRET if it doesn't exist.
// Needed by `npm run dev` (workerd reads it) and by `npm run check` in fresh
// clones/CI, where `wrangler types` derives the Env type from it.
import { existsSync, writeFileSync } from 'node:fs';
import { randomBytes } from 'node:crypto';

if (!existsSync('.dev.vars')) {
  writeFileSync('.dev.vars', `SESSION_SECRET=${randomBytes(32).toString('base64url')}\n`);
  console.log('Created .dev.vars with a random dev SESSION_SECRET');
}
