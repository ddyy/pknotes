// Runs automatically before `npm run dev`: makes a fresh clone work with no
// manual setup. Generates a dev SESSION_SECRET if missing, then applies any
// pending local D1 migrations.
import { existsSync, writeFileSync } from 'node:fs';
import { randomBytes } from 'node:crypto';
import { spawnSync } from 'node:child_process';

if (!existsSync('.dev.vars')) {
  writeFileSync('.dev.vars', `SESSION_SECRET=${randomBytes(32).toString('base64url')}\n`);
  console.log('Created .dev.vars with a random dev SESSION_SECRET');
}

const result = spawnSync('npx', ['wrangler', 'd1', 'migrations', 'apply', 'DB', '--local'], {
  stdio: 'inherit',
  shell: process.platform === 'win32',
});
process.exit(result.status ?? 1);
