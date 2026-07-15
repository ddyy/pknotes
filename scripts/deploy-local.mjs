// Deploy using a personal database_id kept out of git.
//
// The committed wrangler.jsonc keeps a placeholder database_id so the Deploy
// to Cloudflare button can provision per-user resources. To deploy your own
// instance from a clone of this repo, supply the real id either as a
// D1_DATABASE_ID environment variable (e.g. a Workers Builds build variable
// for git-connected deploys) or in a gitignored .deploy.local.json:
//
//   { "database_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" }
//
// The Cloudflare Vite plugin writes the deployable config into dist/ and a
// redirect at .wrangler/deploy/config.json that wrangler follows. This script
// runs after the build, stamps the real id into that generated config, then
// runs migrations + deploy (both follow the redirect).
import { readFileSync, writeFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const overridePath = path.join(root, '.deploy.local.json');

let databaseId = process.env.D1_DATABASE_ID;
if (!databaseId) {
  try {
    databaseId = JSON.parse(readFileSync(overridePath, 'utf8')).database_id;
  } catch {
    console.error(
      `deploy-local: set D1_DATABASE_ID or create ${overridePath}\n` +
        'with your real D1 id (see `wrangler d1 list`):\n' +
        '  { "database_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" }',
    );
    process.exit(1);
  }
}
if (typeof databaseId !== 'string' || !/^[0-9a-f-]{36}$/i.test(databaseId)) {
  console.error('deploy-local: database_id must be a UUID');
  process.exit(1);
}

const redirectPath = path.join(root, '.wrangler', 'deploy', 'config.json');
let generatedPath;
try {
  const redirect = JSON.parse(readFileSync(redirectPath, 'utf8'));
  generatedPath = path.resolve(path.dirname(redirectPath), redirect.configPath);
} catch {
  console.error('deploy-local: no build output found — run via `npm run deploy:local` (which builds first)');
  process.exit(1);
}

const source = readFileSync(generatedPath, 'utf8');
if (!source.includes('"database_id"')) {
  console.error(`deploy-local: no database_id field in ${generatedPath}`);
  process.exit(1);
}
writeFileSync(generatedPath, source.replace(/"database_id":\s*"[^"]*"/, `"database_id": "${databaseId}"`));

for (const args of [
  ['wrangler', 'd1', 'migrations', 'apply', 'DB', '--remote'],
  ['wrangler', 'deploy'],
]) {
  const result = spawnSync('npx', args, { cwd: root, stdio: 'inherit' });
  if (result.status !== 0) process.exit(result.status ?? 1);
}
