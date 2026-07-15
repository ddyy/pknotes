// Deploy using a personal, gitignored config overlay.
//
// The committed wrangler.jsonc keeps a placeholder database_id so the Deploy
// to Cloudflare button can provision per-user resources. For manual deploys
// of your own instance, put the real id in .deploy.local.json (gitignored):
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

let override;
try {
  override = JSON.parse(readFileSync(overridePath, 'utf8'));
} catch {
  console.error(
    `deploy-local: missing or unreadable ${overridePath}\n` +
      'Create it with your real D1 id (see `wrangler d1 list`):\n' +
      '  { "database_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" }',
  );
  process.exit(1);
}
if (typeof override.database_id !== 'string' || !/^[0-9a-f-]{36}$/i.test(override.database_id)) {
  console.error('deploy-local: .deploy.local.json must contain a "database_id" UUID');
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
writeFileSync(generatedPath, source.replace(/"database_id":\s*"[^"]*"/, `"database_id": "${override.database_id}"`));

for (const args of [
  ['wrangler', 'd1', 'migrations', 'apply', 'DB', '--remote'],
  ['wrangler', 'deploy'],
]) {
  const result = spawnSync('npx', args, { cwd: root, stdio: 'inherit' });
  if (result.status !== 0) process.exit(result.status ?? 1);
}
