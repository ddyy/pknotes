import { applyD1Migrations, env } from 'cloudflare:test';
import { beforeAll } from 'vitest';

// Apply the real migrations to the test D1 database once before the suite.
beforeAll(async () => {
  await applyD1Migrations(env.DB, (env as { TEST_MIGRATIONS: D1Migration[] }).TEST_MIGRATIONS);
});
