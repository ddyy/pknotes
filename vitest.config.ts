import { cloudflareTest, readD1Migrations } from '@cloudflare/vitest-pool-workers';
import { defineConfig } from 'vitest/config';

// Worker-level integration tests run inside workerd with a real D1 binding.
// The node:test suites under tests/ (crypto, title, zip) run separately via
// `node --test` and are excluded here.
const migrations = await readD1Migrations('./migrations');

export default defineConfig({
  plugins: [
    cloudflareTest({
      miniflare: {
        compatibilityDate: '2026-07-14',
        compatibilityFlags: ['nodejs_compat'],
        d1Databases: ['DB'],
        bindings: {
          SESSION_SECRET: 'test-secret-not-a-real-key',
          TEST_MIGRATIONS: migrations,
        },
      },
    }),
  ],
  test: {
    include: ['worker/**/*.test.ts'],
    setupFiles: ['./worker/test-setup.ts'],
  },
});
