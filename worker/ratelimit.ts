import type { Context, Next } from 'hono';
import type { AppEnv } from './session';

// Per-IP request limits via the Workers Rate Limiting binding. Counters are
// per-namespace, so the strict and standard tiers don't share budgets.
export function rateLimit(pick: (env: Env) => RateLimit | undefined) {
  return async (c: Context<AppEnv>, next: Next) => {
    // The binding is always present in production (wrangler.jsonc); it's absent
    // in the test runtime, where limiting isn't under test — skip rather than
    // crash.
    const limiter = pick(c.env);
    if (limiter) {
      const key = c.req.header('cf-connecting-ip') ?? 'unknown';
      const { success } = await limiter.limit({ key });
      if (!success) {
        return c.json({ error: 'Too many requests — try again in a minute' }, 429);
      }
    }
    await next();
  };
}
