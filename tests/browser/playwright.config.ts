import { defineConfig, devices } from '@playwright/test';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

/**
 * Plan M5d D5: Chromium only, deterministic (Playwright auto-waits, no
 * fixed sleeps), one worker so the shared seeded server is never
 * contended. The seeded server's address comes from the manifest the
 * harness (`scripts/browser-tests.sh`) writes before launching the run;
 * `STARFORGE_BROWSER_BASE_URL` overrides it for ad-hoc runs.
 */
function manifestBaseUrl(): string {
  const path =
    process.env.SEED_MANIFEST ?? join(process.cwd(), '.seed-manifest.json');
  try {
    const manifest = JSON.parse(readFileSync(path, 'utf8')) as {
      baseUrl: string;
    };
    return manifest.baseUrl;
  } catch {
    return 'http://127.0.0.1:4177';
  }
}

export default defineConfig({
  testDir: '.',
  testMatch: ['viewer.spec.ts', 'merge.spec.ts'],
  fullyParallel: false,
  workers: 1,
  timeout: 120_000,
  expect: { timeout: 10_000 },
  retries: 0,
  reporter: [['line']],
  use: {
    baseURL: process.env.STARFORGE_BROWSER_BASE_URL ?? manifestBaseUrl(),
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
  },
  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
  ],
});
