import { expect, type Page } from '@playwright/test';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

/**
 * The `scripts/browser-tests.sh` harness seeds a throwaway server and
 * writes this manifest next to the specs. It is the only coupling
 * between the seeder and the specs: paths, users, ULIDs, shas.
 */
export interface SeedManifest {
  baseUrl: string;
  owner: string;
  repo: string;
  sessionUlid: string;
  headSha: string;
  otherSha: string;
  trailNumber: number;
  changeK: number;
  users: Record<string, { handle: string; password: string }>;
}
export function loadManifest(): SeedManifest {
  const path =
    process.env.SEED_MANIFEST ?? join(process.cwd(), '.seed-manifest.json');
  return JSON.parse(readFileSync(path, 'utf8')) as SeedManifest;
}

/** Signs in through the real HTML form (CSRF handled by the server). */
export async function signIn(page: Page, handle: string, password: string) {
  await page.goto('/login');
  await expect(page.locator('main h1')).toHaveText('Sign in');
  const form = page.locator('main form');
  await form.getByLabel('Handle or email').fill(handle);
  await form.getByLabel('Password').fill(password);
  await form.getByRole('button', { name: 'Sign in' }).click();
  // A failed login re-renders this page; success leaves it.
  await expect(page.locator('main h1:not(:has-text("Sign in"))')).toBeVisible({
    timeout: 15000,
  });
}

export function sessionPath(m: SeedManifest): string {
  return `/${m.owner}/${m.repo}/sessions/${m.sessionUlid}`;
}

export function changePath(m: SeedManifest): string {
  return `/${m.owner}/${m.repo}/trails/${m.trailNumber}/changes/${m.changeK}`;
}

export function trailPath(m: SeedManifest): string {
  return `/${m.owner}/${m.repo}/trails/${m.trailNumber}`;
}
