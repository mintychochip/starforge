import { expect, test } from '@playwright/test';
import {
  changePath,
  loadManifest,
  signIn,
  trailPath,
} from './helpers';

/**
 * Plan M5d D5, merge flow: sign in, open a Trail, the gate panel shows
 * blocked, approve as a second user, the gate passes, merge with the
 * selected method, and the Trail shows merged.
 */

test.describe('merge flow', () => {
  test('gate blocks until a second user approves, then merges', async ({
    page,
    browser,
  }) => {
    const m = loadManifest();
    const change = changePath(m);

    // Alice owns the repo and holds `trail:write`; she opens the Trail.
    await signIn(page, 'alice', m.users.alice.password);
    await page.goto(trailPath(m));
    await expect(page.locator('main h3', { hasText: 'Changes' })).toBeVisible();

    // The change page's gate panel shows blocked before any approval.
    await page.goto(change);
    await expect(page.locator('#gates-banner-1')).toContainText(
      'Gates failing',
    );
    await expect(page.locator('#approvals-change-1')).toContainText(
      'Approvals: 0',
    );
    await expect(page.locator('#merge-change-1 button')).toBeDisabled();

    // Bob (a write collaborator) approves, from his own context.
    const bobContext = await browser.newContext();
    const bob = await bobContext.newPage();
    await signIn(bob, 'bob', m.users.bob.password);
    await bob.goto(change);
    const review = bob.locator('main #add-review');
    await expect(review).toBeVisible();
    await review.locator('input[value="approve"]').check();
    await review.locator('textarea[name="body"]').fill('ship it');
    await review.getByRole('button', { name: 'Submit review' }).click();
    await expect(bob.locator('main #review-summary')).toContainText(
      'Approvals: 1',
    );
    await bobContext.close();

    // The gate passes and the merge form enables.
    await page.goto(change);
    await expect(page.locator('#gates-banner-1')).toContainText(
      'All gates pass',
    );
    await expect(page.locator('#approvals-change-1')).toContainText(
      'Approvals: 1',
    );
    await expect(page.locator('#merge-change-1 button')).toBeEnabled();

    // Alice merges with the selected method.
    await page.goto(change);
    await expect(page.locator('#merge-change-1 button')).toBeEnabled();
    await page
      .locator('#merge-change-1 select[name="method"]')
      .selectOption('merge');
    await page.locator('#merge-change-1').getByRole('button', { name: 'Merge' }).click();
    await expect(page.locator('main h2 .badge', { hasText: /^merged$/ })).toBeVisible();

    // The Trail shows merged (the Trail header and its change both badge it).
    await page.goto(trailPath(m));
    await expect(page.locator('main .badge', { hasText: /^merged$/ }).first()).toBeVisible();
  });
});
