import { expect, test } from '@playwright/test';
import {
  loadManifest,
  sessionPath,
  signIn,
} from './helpers';

/**
 * Plan M5d D5, session viewer: the keyboard reaches the search box,
 * results jump to `#turn-<seq>`, the split view switches commits
 * through the JS enhancement, collapsed tool calls expand, and the
 * page is complete without JavaScript.
 */

test.describe('session viewer', () => {
  test('keyboard reaches the search box; search highlights hits', async ({
    page,
  }) => {
    const m = loadManifest();
    await signIn(page, 'alice', m.users.alice.password);
    await page.goto(sessionPath(m));

    // Keyboard focus reaches the search box by tabbing from the top of
    // the page (bounded loop; the header's own search box comes first).
    // Scoped to <main>: the site header carries its own search form.
    const search = page.locator('main .session-search input[name="q"]');
    const searchEl = await search.elementHandle();
    let tabbed = false;
    for (let i = 0; i < 40 && !tabbed; i++) {
      await page.keyboard.press('Tab');
      tabbed = await page.evaluate(
        (el) => document.activeElement === el,
        searchEl,
      );
    }
    expect(tabbed).toBe(true);
    await expect(search).toBeFocused();
    await search.pressSequentially('quasar-needle', { delay: 0 });
    await search.press('Enter');

    // Server results list the hit and jump to its anchor.
    await expect(page.locator('main .search-results')).toContainText('1 hits');
    const hit = page.locator('main .search-results a[href*="#turn-2"]');
    await expect(hit).toContainText('turn 2');

    // The ES module highlights the needle in the transcript.
    const marks = page.locator('main .events mark');
    await expect(marks).toHaveCount(1);
    await expect(marks.first()).toHaveText('quasar-needle');
  });

  test('collapsed tool calls expand', async ({ page }) => {
    const m = loadManifest();
    await signIn(page, 'alice', m.users.alice.password);
    await page.goto(sessionPath(m));

    // The <details> element itself stays visible (its summary); the
    // body is hidden until the summary is opened.
    const tool = page.locator('main #turn-3 details.event-tool-call');
    await expect(tool).toHaveJSProperty('open', false);
    await expect(tool.locator('pre')).toBeHidden();
    await tool.locator('summary').click();
    await expect(tool).toHaveJSProperty('open', true);
    await expect(tool.locator('pre')).toContainText('secret-input');
    await expect(tool.locator('summary')).toBeVisible();
  });

  test('split view switches commits through the ES module', async ({
    page,
  }) => {
    const m = loadManifest();
    await signIn(page, 'alice', m.users.alice.password);
    // Open the split view directly for the feature tip; the ES module
    // only swaps the column when one is already present (the first
    // click is plain navigation by design).
    await page.goto(`${sessionPath(m)}?split=${m.headSha}`);
    await expect(page.locator('main .split-col')).toContainText(
      m.headSha.slice(0, 7),
    );

    // A window probe proves the switch swapped the column without a
    // full navigation (which would clear it).
    await page.evaluate(() => {
      Reflect.set(window, '__sfProbe', 42);
    });

    const otherLink = page.locator(
      `main .commit-marker a[href*="split=${m.otherSha}"]`,
    );
    await expect(otherLink).toHaveCount(1);
    await otherLink.click();

    await expect(page.locator('main .split-col')).toContainText(
      m.otherSha.slice(0, 7),
    );
    await expect(page).toHaveURL(new RegExp(`split=${m.otherSha}`));
    await expect
      .poll(() => page.evaluate(() => Reflect.get(window, '__sfProbe')))
      .toBe(42);
    await expect(page.locator('main .split-col a')).toHaveText(
      'Close split view',
    );
  });

  test('page is complete without JavaScript', async ({ page, browser }) => {
    const m = loadManifest();
    // Sign in with JS (cookies are JS-independent), then re-open the
    // viewer in a JS-disabled context sharing those cookies.
    await signIn(page, 'alice', m.users.alice.password);
    const cookies = await page.context().cookies();

    const context = await browser.newContext({ javaScriptEnabled: false });
    await context.addCookies(cookies);
    const nojs = await context.newPage();
    await nojs.goto(sessionPath(m));

    // The transcript and the commit markers render server-side.
    await expect(nojs.locator('main #turn-2')).toBeVisible();
    await expect(nojs.locator('main .commit-marker')).toHaveCount(2);

    // Search works as a plain GET form: results list, no highlight JS.
    // Scoped to <main>: the header has its own search form.
    await nojs.locator('main .session-search input[name="q"]').fill('quasar-needle');
    await nojs.locator('main .session-search').getByRole('button', { name: 'Search' }).click();
    await expect(nojs.locator('main .search-results')).toContainText(
      '1 hits for quasar-needle',
    );
    await expect(
      nojs.locator('main .search-results a[href*="#turn-2"]'),
    ).toBeVisible();

    // Split view falls back to plain link navigation.
    await nojs
      .locator(`main .commit-marker a[href*="split=${m.headSha}"]`)
      .click();
    await expect(nojs.locator('main .split-col')).toContainText(
      m.headSha.slice(0, 7),
    );

    await context.close();
  });
});
