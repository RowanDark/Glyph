import AxeBuilder from '@axe-core/playwright';
import { expect, test } from '@playwright/test';

type RouteTarget = {
  name: string;
  path: string;
  readySelector: string;
};

const ROUTES: RouteTarget[] = [
  {
    name: 'Operations overview',
    path: '/',
    readySelector: 'h1:has-text("Operations overview")'
  },
  {
    name: 'Runs',
    path: '/runs',
    readySelector: 'h1:has-text("Runs")'
  },
  {
    name: 'Flows',
    path: '/flows',
    readySelector: 'h1:has-text("Flow timeline")'
  },
  {
    name: 'Cases',
    path: '/cases',
    readySelector: 'main'
  }
];

const SERIOUS_IMPACTS = new Set(['serious', 'critical']);

test.describe('Accessibility regressions', () => {
  for (const route of ROUTES) {
    test(`should not introduce critical issues on ${route.name}`, async ({ page }, testInfo) => {
      await page.goto(route.path, { waitUntil: 'domcontentloaded' });
      await page.waitForSelector(route.readySelector, { state: 'visible' });

      const analysis = await new AxeBuilder({ page })
        .include('main')
        .analyze();

      const seriousViolations = analysis.violations.filter((violation) =>
        SERIOUS_IMPACTS.has(violation.impact ?? '')
      );

      const summary = analysis.violations
        .map((violation) => `${violation.impact ?? 'unknown'}: ${violation.id} → ${violation.help}`)
        .join('\n');

      await testInfo.attach('axe-report', {
        body: Buffer.from(JSON.stringify(analysis, null, 2)),
        contentType: 'application/json'
      });

      if (summary) {
        await testInfo.attach('axe-summary.txt', {
          body: Buffer.from(summary),
          contentType: 'text/plain'
        });
      }

      expect.soft(analysis.violations.length, 'Accessibility violations detected').toBe(0);
      expect(seriousViolations, 'Critical accessibility regressions detected').toEqual([]);
    });
  }
});
