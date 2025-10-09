import { test } from '@playwright/test';

const COLOR_DEFICIENCIES = [
  'deuteranopia',
  'protanopia',
  'tritanopia'
] as const;

const FILTER_MATRICES: Record<(typeof COLOR_DEFICIENCIES)[number], string> = {
  deuteranopia: '0.367322 0.860646 -0.227968 0 0 0.280085 0.672501 0.047413 0 0 -0.011820 0.042940 0.968881 0 0 0 0 0 1 0',
  protanopia: '0.152286 1.052583 -0.204868 0 0 0.114503 0.786281 0.099216 0 0 -0.003882 -0.048116 1.051998 0 0 0 0 0 1 0',
  tritanopia: '1.255528 -0.076749 -0.178779 0 0 -0.078411 0.930809 0.147602 0 0 0.004733 -0.048130 1.043397 0 0 0 0 0 1 0'
};

type RouteTarget = {
  name: string;
  slug: string;
  path: string;
  readySelector: string;
};

const ROUTES: RouteTarget[] = [
  {
    name: 'Operations overview',
    slug: 'dashboard',
    path: '/',
    readySelector: 'h1:has-text("Operations overview")'
  },
  {
    name: 'Runs',
    slug: 'runs',
    path: '/runs',
    readySelector: 'h1:has-text("Runs")'
  },
  {
    name: 'Flows',
    slug: 'flows',
    path: '/flows',
    readySelector: 'h1:has-text("Flow timeline")'
  }
];

async function applyFilter(page: Parameters<typeof test>[0]['page'], filterId: string, matrix: string) {
  await page.evaluate(([id, values]) => {
    let svg = document.getElementById('vision-filter-root') as SVGSVGElement | null;
    if (!svg) {
      svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
      svg.setAttribute('id', 'vision-filter-root');
      svg.setAttribute('aria-hidden', 'true');
      svg.setAttribute('focusable', 'false');
      svg.style.position = 'absolute';
      svg.style.width = '0';
      svg.style.height = '0';
      const defs = document.createElementNS('http://www.w3.org/2000/svg', 'defs');
      svg.appendChild(defs);
      document.body.prepend(svg);
    }

    const defs = svg.querySelector('defs')!;
    let filter = defs.querySelector(`#${id}`) as SVGFilterElement | null;
    if (!filter) {
      filter = document.createElementNS('http://www.w3.org/2000/svg', 'filter');
      filter.setAttribute('id', id);
      defs.appendChild(filter);
    }

    let matrixElement = filter.querySelector('feColorMatrix');
    if (!matrixElement) {
      matrixElement = document.createElementNS('http://www.w3.org/2000/svg', 'feColorMatrix');
      matrixElement.setAttribute('type', 'matrix');
      filter.appendChild(matrixElement);
    }

    matrixElement.setAttribute('values', values);
    document.documentElement.style.filter = `url(#${id})`;
  }, [filterId, matrix]);
}

test.describe('Color vision regressions', () => {
  for (const route of ROUTES) {
    test(`captures colorblind previews for ${route.name}`, async ({ page }, testInfo) => {
      await page.goto(route.path, { waitUntil: 'domcontentloaded' });
      await page.waitForSelector(route.readySelector, { state: 'visible' });

      for (const deficiency of COLOR_DEFICIENCIES) {
        await applyFilter(page, `vision-${route.slug}-${deficiency}`, FILTER_MATRICES[deficiency]);
        const screenshot = await page.screenshot({ fullPage: true });
        await testInfo.attach(`${route.slug}-${deficiency}.png`, {
          body: screenshot,
          contentType: 'image/png'
        });
      }

      await page.evaluate(() => {
        document.documentElement.style.filter = 'none';
      });
    });
  }
});
