#!/usr/bin/env node
/**
 * Smoke-drive the built console in a headless browser: both themes, every route,
 * assert no console errors and no horizontal overflow. Exits non-zero on failure.
 * Requires the console built (apps/web/dist) and a simple static server.
 *
 * Usage: CONSOLE_URL=http://localhost:4173 node scripts/ui-check.mjs
 * (Falls back to `vite preview` if CONSOLE_URL is unset and dist exists.)
 */

import { spawn } from 'node:child_process';
import { existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, '..');
const dist = join(root, 'apps/web/dist');

let url = process.env.CONSOLE_URL ?? 'http://localhost:4173';
let preview = null;

async function main() {
  if (!process.env.CONSOLE_URL && existsSync(dist)) {
    preview = spawn('npx', ['vite', 'preview', '--port', '4173', '--strictPort'], {
      cwd: join(root, 'apps/web'),
      shell: true,
      stdio: 'ignore',
    });
    await new Promise((r) => setTimeout(r, 2000));
  }

  // Dynamic import so the script fails cleanly when Puppeteer/Playwright is absent.
  const { default: puppeteer } = await import('puppeteer').catch(() => ({ default: null }));
  if (!puppeteer) {
    console.log('Puppeteer not installed — skipping the browser smoke check.');
    console.log('  npm i -D puppeteer  # then re-run');
    preview?.kill();
    process.exit(0);
  }

  const browser = await puppeteer.launch({ headless: 'new' });
  const page = await browser.newPage();
  await page.setViewport({ width: 1280, height: 800 });

  const errors = [];
  page.on('pageerror', (err) => errors.push(`pageerror: ${err.message}`));
  page.on('console', (msg) => {
    if (msg.type() === 'error') errors.push(`console.error: ${msg.text()}`);
  });

  const routes = ['', '#/dashboard', '#/batches', '#/transactions', '#/recipients', '#/analytics', '#/reports', '#/security'];

  for (const theme of ['light', 'dark']) {
    for (const route of routes) {
      await page.goto(`${url}/${route}`, { waitUntil: 'networkidle0', timeout: 15000 });
      await page.evaluate((t) => localStorage.setItem('solvaren.theme', t), theme);
      await page.reload({ waitUntil: 'networkidle0' });

      const overflow = await page.evaluate(
        () => document.documentElement.scrollWidth > document.documentElement.clientWidth,
      );
      if (overflow) errors.push(`overflow-x at ${route} (${theme})`);
      console.log(`  ${theme.padEnd(5)} ${route || '/'} ok`);
    }
  }

  // Mobile viewport spot-check.
  await page.setViewport({ width: 390, height: 844 });
  await page.goto(`${url}/`, { waitUntil: 'networkidle0' });
  const mobileOverflow = await page.evaluate(
    () => document.documentElement.scrollWidth > document.documentElement.clientWidth,
  );
  if (mobileOverflow) errors.push('overflow-x at / (mobile 390px)');

  await browser.close();
  preview?.kill();

  if (errors.length > 0) {
    console.error('\n✗ UI check failures:');
    for (const e of errors) console.error(`  - ${e}`);
    process.exit(1);
  }
  console.log('\n✓ Console renders clean in both themes, all routes, desktop + mobile.');
}

main().catch((err) => {
  console.error(err instanceof Error ? err.message : err);
  preview?.kill();
  process.exit(1);
});
