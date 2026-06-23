#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');
const { chromium } = require('playwright');

const baseURL = (process.argv[2] || process.env.BASE_URL || 'http://127.0.0.1:8000').replace(/\/$/, '');
const outDir = path.resolve(process.cwd(), 'artifacts', 'issue-6');
const outFile = path.join(outDir, 'ci-smoke-results.json');
fs.mkdirSync(outDir, { recursive: true });

const summary = {
  baseURL,
  started_at: new Date().toISOString(),
  checks: [],
};

function parseCount(text) {
  const match = String(text || '').match(/(\d[\d,]*)/);
  return match ? Number(match[1].replace(/,/g, '')) : null;
}

async function waitFor(predicate, label, timeoutMs = 15000, intervalMs = 250) {
  const started = Date.now();
  let lastError = null;
  while (Date.now() - started < timeoutMs) {
    try {
      if (await predicate()) return;
    } catch (err) {
      lastError = err;
    }
    await new Promise(resolve => setTimeout(resolve, intervalMs));
  }
  const detail = lastError ? ` (${lastError.message})` : '';
  throw new Error(`Timed out waiting for ${label}${detail}`);
}

async function textOf(locator) {
  const text = await locator.textContent();
  return (text || '').trim();
}

function record(name, details) {
  summary.checks.push({ name, ...details });
}

async function smokeDashboard(page) {
  await page.goto(`${baseURL}/dashboard.html`, { waitUntil: 'domcontentloaded' });
  await waitFor(async () => (await page.locator('#cve-list .cve-row').count()) > 0, 'dashboard rows');

  const initialText = await textOf(page.locator('#result-count'));
  const initialCount = parseCount(initialText);
  if (!initialCount || initialCount < 1) {
    throw new Error(`Dashboard did not expose a usable result count: ${initialText || '(blank)'}`);
  }

  const firstCve = await textOf(page.locator('#cve-list .cve-row .font-mono').first());
  if (!firstCve) throw new Error('Could not read first CVE id from dashboard rows');

  const searchInput = page.locator('#search-input');
  await searchInput.fill(firstCve);
  await waitFor(async () => {
    const text = await textOf(page.locator('#result-count'));
    return /1 result\b/i.test(text);
  }, 'dashboard exact search result');

  const exactText = await textOf(page.locator('#result-count'));
  const exactCount = parseCount(exactText);
  if (exactCount !== 1) {
    throw new Error(`Exact dashboard search should yield 1 result, got: ${exactText}`);
  }

  await searchInput.fill('');
  await waitFor(async () => parseCount(await textOf(page.locator('#result-count'))) === initialCount, 'dashboard search reset');

  await page.selectOption('#severity-filter', 'critical');
  await waitFor(async () => {
    const count = parseCount(await textOf(page.locator('#result-count')));
    return count !== null && count < initialCount;
  }, 'dashboard severity filter');
  const criticalText = await textOf(page.locator('#result-count'));
  const criticalCount = parseCount(criticalText);
  if (criticalCount === null || criticalCount >= initialCount) {
    throw new Error(`Severity filter did not reduce dashboard results: ${criticalText}`);
  }

  await page.click('#clear-filters');
  await waitFor(async () => parseCount(await textOf(page.locator('#result-count'))) === initialCount, 'dashboard clear filters');

  await page.selectOption('#kev-filter', 'only');
  await waitFor(async () => {
    const count = parseCount(await textOf(page.locator('#result-count')));
    return count !== null && count < initialCount;
  }, 'dashboard KEV filter');
  const kevText = await textOf(page.locator('#result-count'));
  const kevCount = parseCount(kevText);
  if (kevCount === null || kevCount >= initialCount) {
    throw new Error(`KEV filter did not reduce dashboard results: ${kevText}`);
  }

  record('dashboard', {
    initial_count: initialCount,
    exact_search: firstCve,
    exact_count: exactCount,
    critical_count: criticalCount,
    kev_count: kevCount,
  });
}

async function smokeNews(page) {
  await page.goto(`${baseURL}/news.html`, { waitUntil: 'domcontentloaded' });
  await waitFor(async () => (await page.locator('#news-grid a').count()) > 0, 'news cards');

  const cards = page.locator('#news-grid a');
  const initialCount = await cards.count();
  if (initialCount < 1) throw new Error('News grid did not render any cards');

  const firstTitle = await textOf(page.locator('#news-grid a p.text-xs.font-mono').first());
  if (!firstTitle) throw new Error('Could not read first news title');

  await page.locator('#news-search').fill(firstTitle);
  await waitFor(async () => (await page.locator('#news-grid a').count()) === 1, 'news exact search');
  const exactCount = await page.locator('#news-grid a').count();
  if (exactCount !== 1) throw new Error(`Exact news search should yield 1 card, got ${exactCount}`);

  await page.locator('#news-search').fill('');
  await waitFor(async () => (await page.locator('#news-grid a').count()) === initialCount, 'news search reset');

  await page.selectOption('#tier-filter', '4');
  await waitFor(async () => (await page.locator('#news-grid a').count()) < initialCount, 'news tier filter');
  const tierCount = await page.locator('#news-grid a').count();
  if (tierCount >= initialCount) {
    throw new Error(`Tier filter did not reduce news cards: ${tierCount} >= ${initialCount}`);
  }

  record('news', {
    initial_cards: initialCount,
    exact_title: firstTitle,
    exact_count: exactCount,
    tier_4_count: tierCount,
  });
}

async function smokeIndex(page) {
  await page.goto(`${baseURL}/index.html`, { waitUntil: 'domcontentloaded' });
  await waitFor(async () => (await page.locator('#news-feed a').count()) > 0, 'index news feed');

  const feedCount = await page.locator('#news-feed a').count();
  const firstHeadline = await textOf(page.locator('#news-feed a p.text-xs.font-mono').first());
  if (!firstHeadline) throw new Error('Home page news feed headline missing');

  const loadingVisible = await page.locator('#news-loading').isVisible().catch(() => false);
  if (loadingVisible) throw new Error('Home page loading state never cleared');

  record('index', {
    feed_count: feedCount,
    first_headline: firstHeadline,
  });
}

async function smokeDocs(page) {
  await page.goto(`${baseURL}/docs.html`, { waitUntil: 'domcontentloaded' });
  await waitFor(async () => {
    const texts = await Promise.all([
      textOf(page.locator('#active-sensors')),
      textOf(page.locator('#cves-current-year')),
      textOf(page.locator('#critical-cves')),
      textOf(page.locator('#epss-coverage')),
    ]);
    return texts.every(text => text && text !== '...');
  }, 'docs stats');

  const stats = {
    active_sensors: await textOf(page.locator('#active-sensors')),
    cves_current_year: await textOf(page.locator('#cves-current-year')),
    critical_cves: await textOf(page.locator('#critical-cves')),
    epss_coverage: await textOf(page.locator('#epss-coverage')),
    version: await textOf(page.locator('#version-badge')),
  };

  if (!/^v\d+/i.test(stats.version)) {
    throw new Error(`Docs version badge missing or malformed: ${stats.version}`);
  }

  record('docs', stats);
}

async function main() {
  const browser = await chromium.launch({ headless: true });
  const page = await browser.newPage({ viewport: { width: 1440, height: 1200 } });

  try {
    await smokeDashboard(page);
    await smokeNews(page);
    await smokeIndex(page);
    await smokeDocs(page);
    summary.status = 'pass';
    summary.finished_at = new Date().toISOString();
    fs.writeFileSync(outFile, JSON.stringify(summary, null, 2) + '\n');
    console.log(`PASS ${outFile}`);
  } catch (err) {
    summary.status = 'fail';
    summary.error = err.message;
    summary.finished_at = new Date().toISOString();
    fs.writeFileSync(outFile, JSON.stringify(summary, null, 2) + '\n');
    console.error(`FAIL ${err.stack || err.message}`);
    try {
      await page.screenshot({ path: path.join(outDir, 'failure.png'), fullPage: true });
    } catch (_) {}
    process.exitCode = 1;
  } finally {
    await page.close().catch(() => {});
    await browser.close().catch(() => {});
  }
}

main().catch(err => {
  summary.status = 'fail';
  summary.error = err.message;
  summary.finished_at = new Date().toISOString();
  fs.writeFileSync(outFile, JSON.stringify(summary, null, 2) + '\n');
  console.error(err.stack || err.message);
  process.exit(1);
});
