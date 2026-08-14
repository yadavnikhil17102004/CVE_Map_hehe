#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');
const { performance } = require('perf_hooks');

const DATA_PATH = path.resolve(process.cwd(), 'data/2026.json');
const INTEL_PATH = path.resolve(process.cwd(), 'data/nvd_intel_2026.json');

const data = JSON.parse(fs.readFileSync(DATA_PATH, 'utf8'));
const intel = JSON.parse(fs.readFileSync(INTEL_PATH, 'utf8'));
const cves = data.cves || [];

function median(values) {
  const arr = [...values].sort((a, b) => a - b);
  const m = Math.floor(arr.length / 2);
  return arr.length % 2 ? arr[m] : (arr[m - 1] + arr[m]) / 2;
}

function avg(values) {
  return values.reduce((a, b) => a + b, 0) / Math.max(1, values.length);
}

function runBenchmark(label, fn, runs = 12) {
  const samples = [];
  for (let i = 0; i < runs; i++) {
    const t0 = performance.now();
    fn();
    const t1 = performance.now();
    samples.push(t1 - t0);
  }
  return { label, samples, median: median(samples), avg: avg(samples) };
}

function inferTypeFromText(text) {
  if (/\brce\b|remote.?code.?exec|code.?execution/.test(text)) return 'RCE';
  if (/zero.?day|0day/.test(text)) return 'Zero-Day';
  if (/\blpe\b|privilege.?escal|local.?privesc/.test(text)) return 'LPE';
  if (/inject|sqli|\bxss\b|\bssti\b/.test(text)) return 'Inject';
  if (/\bdos\b|denial.of.service|flood|crash/.test(text)) return 'DoS';
  if (/bypass|auth.bypass/.test(text)) return 'Bypass';
  if (/\bpoc\b|proof.of.concept|writeup/.test(text)) return 'PoC';
  return 'Exploit';
}

function baselineLookup(ids) {
  for (const id of ids) {
    cves.find(c => c.cve_id === id);
  }
}

function baselineSortByDate() {
  const list = [...cves];
  list.sort((a, b) => {
    const da = Math.max(0, ...(a.repositories || []).map(r => r.pushed_at ? new Date(r.pushed_at).getTime() : 0));
    const db = Math.max(0, ...(b.repositories || []).map(r => r.pushed_at ? new Date(r.pushed_at).getTime() : 0));
    return db - da;
  });
  return list;
}

function baselineRenderPrep(limit = 600) {
  const list = cves.slice(0, limit);
  return list.map(cve => {
    const repos = cve.repositories || [];
    const stars = repos.reduce((s, r) => s + (r.stargazers_count || 0), 0);
    const latestEpoch = Math.max(0, ...repos.map(r => r.pushed_at ? new Date(r.pushed_at).getTime() : 0));
    const text = [cve.cve_id, ...repos.map(r => (r.description || '') + (r.full_name || ''))].join(' ').toLowerCase();
    const type = inferTypeFromText(text);
    return { id: cve.cve_id, stars, latestEpoch, type };
  });
}

function baselineChartMetrics(year = 2026) {
  const trend = new Array(12).fill(0);
  const crit = new Array(12).fill(0);
  for (const cve of cves) {
    const score = intel[cve.cve_id]?.s || 0;
    const isCrit = score >= 9.0;
    for (const r of (cve.repositories || [])) {
      if (!r.pushed_at) continue;
      const d = new Date(r.pushed_at);
      if (d.getFullYear() !== year) continue;
      const m = d.getMonth();
      trend[m]++;
      if (isCrit) crit[m]++;
    }
  }
  return { trend, crit };
}

function buildMeta() {
  const byId = Object.create(null);
  const metaById = Object.create(null);
  for (const cve of cves) {
    byId[cve.cve_id] = cve;
    const monthCounts = new Array(12).fill(0);
    let stars = 0;
    let latestEpoch = 0;
    const parts = [cve.cve_id];
    for (const r of (cve.repositories || [])) {
      stars += r.stargazers_count || 0;
      parts.push((r.description || '') + (r.full_name || ''));
      if (r.pushed_at) {
        const d = new Date(r.pushed_at);
        const epoch = d.getTime();
        if (epoch > latestEpoch) latestEpoch = epoch;
        if (!Number.isNaN(epoch)) monthCounts[d.getMonth()] += 1;
      }
    }
    metaById[cve.cve_id] = {
      stars,
      latestEpoch,
      type: inferTypeFromText(parts.join(' ').toLowerCase()),
      monthCounts,
    };
  }
  return { byId, metaById };
}

const optimizedCtx = buildMeta();

function optimizedLookup(ids) {
  for (const id of ids) {
    optimizedCtx.byId[id];
  }
}

function optimizedSortByDate() {
  const list = [...cves];
  list.sort((a, b) => {
    return optimizedCtx.metaById[b.cve_id].latestEpoch - optimizedCtx.metaById[a.cve_id].latestEpoch;
  });
  return list;
}

function optimizedRenderPrep(limit = 600) {
  const list = cves.slice(0, limit);
  return list.map(cve => {
    const m = optimizedCtx.metaById[cve.cve_id];
    return { id: cve.cve_id, stars: m.stars, latestEpoch: m.latestEpoch, type: m.type };
  });
}

function optimizedChartMetrics() {
  const trend = new Array(12).fill(0);
  const crit = new Array(12).fill(0);
  for (const cve of cves) {
    const score = intel[cve.cve_id]?.s || 0;
    const isCrit = score >= 9.0;
    const mc = optimizedCtx.metaById[cve.cve_id].monthCounts;
    for (let i = 0; i < 12; i++) {
      if (!mc[i]) continue;
      trend[i] += mc[i];
      if (isCrit) crit[i] += mc[i];
    }
  }
  return { trend, crit };
}

const ids = cves.slice(0, 1200).map(c => c.cve_id);

const benches = [
  ['Detail lookup (1200 ids)', () => baselineLookup(ids), () => optimizedLookup(ids), 20],
  ['Sort by latest date', baselineSortByDate, optimizedSortByDate, 12],
  ['Row prep (600 rows)', () => baselineRenderPrep(600), () => optimizedRenderPrep(600), 16],
  ['Chart metrics build', baselineChartMetrics, optimizedChartMetrics, 14],
];

const results = [];
for (const [name, beforeFn, afterFn, runs] of benches) {
  const before = runBenchmark(`${name} (before)`, beforeFn, runs);
  const after = runBenchmark(`${name} (after)`, afterFn, runs);
  const improvement = ((before.median - after.median) / before.median) * 100;
  results.push({ name, before, after, improvement });
}

console.log(`Dataset: ${cves.length} CVEs, ${cves.reduce((s, c) => s + (c.repositories || []).length, 0)} repos`);
console.log('');
console.log('| Benchmark | Before median (ms) | After median (ms) | Improvement |');
console.log('|---|---:|---:|---:|');
for (const r of results) {
  console.log(`| ${r.name} | ${r.before.median.toFixed(2)} | ${r.after.median.toFixed(2)} | ${r.improvement.toFixed(1)}% |`);
}
