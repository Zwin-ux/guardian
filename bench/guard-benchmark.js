#!/usr/bin/env node
// Firewall latency benchmark. Plain Node, no dependencies, no flags needed:
//
//   node bench/guard-benchmark.js
//
// Measures evaluatePolicy() latency (the pure engine — the exact work added to
// every PreToolUse hook call, excluding Node process startup) for four
// realistic scenarios, using process.hrtime.bigint() per call. Deterministic
// inputs; results depend only on the machine.
//
// Prints a markdown table plus environment metadata so results can be
// committed honestly (see bench/RESULTS.md) with the OS/runtime labeled.
'use strict';
const os = require('os');
const { evaluatePolicy } = require('../lib/policy.js');

const CTX = { workspace: '/repo', home: '/home/user' };
const WARMUP = 500;
const ITERATIONS = 5000;

// A deterministic ~5KB multi-segment script of ordinary build commands.
function longCommand() {
  const parts = [];
  let i = 0;
  while (parts.join(' && ').length < 5000) {
    parts.push(`echo step-${i} && npm --silent run build:part-${i} | tee logs/part-${i}.log`);
    i++;
  }
  return parts.join(' && ');
}

const SCENARIOS = [
  { name: 'normal allow', command: 'git status && npm --silent test', expect: 'allow' },
  { name: 'block (rm -rf /)', command: 'rm -rf /', expect: 'block' },
  { name: 'wrapped block', command: 'sh -c "cmd /c \'rm -rf /\'"', expect: 'block' },
  { name: `long command (${longCommand().length} chars)`, command: longCommand(), expect: 'allow' },
];

function stats(samplesNs) {
  const sorted = [...samplesNs].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
  const pick = (q) => sorted[Math.min(sorted.length - 1, Math.floor(q * sorted.length))];
  const toMs = (ns) => Number(ns) / 1e6;
  return {
    median: toMs(pick(0.5)),
    p95: toMs(pick(0.95)),
    max: toMs(sorted[sorted.length - 1]),
  };
}

function bench(scenario) {
  // sanity: the scenario must decide what it claims, or the numbers are noise
  const d = evaluatePolicy(scenario.command, CTX);
  if (d.action !== scenario.expect) {
    console.error(`ABORT: scenario "${scenario.name}" expected ${scenario.expect}, engine returned ${d.action} (${d.ruleId})`);
    process.exit(1);
  }
  for (let i = 0; i < WARMUP; i++) evaluatePolicy(scenario.command, CTX);
  const samples = new Array(ITERATIONS);
  for (let i = 0; i < ITERATIONS; i++) {
    const t0 = process.hrtime.bigint();
    evaluatePolicy(scenario.command, CTX);
    samples[i] = process.hrtime.bigint() - t0;
  }
  return stats(samples);
}

const rows = [];
for (const s of SCENARIOS) {
  const r = bench(s);
  rows.push({ name: s.name, ...r });
}

const fmt = (n) => n.toFixed(3);
console.log(`# Guardian firewall benchmark`);
console.log(``);
console.log(`- engine: evaluatePolicy() (lib/policy.js), pure in-process calls`);
console.log(`- iterations: ${ITERATIONS} per scenario (after ${WARMUP} warmup)`);
console.log(`- node: ${process.version}`);
console.log(`- os: ${os.type()} ${os.release()} (${os.arch()}), ${os.cpus()[0] ? os.cpus()[0].model.trim() : 'unknown CPU'}`);
console.log(`- date: ${new Date().toISOString().slice(0, 10)}`);
console.log(``);
console.log(`| scenario | median ms | p95 ms | max ms |`);
console.log(`|---|---:|---:|---:|`);
for (const r of rows) {
  console.log(`| ${r.name} | ${fmt(r.median)} | ${fmt(r.p95)} | ${fmt(r.max)} |`);
}
