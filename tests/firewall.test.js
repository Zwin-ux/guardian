#!/usr/bin/env node
// Fixture suite for the blast-radius firewall. No test framework — just Node.
//
// Runs every structured fixture (tests/fixtures/commands.js) through BOTH
// engines with a fixed workspace/home so path logic is deterministic on any OS:
//   1. evaluatePolicy — asserts the structured decision: action, and for
//      blocks the exact stable ruleId + category.
//   2. evaluate (legacy adapter API) — asserts the deny boolean agrees, so the
//      backward-compatible surface can never drift from the engine.
// A failing case prints and sets exit code 1.
'use strict';
const { evaluate, evaluatePolicy } = require('../hooks/guard.js');
const { RULE_CATEGORIES } = require('../lib/rules.js');
const { CTX, ALLOW, BLOCK } = require('./fixtures/commands.js');

let failures = 0;
function fail(fixture, msg, decision) {
  failures++;
  console.log(`FAIL [${fixture.id}] ${fixture.command}`);
  console.log(`      ${msg}`);
  if (decision) console.log(`      decision: ${JSON.stringify(decision)}`);
}

for (const fx of ALLOW) {
  const ctx = fx.ctx || CTX;
  let d;
  try {
    d = evaluatePolicy(fx.command, ctx);
  } catch (e) {
    fail(fx, `evaluatePolicy threw (must fail open, never throw): ${e.message}`);
    continue;
  }
  if (d.action !== 'allow') {
    fail(fx, `expected allow (${fx.rationale}), got ${d.action}`, d);
  } else if (d.ruleId !== null) {
    fail(fx, `allow decision must carry ruleId null, got ${d.ruleId}`, d);
  }
  const legacy = evaluate(fx.command, ctx);
  if (legacy.deny) fail(fx, 'legacy evaluate() denies but engine allows', legacy);
}

for (const fx of BLOCK) {
  const ctx = fx.ctx || CTX;
  let d;
  try {
    d = evaluatePolicy(fx.command, ctx);
  } catch (e) {
    fail(fx, `evaluatePolicy threw (must fail open, never throw): ${e.message}`);
    continue;
  }
  if (d.action !== 'block') {
    fail(fx, `expected block (${fx.rationale}), got ${d.action}`, d);
  } else {
    if (d.ruleId !== fx.expect.ruleId) {
      fail(fx, `expected ruleId ${fx.expect.ruleId}, got ${d.ruleId}`, d);
    }
    if (RULE_CATEGORIES[d.ruleId] !== fx.expect.category) {
      fail(fx, `expected category ${fx.expect.category}, got ${RULE_CATEGORIES[d.ruleId]}`, d);
    }
    if (!d.reason || !d.reason.trim()) fail(fx, 'block decision has an empty reason', d);
  }
  const legacy = evaluate(fx.command, ctx);
  if (!legacy.deny) fail(fx, 'legacy evaluate() allows but engine blocks', legacy);
}

const total = ALLOW.length + BLOCK.length;
if (failures === 0) {
  console.log(`✓ all ${total} firewall fixtures passed (${ALLOW.length} allow, ${BLOCK.length} block)`);
  process.exit(0);
} else {
  console.log(`\n✗ ${failures} failures across ${total} fixtures`);
  process.exit(1);
}
