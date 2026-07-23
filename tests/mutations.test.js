#!/usr/bin/env node
// Deterministic adversarial mutation suite.
//
// Takes every structured fixture and rewrites it through realistic formatting
// variants an agent might emit — extra whitespace, tabs, newlines, quoting,
// shell-wrapper indirection (sh -c / bash -lc / cmd /c / powershell -Command),
// benign pipe suffixes, path spelling variants — and asserts the decision does
// NOT change:
//   - every BLOCK fixture must still block, with the SAME stable ruleId
//   - every ALLOW fixture must still allow (false positives are product failure)
//
// No randomness anywhere: mutations are enumerated, so a failure reproduces
// byte-for-byte. Each failure reports {fixtureId, mutation, shell, expected,
// actual, matchedRule} and the exact mutated command.
//
// Mutations that would GENUINELY change semantics for a fixture (e.g. wrapping
// a command that already contains the wrapper's quote character) declare
// themselves inapplicable rather than encode a wrong expectation.
'use strict';
const { evaluatePolicy } = require('../lib/policy.js');
const { WRAPPERS } = require('../lib/normalize-command.js');
const { CTX, ALLOW, BLOCK } = require('./fixtures/commands.js');

// ---------- the mutation catalog (deterministic, order matters for reporting) ----------

const MUTATIONS = [
  {
    name: 'double-spaces',
    shell: 'bash',
    applicable: (c) => c.includes(' '),
    apply: (c) => c.replace(/ /g, '  '),
  },
  {
    name: 'tabs-for-spaces',
    shell: 'bash',
    applicable: (c) => c.includes(' '),
    apply: (c) => c.replace(/ /g, '\t'),
  },
  {
    name: 'trailing-newline',
    shell: 'bash',
    applicable: () => true,
    apply: (c) => c + '\n',
  },
  {
    name: 'leading-newline',
    shell: 'bash',
    applicable: () => true,
    apply: (c) => '\n' + c,
  },
  {
    name: 'trailing-spaces',
    shell: 'bash',
    applicable: () => true,
    apply: (c) => c + '   ',
  },
  {
    name: 'benign-first-segment',
    shell: 'bash',
    applicable: () => true,
    apply: (c) => 'echo ok\n' + c,
  },
  {
    name: 'benign-pipe-suffix',
    shell: 'bash',
    applicable: () => true,
    apply: (c) => c + ' | cat',
  },
  {
    name: 'wrap-sh-c-double',
    shell: 'sh',
    applicable: (c) => !c.includes('"'),
    apply: (c) => `sh -c "${c}"`,
  },
  {
    name: 'wrap-sh-c-single',
    shell: 'sh',
    applicable: (c) => !c.includes("'"),
    apply: (c) => `sh -c '${c}'`,
  },
  {
    name: 'wrap-bash-lc',
    shell: 'bash',
    applicable: (c) => !c.includes('"'),
    apply: (c) => `bash -lc "${c}"`,
  },
  {
    name: 'wrap-cmd-c',
    shell: 'cmd',
    applicable: (c) => !c.includes('"'),
    apply: (c) => `cmd /c "${c}"`,
  },
  {
    name: 'wrap-powershell-command',
    shell: 'powershell',
    applicable: (c) => !c.includes('"'),
    apply: (c) => `powershell -Command "${c}"`,
  },
  {
    name: 'leading-backslash',
    shell: 'bash',
    // \sudo is not a wrapper any shell would strip — skip wrapper-prefixed fixtures
    applicable: (c) => /^[A-Za-z/]/.test(c) && !WRAPPERS.has(c.split(/\s/)[0].toLowerCase()),
    apply: (c) => '\\' + c,
  },
  {
    name: 'quote-last-token-double',
    shell: 'bash',
    applicable: (c) => !c.includes('"') && !c.includes("'") && c.trim().includes(' '),
    apply: (c) => {
      const i = c.lastIndexOf(' ');
      return c.slice(0, i + 1) + '"' + c.slice(i + 1) + '"';
    },
  },
  {
    name: 'path-root-double-slash',
    shell: 'bash',
    applicable: (c) => / \/$/.test(c),
    apply: (c) => c.replace(/\/$/, '//'),
  },
  {
    name: 'path-root-dot-suffix',
    shell: 'bash',
    applicable: (c) => / \/$/.test(c),
    apply: (c) => c.replace(/\/$/, '/.'),
  },
  {
    name: 'backslash-to-forward-slash',
    shell: 'powershell',
    applicable: (c) => c.includes('\\'),
    apply: (c) => c.replace(/\\/g, '/'),
  },
  // enumerated combinations (still deterministic)
  {
    name: 'wrap-sh-c-double+double-spaces',
    shell: 'sh',
    applicable: (c) => !c.includes('"') && c.includes(' '),
    apply: (c) => `sh -c "${c.replace(/ /g, '  ')}"`,
  },
  {
    name: 'wrap-cmd-c+tabs',
    shell: 'cmd',
    applicable: (c) => !c.includes('"') && c.includes(' '),
    apply: (c) => `cmd /c "${c.replace(/ /g, '\t')}"`,
  },
  {
    name: 'wrap-bash-lc+benign-pipe-suffix',
    shell: 'bash',
    applicable: (c) => !c.includes('"'),
    apply: (c) => `bash -lc "${c} | cat"`,
  },
];

// ---------- run ----------

let cases = 0;
let failuresList = [];
const byMutation = new Map();
const byRule = new Map();

function bump(map, key) {
  map.set(key, (map.get(key) || 0) + 1);
}

function runFixture(fx, expectedAction, expectedRuleId) {
  const ctx = fx.ctx || CTX;
  for (const mut of MUTATIONS) {
    if (!mut.applicable(fx.command)) continue;
    const mutated = mut.apply(fx.command);
    cases++;
    bump(byMutation, mut.name);
    let d;
    try {
      d = evaluatePolicy(mutated, ctx);
    } catch (e) {
      failuresList.push({
        fixtureId: fx.id, mutation: mut.name, shell: mut.shell,
        expected: expectedAction, actual: `THREW: ${e.message}`, matchedRule: null, command: mutated,
      });
      continue;
    }
    const actionOk = d.action === expectedAction;
    const ruleOk = expectedAction !== 'block' || d.ruleId === expectedRuleId;
    if (actionOk && d.ruleId) bump(byRule, d.ruleId);
    if (!actionOk || !ruleOk) {
      failuresList.push({
        fixtureId: fx.id, mutation: mut.name, shell: d.shell || mut.shell,
        expected: expectedAction === 'block' ? `block/${expectedRuleId}` : 'allow',
        actual: `${d.action}${d.ruleId ? '/' + d.ruleId : ''}`,
        matchedRule: d.ruleId || null,
        command: mutated,
      });
    }
  }
}

for (const fx of BLOCK) runFixture(fx, 'block', fx.expect.ruleId);
for (const fx of ALLOW) runFixture(fx, 'allow', null);

// ---------- report ----------

console.log(`mutation cases evaluated: ${cases} (from ${BLOCK.length} block + ${ALLOW.length} allow fixtures, ${MUTATIONS.length} mutations)`);
console.log('cases per mutation:');
for (const [name, n] of byMutation) console.log(`  ${String(n).padStart(4)}  ${name}`);
console.log('block decisions per rule:');
for (const [id, n] of [...byRule.entries()].sort((a, b) => b[1] - a[1])) console.log(`  ${String(n).padStart(4)}  ${id}`);

if (failuresList.length) {
  console.log(`\n✗ ${failuresList.length}/${cases} mutated cases failed:`);
  for (const f of failuresList) {
    console.log(JSON.stringify(f, null, 2));
  }
  process.exit(1);
}
console.log(`\n✓ all ${cases} deterministic mutation cases passed`);
process.exit(0);
