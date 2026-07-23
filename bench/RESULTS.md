# Firewall benchmark results

Latency of `evaluatePolicy()` (lib/policy.js) — the pure decision engine that
runs on every PreToolUse hook call. These numbers exclude Node process startup
(the hook process itself), which dominates wall-clock time for a single hook
invocation; they isolate the cost the policy engine adds.

Produced by `npm run bench` (`bench/guard-benchmark.js`): deterministic inputs,
500 warmup + 5000 measured iterations per scenario, timed with
`process.hrtime.bigint()`.

## Windows 11, Node v24.18.0 (2026-07-23)

- os: Windows_NT 10.0.26200 (x64), 12th Gen Intel(R) Core(TM) i7-12650H
- node: v24.18.0 (note: CI runs Node 20; the engine uses no Node-24-only APIs)

| scenario | median ms | p95 ms | max ms |
|---|---:|---:|---:|
| normal allow (`git status && npm --silent test`) | 0.007 | 0.021 | 0.802 |
| block (`rm -rf /`) | 0.006 | 0.011 | 0.574 |
| wrapped block (`sh -c "cmd /c 'rm -rf /'"`) | 0.011 | 0.023 | 1.101 |
| long command (5003 chars, 65 segments) | 0.696 | 1.119 | 2.773 |

## Reading

- Typical agent commands decide in ~7 µs median; even the pathological 5 KB
  multi-segment script stays under ~3 ms worst-case. The firewall's decision
  cost is negligible next to the hook's Node startup (~tens of ms).
- Performance budget: median < 1 ms and p95 < 5 ms for the long-command
  scenario on developer hardware. A change that violates this budget needs a
  written justification in the PR.
- Max values include one-off GC/JIT outliers; median/p95 are the honest
  steady-state signal.

Rerun on your own machine with `npm run bench` and append rows rather than
overwriting history when the environment differs.
