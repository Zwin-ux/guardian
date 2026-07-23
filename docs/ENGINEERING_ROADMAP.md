# Engineering Roadmap

Guardian should remain narrow: prevent common catastrophic commands and block false completion when fast project checks fail. The roadmap strengthens the current promise through structured decisions, adversarial testing, measurable latency, and release integrity.

## Release 1 — Structured command decision engine

### Goal
Separate command normalization, policy evaluation, and user-facing output so every allow/block decision is testable and explainable.

### Build
- `lib/normalize-command.js`: normalize shell wrappers, whitespace, quoting, platform separators, and common command-shell prefixes.
- `lib/policy.js`: pure function that evaluates a normalized command.
- Return a structured decision: `action`, `ruleId`, `reason`, `matchedText`, `shell`, and `limitations`.
- Move rule definitions into a readable data structure rather than scattered conditionals.
- Add a read-only CLI: `node tools/check-command.js --shell bash --json -- <command>`.
- Preserve fail-open behavior for parser errors, but return a structured warning.
- Document platform-specific assumptions for Bash, PowerShell, CMD, and POSIX shells.

### Done when
- The policy engine is a pure function with no process or filesystem side effects.
- Every blocked fixture includes an expected rule ID and reason.
- Every allowed fixture proves it does not match any blocking rule.
- JSON output is stable and contains no prose outside the response object.

## Release 2 — Adversarial mutation suite

### Goal
Measure how the firewall behaves when harmless and dangerous commands are rewritten through quoting, spacing, wrappers, and platform syntax.

### Build
- Expand fixtures into structured cases with command, shell, expected action, and rationale.
- Deterministic mutation generator using only the Node standard library.
- Mutations: repeated whitespace, tabs/newlines, quote styles, escaped separators, `sh -c`, `bash -lc`, `cmd /c`, PowerShell `-Command`, path variants, environment-variable spelling, and benign pipeline changes.
- Dedicated regression fixtures for every discovered false positive and false negative.
- Report allow/block counts by rule and shell.
- Add a documented corpus of known bypasses that are outside the threat model rather than hiding them.

### Done when
- CI evaluates at least 200 deterministic mutated cases.
- Failures identify the source fixture, mutation, shell, expected decision, and actual rule.
- False-positive-sensitive allow cases remain at least as numerous as block cases.
- Known unsupported evasions are documented with a reason they remain out of scope.

## Release 3 — Definition-of-Done integration tests

### Goal
Prove the completion gate detects projects and handles failures correctly across Node, Python, Rust, and Go.

### Build
- Temporary fixture projects for each supported ecosystem.
- Test format, typecheck, test opt-in, missing toolchain, timeout, malformed config, repeated identical failure, bypass variable, and disabled gate.
- Refactor command discovery into a pure function returning chosen commands and rationale.
- Cap captured output and redact obvious credential-like environment values.
- Add structured gate result output for the `/proof` command.
- Test that the gate never runs commands outside the project root.

### Done when
- Integration tests exercise real child processes in isolated temporary directories.
- Missing tools and parser errors fail open with visible warnings.
- A repeated unchanged failure follows the documented escape behavior.
- The proof report lists commands, exit codes, durations, and final shippability.

## Release 4 — Performance and observability

### Goal
Demonstrate that safety hooks do not noticeably slow normal agent workflows.

### Build
- `bench/guard-benchmark.js`: benchmark allow, block, wrapped, and long-command cases.
- Measure median, p95, and maximum decision latency over a fixed number of iterations.
- Add a performance budget for the command firewall.
- Add optional debug logging controlled by `GUARDIAN_DEBUG=1`; keep default behavior silent and local.
- Include rule-hit counts in test artifacts.

### Done when
- CI runs a stable smoke benchmark without flaky hard timing assertions.
- Release documentation reports representative local benchmark numbers and environment.
- Debug mode explains normalization and rule matching without exposing secrets.
- Default operation still uses no network, telemetry, runtime dependencies, or binaries.

## Release 5 — Release and supply-chain hardening

### Goal
Make the plugin artifact and its claims independently verifiable.

### Build
- Pin GitHub Actions to reviewed full commit SHAs.
- Add syntax checks, full tests, integration tests, mutation tests, and benchmark smoke checks to the three-OS matrix.
- Add `THREAT_MODEL.md`, `SECURITY.md`, `CHANGELOG.md`, and responsible disclosure instructions.
- Validate plugin manifests and generated catalog metadata in CI.
- Add a release checklist with version consistency checks.
- Produce one demo showing a catastrophic command blocked, a normal cleanup allowed, and a failing typecheck preventing completion.
- Keep limitation language next to security claims.

### Done when
- A tagged release maps to a specific tested commit.
- Marketplace metadata pins the intended commit.
- README claims can be traced to fixtures, integration tests, benchmarks, or the threat model.
- The plugin remains small enough for a reviewer to audit directly.
