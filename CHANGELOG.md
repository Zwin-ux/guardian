# Changelog

All notable changes to Grok Build Guardian. Format follows
[Keep a Changelog](https://keepachangelog.com/); versions follow semver.

## [0.2.0] - 2026-07-22

### Changed
- **Firewall refactored into a pure structured policy engine** (`lib/`):
  `evaluatePolicy(command, ctx)` returns a stable decision
  `{action, ruleId, reason, matchedText, shell, limitations}`. Every rule is a
  data object with a stable id in `lib/rules.js`. `hooks/guard.js` is now a
  thin adapter; the legacy `evaluate(command, opts)` API is unchanged.
- Internal firewall errors now surface a visible non-blocking `systemMessage`
  warning instead of a silent allow (still fail-open).
- Done-gate: skipped checks (missing tool, timeout) now emit a visible
  `additionalContext` warning instead of passing silently.

### Added
- Shell-wrapper unwrapping for `bash -lc`-style option clusters and multi-arg
  `powershell -Command` (previously only exact `-c`/`-Command` next-arg forms).
- `ENV_PIPE_EXFIL` now catches bare `env | curl …` (was allowed while
  `printenv | curl …` blocked, because `env` was stripped as a wrapper).
- `tools/check-command.js` — read-only decision inspector (prints JSON,
  always exits 0).
- `tools/validate-manifests.js` — CI check that both plugin manifests parse
  and agree with `package.json` on name/version.
- Structured fixture suite (51 cases asserting exact rule ids) + 855-case
  deterministic adversarial mutation suite + 15-case done-gate integration
  suite with real temp projects. `npm test` runs all three.
- `bench/guard-benchmark.js` + committed measured results
  (`bench/RESULTS.md`): median 0.007 ms per decision, < 3 ms worst-case for a
  5 KB command (Windows 11, Node v24.18.0).
- `THREAT_MODEL.md`: assets, adversary, per-rule scope table, and a verified
  known-bypass corpus.

### Fixed
- Done-gate blocked instead of failing open when a detected toolchain was not
  actually installed (`cargo`/`go`/`python -m mypy` missing): shell
  not-found exits (127/126, Windows "is not recognized", "No module named")
  are now treated as skipped checks, with a visible warning.
- Done-gate's gofmt special case (exit 0 + unformatted-file list on stdout)
  never fired because stage stdout was not captured on success; it now blocks
  as documented.

### Security
- GitHub Actions pinned to full commit SHAs in CI.

## [0.1.0] - 2026-07-19

### Added
- Blast-radius firewall (`hooks/guard.js`): PreToolUse hook denying
  catastrophic shell commands (recursive deletes of dangerous paths, `.git`
  deletion, disk formatting, `curl | bash`, credential/env exfiltration) with
  a hard bias to allow and fail-open error handling.
- Definition-of-Done gate (`hooks/done-gate.js`): Stop/SubagentStop hook
  running detected format/typecheck (tests opt-in) commands and blocking a
  false "done", with no-progress escape and `GUARDIAN_SKIP=1` bypass.
- 50 firewall fixtures running in CI on Linux/macOS/Windows.
- `/proof` command, `finisher` agent, `clean-finish` skill.
