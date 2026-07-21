---
description: Generate a proof-of-work report — what changed, which quality gates pass, and what's left before this is shippable.
argument-hint: "[optional: path or scope]"
user-invocable: true
---

Produce a concise **proof-of-work report** for the current change. Do not modify
any files — this is read-only.

1. **What changed** — run `git status --short` and `git diff --stat` and summarize
   the files touched (and rough +/- lines).
2. **Quality gates** — detect and run the project's checks read-only and report
   pass/fail for each:
   - format (e.g. `npm run format` / `cargo fmt --check` / `gofmt -l .`)
   - typecheck (e.g. `tsc --noEmit` / `cargo check` / `go vet` / `mypy`)
   - tests (only if the user asks, or a fast test script exists)
   If a `.guardian.json` defines commands, use those.
3. **Verdict** — one of: ✅ ready to ship, ⚠️ ready with caveats (list them), or
   ❌ not ready (list the blocking failures with the shortest path to green).

Keep it tight: a short table or bullet list, then the verdict. This is the
artifact a reviewer or teammate reads to trust the work is done.
