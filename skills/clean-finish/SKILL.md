---
name: clean-finish
description: Definition-of-done discipline for coding work — before calling a change complete, ensure it is formatted, type-checks, tests pass, and the diff is scoped. Use when finishing a task, preparing to commit, or when the user says "wrap up", "finish", or "is this done?".
when-to-use: At the end of a coding task, before committing or shipping, or whenever deciding whether work is actually complete.
---

# Clean finish

"Done" means the change is **shippable**, not just written. Before you call a
task complete, verify — don't assume:

## The definition of done

1. **Formatted.** The code matches the project's formatter (`npm run format`,
   `cargo fmt`, `gofmt`, `ruff format`, …). Never leave a diff the formatter would rewrite.
2. **Type-checks.** No new type errors (`tsc --noEmit`, `cargo check`, `go vet`,
   `mypy`). A green typecheck is cheap and catches whole classes of bugs.
3. **Tests pass.** Run the relevant tests. If you changed behavior, the tests
   should reflect it. If you couldn't run tests, say so explicitly.
4. **Scoped diff.** `git diff` contains only what this task needed — no stray
   debug prints, commented-out code, unrelated reformatting, or secrets.
5. **Proof, not vibes.** State what you ran and what passed. "Tests pass" without
   having run them is a claim, not a fact.

## How to work

- Run the gates yourself before declaring done. If Grok Build Guardian's gate
  blocks your turn, that's this discipline enforced — fix the failures, don't
  bypass them.
- If a check can't run (missing toolchain, environment issue), report that
  honestly instead of claiming success.
- Prefer the smallest change that makes the gate pass. Don't disable a lint rule
  or delete a failing test to go green.

A change that is written but unformatted, untyped, and untested is not finished —
it's a draft that looks finished.
