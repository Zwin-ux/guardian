# 🛡 Grok Build Guardian

**Makes coding agents finish work cleanly.** Two guardrails in one plugin for
[Grok Build](https://x.ai/cli):

1. **Blast-radius firewall** — blocks catastrophic shell commands *before they run*
   (`rm -rf /`, `curl … | bash`, a `.env` piped to the network, formatting a disk,
   deleting `.git`), while staying out of your way for everyday commands.
2. **Definition-of-Done gate** — won't let the agent end its turn until your code is
   formatted, type-checks, and (optionally) tests pass — then it reports what it did.

Local, auditable, **no network, no telemetry, no dependencies, no binaries.**

> **Independent community project.** Not affiliated with, endorsed by, or sponsored
> by xAI. "Grok" and "Grok Build" are trademarks of xAI.

---

## Why

An AI coding agent is fast and mostly right — but "mostly" is the problem. It can
fat-finger an `rm -rf` with a bad path expansion, `curl | bash` a hallucinated URL,
or declare a task "done" with a failing type-check. Guardian is a safety net for
exactly those good-faith mistakes.

**Threat model:** it defends against *the agent* generating a destructive command in
good faith — not a human deliberately trying to evade it. That's why it fails open
(a bug never blocks real work) and biases hard toward allowing.

## What it blocks (and what it doesn't)

| Blocked 🛑 | Allowed ✅ |
|---|---|
| `rm -rf /`, `rm -r ~`, `rm -rf ..` | `rm -rf node_modules`, `rm -rf dist build` |
| `rm -rf .git` | `git clean -fd`, `git reset --hard` |
| `curl -fsSL x \| sudo bash` | `curl x \| jq`, `curl x \| python -m json.tool` |
| `cat ~/.ssh/id_rsa \| curl …`, `curl -F f=@.env …` | `curl -d @payload.json …`, `curl -F c=@.env.example …` |
| `dd of=/dev/sda …`, `mkfs.ext4 …`, `chmod -R 000 /` | `dd if=/dev/zero of=./disk.img` |

The firewall ships with **50 fixture tests** (30 must-allow, 20 must-block) that run
in CI on Linux, macOS, and Windows. Low false-positive rate is the whole point — a
firewall that cries wolf gets uninstalled.

## The Definition-of-Done gate

When the agent tries to finish, Guardian runs your project's fast checks and blocks
the finish with actionable feedback until they pass:

```
🛡 Guardian: work isn't finished cleanly yet.

❌ typecheck failed:
src/api.ts(42,7): error TS2322: Type 'string' is not assignable to type 'number'.

Fix the above, then finish.
```

- **Zero-config** for Node, Rust, Go, and Python — it reads `package.json` scripts,
  `Cargo.toml`, `go.mod`, or `pyproject.toml`.
- **Fast by default:** format-check + typecheck only. Tests are opt-in (they're
  slow and sometimes known-failing) — enable with `"tests": true`.
- **Never traps you:** if the same failure repeats with no change, it stops blocking
  and lets you finish with a warning. Bypass anytime with `GUARDIAN_SKIP=1` or by
  disabling it in `.guardian.json`.

## Install

```sh
grok plugin install Zwin-ux/grok-build-guardian --trust
```

Requires Node.js on `PATH` (already present in most dev environments). If Node is
missing, the hooks fail open — you simply get no protection, never a broken shell.

## Configure

Optional `.guardian.json` in your repo root (all fields optional; defaults shown):

```json
{
  "gate": { "enabled": true, "format": true, "typecheck": true, "tests": false },
  "commands": { "format": null, "typecheck": null, "test": null }
}
```

Set `commands` to override the auto-detected commands, or `"enabled": false` to turn
the completion gate off entirely (the firewall keeps running).

## Commands, agents, skills

- **`/proof`** — a read-only proof-of-work report: what changed, which gates pass,
  and whether it's shippable.
- **`finisher` agent** — a focused clean-up pass that runs the gates and fixes what
  they surface, minimally.
- **`clean-finish` skill** — the definition-of-done discipline, auto-applied.

## Security

No network, no telemetry, no credentials, no dependencies, no binaries — pure Node
standard library in two short, readable files. See [SECURITY.md](SECURITY.md). The
plugin only ever *denies* dangerous commands and *runs your own* toolchain; it never
exfiltrates anything.

## Limitations (honest)

- No shell-variable resolution: `X=/; rm -rf $X` is not caught (we can't know `$X`).
- One level of `sh -c` / `cmd /c` unwrapping; deeper nesting or `$(…)` is allowed.
- It stops accidental disasters, **not** a determined human evading it.
- Fail-open: a parser bug or timeout never blocks — and never protects.

## Development

```sh
npm test   # runs the firewall fixture suite (no dependencies)
```

## License

[MIT](LICENSE)
