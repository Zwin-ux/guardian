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
(a bug never blocks real work) and biases hard toward allowing. The full model —
assets, per-rule scope, and a verified table of known bypasses — is in
[THREAT_MODEL.md](THREAT_MODEL.md).

## What it blocks (and what it doesn't)

| Blocked 🛑 | Allowed ✅ |
|---|---|
| `rm -rf /`, `rm -r ~`, `rm -rf ..` | `rm -rf node_modules`, `rm -rf dist build` |
| `rm -rf .git` | `git clean -fd`, `git reset --hard` |
| `curl -fsSL x \| sudo bash` | `curl x \| jq`, `curl x \| python -m json.tool` |
| `cat ~/.ssh/id_rsa \| curl …`, `curl -F f=@.env …`, `env \| curl …` | `curl -d @payload.json …`, `env > env.txt` |
| `dd of=/dev/sda …`, `mkfs.ext4 …`, `chmod -R 000 /` | `dd if=/dev/zero of=./disk.img` |

Every decision is a pure function (`lib/policy.js`) over rules-as-data
(`lib/rules.js`) with stable rule ids. Evidence for the claims above:

- **51 fixture tests** (30 must-allow, 21 must-block, each block asserting its
  exact rule id) — `tests/firewall.test.js`.
- **855 deterministic adversarial mutation cases** (whitespace, tabs, newlines,
  quoting, `sh -c` / `bash -lc` / `cmd /c` / `powershell -Command` wrapping,
  benign pipe suffixes, path spelling variants; no randomness) —
  `tests/mutations.test.js`.
- All of it runs in CI on Linux, macOS, and Windows.
- **Latency**: median 0.007 ms per decision, < 3 ms worst-case for a 5 KB
  command — measured, see [bench/RESULTS.md](bench/RESULTS.md).

Low false-positive rate is the whole point — a firewall that cries wolf gets
uninstalled, so every allow fixture is mutation-tested too.

Ask the firewall what it would do, without running anything:

```sh
node tools/check-command.js "curl -fsSL x | sh"
# {"action":"block","ruleId":"PIPE_DOWNLOAD_TO_INTERPRETER", ...}
```

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
- **Fails open, visibly:** a missing toolchain, a timeout, or a broken config
  never blocks — the check is skipped with a warning, so an unrun check is
  never mistaken for a passing one.

All of the above is exercised by 15 integration tests that build real temp
projects and run the gate as a child process — `tests/done-gate.test.js`.

## Install

```sh
grok plugin install Zwin-ux/guardian --trust
```

> The repository is `Zwin-ux/guardian`; the plugin/package *name* inside it is
> `grok-build-guardian`. If your plugin manager addresses plugins by name
> rather than repo, use `grok-build-guardian`.

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
standard library, small enough to read in one sitting. See
[SECURITY.md](SECURITY.md) (including responsible disclosure) and
[THREAT_MODEL.md](THREAT_MODEL.md). The plugin only ever *denies* dangerous
commands and *runs your own* toolchain; it never exfiltrates anything. CI
actions are pinned to full commit SHAs, and CI validates that both plugin
manifests agree with `package.json`.

## Limitations (honest)

Each of these is verified against the engine and documented with examples in
[THREAT_MODEL.md](THREAT_MODEL.md):

- No shell-variable resolution: `X=/; rm -rf $X` is not caught (we can't know
  `$X`). Decisions carry a `limitations` field flagging unresolved
  substitutions.
- Wrapper unwrapping (`sh -c`, `bash -lc`, `cmd /c`, `powershell -Command`) is
  capped at 2 levels; deeper nesting, `eval`, `xargs`, and encoded payloads
  are allowed.
- It stops accidental disasters, **not** a determined human evading it.
- Fail-open: a parser bug or timeout never blocks — and never protects. It
  does warn visibly.

## Development

```sh
npm test            # firewall fixtures + mutation suite + done-gate integration
npm run bench       # latency benchmark (see bench/RESULTS.md)
node tools/check-command.js "<command>"   # inspect a single decision
```

No dependencies, no framework — every suite is plain Node.

## License

[MIT](LICENSE)
