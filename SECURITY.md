# Security

Grok Build Guardian is a security tool, so it holds itself to its own bar.

## Guarantees

- **No network.** Neither hook makes any network request. There is no telemetry,
  no analytics, no "phone home." You can verify this by reading `hooks/guard.js`
  and `hooks/done-gate.js` — they are short, dependency-free Node scripts.
- **No credential access.** The firewall reads the command string from the hook
  envelope on stdin to decide allow/deny. It never reads your secrets, and it
  exists specifically to stop other commands from exfiltrating them.
- **No dependencies.** Pure Node standard library. No `node_modules`, no
  install step, no third-party supply chain.
- **Fail-open by design.** If a hook errors or times out it allows the action.
  Guardian can miss an edge case; it will not brick your workflow.

## What runs on your machine

- `hooks/guard.js` — a `PreToolUse` hook that inspects shell commands and returns
  `deny` for a small set of catastrophic patterns. Read-only analysis of the
  command text.
- `hooks/done-gate.js` — a `Stop`/`SubagentStop` hook that runs your project's
  own `format`/`typecheck`/`test` commands (auto-detected or configured in
  `.guardian.json`). It executes *your* toolchain in *your* repo; it ships no
  commands of its own to run.

## Reporting a vulnerability

Open a private security advisory on the GitHub repository
([Zwin-ux/guardian](https://github.com/Zwin-ux/guardian/security/advisories)),
or contact the maintainer listed in `.grok-plugin/plugin.json`. Please do not
open a public issue for a vulnerability.

**Responsible disclosure:** report privately first; you'll get an
acknowledgment within 7 days. Please allow up to 90 days for a fix before any
public disclosure — Guardian will credit reporters in the changelog unless you
prefer otherwise. Note that documented out-of-scope bypasses
(see `THREAT_MODEL.md`) are limitations, not vulnerabilities; a report that a
*good-faith agent's accidental command* slips through IS in scope and very
welcome.
