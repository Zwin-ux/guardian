# Guardian Core Library

The command firewall is a pure, structured policy engine:

- `normalize-command.js` — tokenization and normalization: path/quote/whitespace
  handling, top-level segment splitting, argv tokenization, and shell-wrapper
  unwrapping (`sh -c`, `bash -lc`, `powershell -Command`, `cmd /c`). Pure text
  functions only.
- `rules.js` — every firewall rule as a data object `{ id, category, scope,
  describe, evaluate }` with a **stable rule id** (e.g.
  `RECURSIVE_DELETE_DANGEROUS_PATH`). Rule ids are referenced by tests, the
  mutation suite, and `THREAT_MODEL.md`; never rename one — add new ids instead.
- `policy.js` — `evaluatePolicy(command, ctx)`: the pure decision function.
- `decision.js` — constructors for the stable decision shape.

Decision shape:

```json
{
  "action": "allow",
  "ruleId": null,
  "reason": "No dangerous pattern matched.",
  "matchedText": null,
  "shell": "bash",
  "limitations": []
}
```

- `action` is `"allow"`, `"block"`, or `"warn"`. `"warn"` is the fail-open
  signal: the engine hit an internal error, the command is allowed, and the
  caller must surface the warning visibly.
- `limitations` lists analysis limits that applied to *this* command (e.g.
  unresolved `$(...)` substitution, wrapper nesting beyond the depth cap) so a
  consumer never mistakes "allow" for "proven safe".

Purity contract: the policy engine must not read files, environment variables,
network state, or process-global configuration. `ctx` carries `workspace`,
`home`, and optionally `shell` explicitly. Integration edges (stdin envelope,
environment defaults, hook protocol output) live only in `hooks/guard.js` and
`tools/check-command.js`.

## Platform assumptions

- **bash / POSIX shells**: segments split on `&&`, `||`, `;`, and newlines;
  pipes split on `|`; single/double quotes respected; backslash escapes are
  NOT interpreted. `sh -c` / `bash -lc` unwrap takes the next argument only
  (POSIX semantics: later args become `$0`, `$1`, …).
- **PowerShell**: `-Command` (or `-c`) consumes the rest of the argument list.
  PowerShell-specific operators (`-and`, subexpressions `$( )`) are not parsed.
- **CMD**: `cmd /c` and `cmd /k` consume the rest of the argument list.
- Shell variables and command substitutions are never resolved (see
  `THREAT_MODEL.md`); the decision reports this in `limitations`.
