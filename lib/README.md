# Guardian Core Library

The first refactor should move command handling into pure, testable modules:

- `normalize-command.js` converts raw shell input into a normalized representation while preserving the original command.
- `policy.js` evaluates the normalized command and returns a structured decision.
- `types.js` documents the stable decision shape used by hooks, tests, and the proof command.

Target decision shape:

```json
{
  "action": "allow",
  "ruleId": null,
  "reason": "No dangerous pattern matched.",
  "matchedText": null,
  "shell": "bash",
  "warnings": []
}
```

The policy engine must not read files, environment variables, network state, or process-global configuration. Hooks may perform integration work, but the core decision must remain a pure function.
