#!/usr/bin/env node
// Grok Build Guardian — blast-radius firewall (PreToolUse hook).
//
// Thin adapter over the pure policy engine in lib/policy.js. This file owns
// ONLY the integration edges: reading the hook envelope from stdin, resolving
// workspace/home from the real environment, and mapping the structured
// decision onto the hook protocol. All rule logic lives in lib/rules.js.
//
// Denies a shell command only when it crosses an unambiguous safety boundary:
// irreversible destruction (delete/format/wipe outside the repo or at a system
// root) or secret exfiltration / remote-code execution. Everything else is
// allowed. Threat model: a good-faith agent emitting a catastrophic command —
// NOT a human deliberately evading the guard. Therefore: FAIL-OPEN everywhere,
// no shell-variable resolution, and a hard bias to allow.
//
// Contract: reads the PreToolUse JSON envelope on stdin; on a block it prints
// {"decision":"deny","reason":"..."} to stdout; otherwise prints nothing —
// except an internal engine error, which prints a non-blocking
// {"systemMessage":"..."} warning (visible fail-open). Always exits 0 — a deny
// is honored via stdout regardless of exit code, and any error must never
// block real work.
'use strict';

const { evaluatePolicy } = require('../lib/policy.js');

// Resolve the evaluation context from explicit opts, falling back to the
// process environment. This is the ONLY place environment defaults are read;
// the policy engine itself is pure.
function resolveContext(opts) {
  opts = opts || {};
  return {
    home: opts.home || process.env.HOME || process.env.USERPROFILE || '/home/user',
    workspace: opts.workspace || process.env.GROK_WORKSPACE_ROOT || process.cwd(),
    shell: opts.shell,
  };
}

// Backward-compatible API: evaluate(command, opts) -> { deny, reason? }.
// Existing integrations and the historical fixture suite use this shape.
function evaluate(command, opts) {
  const d = evaluatePolicy(command, resolveContext(opts));
  if (d.action === 'block') return { deny: true, reason: d.reason };
  return { deny: false };
}

// ---------- CLI entrypoint (fail-open) ----------

function runCli() {
  let data = '';
  process.stdin.setEncoding('utf8');
  process.stdin.on('data', (d) => (data += d));
  process.stdin.on('end', () => {
    try {
      const env = JSON.parse(data || '{}');
      const toolName = env.tool_name || env.toolName || '';
      if (toolName && !/^bash$|run_terminal_command/i.test(toolName)) return process.exit(0);
      if (env.toolInputTruncated || env.tool_input_truncated) return process.exit(0);
      const command = (env.tool_input && env.tool_input.command) || (env.toolInput && env.toolInput.command) || '';
      if (!command || typeof command !== 'string') return process.exit(0);
      const verdict = evaluatePolicy(command, resolveContext());
      if (verdict.action === 'block') {
        process.stdout.write(JSON.stringify({ decision: 'deny', reason: verdict.reason }));
      } else if (verdict.action === 'warn') {
        // fail-open, but visibly: no "decision" key means the command is
        // allowed; the message surfaces the internal problem.
        process.stdout.write(JSON.stringify({ systemMessage: `⚠️ ${verdict.reason}` }));
      }
    } catch (_) {
      // fail-open: never block on an internal error
    }
    process.exit(0);
  });
  process.stdin.on('error', () => process.exit(0));
}

if (require.main === module) runCli();
module.exports = { evaluate, evaluatePolicy };
