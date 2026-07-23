// Guardian core — the stable decision shape.
//
// Every policy evaluation returns exactly this object. Hooks, tests, the
// mutation suite, and tools/check-command.js all consume it; treat additions
// as additive and never repurpose a field.
//
//   {
//     action:      "allow" | "block" | "warn",
//     ruleId:      string | null,   // stable rule identifier, e.g. RECURSIVE_DELETE_DANGEROUS_PATH
//     reason:      string,          // human-readable explanation (user-facing on block)
//     matchedText: string | null,   // the command fragment that triggered the rule
//     shell:       string,          // shell context the match was interpreted under
//     limitations: string[]         // analysis limits that applied to THIS command
//   }
//
// "warn" is the fail-open signal: the engine hit an internal error and the
// command is ALLOWED, but the caller should surface the warning visibly.
'use strict';

function allow(shell, limitations) {
  return {
    action: 'allow',
    ruleId: null,
    reason: 'No dangerous pattern matched.',
    matchedText: null,
    shell: shell || 'bash',
    limitations: limitations || [],
  };
}

function block(ruleId, reason, matchedText, shell, limitations) {
  return {
    action: 'block',
    ruleId,
    reason,
    matchedText: matchedText || null,
    shell: shell || 'bash',
    limitations: limitations || [],
  };
}

function warn(ruleId, reason, shell, limitations) {
  return {
    action: 'warn',
    ruleId: ruleId || 'INTERNAL_ERROR',
    reason,
    matchedText: null,
    shell: shell || 'bash',
    limitations: limitations || [],
  };
}

module.exports = { allow, block, warn };
