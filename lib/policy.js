// Guardian core — pure policy evaluation.
//
// evaluatePolicy(command, ctx) -> decision (see lib/decision.js).
//
// PURE by contract: no process.exit, no fs, no network, and no environment
// reads. Everything the engine needs arrives in `ctx`:
//   { workspace: string, home: string, shell?: string }
// The hook adapter (hooks/guard.js) is responsible for resolving defaults
// from the real environment before calling in.
//
// Fail-open: an internal error never throws out of this function — it returns
// a `warn` decision (action "warn" = allowed, but surface the warning).
'use strict';

const {
  normalizePath,
  splitTop,
  splitSegments,
  tokenize,
  bareCommand,
  parseFlags,
  unwrapShellStage,
} = require('./normalize-command.js');
const { PIPELINE_RULES, SEGMENT_RULES, STAGE_RULES } = require('./rules.js');
const decision = require('./decision.js');

const MAX_UNWRAP_DEPTH = 2;

const LIMITATION_NESTING = `shell wrappers nested deeper than ${MAX_UNWRAP_DEPTH} levels are not analyzed`;
const LIMITATION_SUBSTITUTION = 'shell variables and $(...)/backtick substitutions are not resolved';

function buildStage(str) {
  const argv = tokenize(str);
  const bc = bareCommand(argv);
  return {
    str,
    argv,
    bc,
    c: bc.cmd.toLowerCase(),
    parsed: parseFlags(bc.args),
  };
}

// Evaluate one top-level segment (recursing into unwrapped shell wrappers).
// Returns { id, reason, matchedText, shell } or null.
function evalSegment(segment, ctx, depth, state, shell) {
  if (depth > MAX_UNWRAP_DEPTH) {
    state.limitations.add(LIMITATION_NESTING);
    return null;
  }

  const stages = splitTop(segment, ['|']).map(buildStage);

  // pipeline rules, stage-major (historical first-match ordering)
  for (let i = 0; i < stages.length; i++) {
    for (const rule of PIPELINE_RULES) {
      const m = rule.evaluate(stages, i, ctx);
      if (m) return { id: m.id || rule.id, reason: m.reason, matchedText: m.matchedText, shell };
    }
  }

  // segment rules
  for (const rule of SEGMENT_RULES) {
    const m = rule.evaluate(segment, stages, ctx);
    if (m) return { id: m.id || rule.id, reason: m.reason, matchedText: m.matchedText, shell };
  }

  // stage rules (unwrap shell wrappers first, exactly like the original engine)
  for (const stage of stages) {
    const wrapped = unwrapShellStage(stage.argv);
    if (wrapped && wrapped.command) {
      for (const inner of splitSegments(wrapped.command)) {
        const r = evalSegment(inner, ctx, depth + 1, state, wrapped.shell);
        if (r) return r;
      }
    }
    for (const rule of STAGE_RULES) {
      const m = rule.evaluate(stage, segment, ctx);
      if (m) return { id: m.id || rule.id, reason: m.reason, matchedText: m.matchedText, shell };
    }
  }
  return null;
}

function evaluatePolicy(command, ctx) {
  const shell = (ctx && ctx.shell) || 'bash';
  try {
    if (typeof command !== 'string' || !command.trim()) {
      return decision.allow(shell);
    }
    const context = {
      home: normalizePath((ctx && ctx.home) || '/home/user'),
      workspace: normalizePath((ctx && ctx.workspace) || '/workspace'),
    };
    const state = { limitations: new Set() };
    if (/\$\(|`|\$\{?[A-Za-z_]/.test(command)) {
      // honest signal: anything behind a substitution is invisible to us
      state.limitations.add(LIMITATION_SUBSTITUTION);
    }

    for (const segment of splitSegments(command)) {
      const hit = evalSegment(segment, context, 0, state, shell);
      if (hit) {
        return decision.block(hit.id, hit.reason, (hit.matchedText || '').trim() || null, hit.shell, [...state.limitations]);
      }
    }
    return decision.allow(shell, [...state.limitations]);
  } catch (e) {
    // fail-open: internal errors allow, but visibly
    return decision.warn(
      'INTERNAL_ERROR',
      `Guardian firewall hit an internal error while analyzing this command and is allowing it (fail-open): ${e && e.message ? e.message : e}`,
      shell
    );
  }
}

module.exports = { evaluatePolicy, MAX_UNWRAP_DEPTH };
