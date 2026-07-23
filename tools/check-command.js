#!/usr/bin/env node
// Guardian — read-only command inspector.
//
//   node tools/check-command.js "rm -rf /"
//   node tools/check-command.js --shell powershell -- "Remove-Item -Recurse C:\\"
//   node tools/check-command.js --workspace /repo --home /home/user "git clean -fx"
//
// Prints the structured policy decision as JSON and ALWAYS exits 0 — this tool
// never blocks anything; it only explains what the firewall would decide.
// Workspace/home default from the environment exactly like the hook does.
'use strict';

const { evaluatePolicy } = require('../lib/policy.js');

function main(argv) {
  const opts = {};
  const rest = [];
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--') {
      rest.push(...argv.slice(i + 1));
      break;
    } else if (a === '--shell') opts.shell = argv[++i];
    else if (a === '--workspace') opts.workspace = argv[++i];
    else if (a === '--home') opts.home = argv[++i];
    else if (a === '--help' || a === '-h') {
      process.stdout.write(
        'usage: node tools/check-command.js [--shell S] [--workspace P] [--home P] [--] "<command>"\n' +
        'Prints the firewall decision as JSON. Read-only; always exits 0.\n'
      );
      return;
    } else rest.push(a);
  }

  const command = rest.join(' ');
  const ctx = {
    home: opts.home || process.env.HOME || process.env.USERPROFILE || '/home/user',
    workspace: opts.workspace || process.env.GROK_WORKSPACE_ROOT || process.cwd(),
    shell: opts.shell,
  };

  let out;
  try {
    out = evaluatePolicy(command, ctx);
  } catch (e) {
    // evaluatePolicy already fails open internally; this is belt-and-braces.
    out = {
      action: 'warn',
      ruleId: 'INTERNAL_ERROR',
      reason: String(e && e.message ? e.message : e),
      matchedText: null,
      shell: ctx.shell || 'bash',
      limitations: [],
    };
  }
  process.stdout.write(JSON.stringify(out, null, 2) + '\n');
}

main(process.argv.slice(2));
process.exit(0);
