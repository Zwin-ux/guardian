#!/usr/bin/env node
// Grok Build Guardian — Definition-of-Done gate (Stop / SubagentStop hook).
//
// When the agent tries to end its turn, run the project's fast quality gates
// (format-check + typecheck by default; tests opt-in) and BLOCK the stop with
// actionable feedback until they pass. Then the turn can finish.
//
// Discipline (mirrors the firewall): FAIL-OPEN on everything — a gate that
// can't run, times out, or errors must never trap the agent. Never block twice
// on the identical unchanged failure (no-progress → allow + warn). Zero-config
// for common stacks; fully overridable via `.guardian.json`; opt-out anytime.
'use strict';
const fs = require('fs');
const path = require('path');
const os = require('os');
const { execSync } = require('child_process');
const crypto = require('crypto');

function readStdin() {
  return new Promise((resolve) => {
    let d = '';
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', (c) => (d += c));
    process.stdin.on('end', () => resolve(d));
    process.stdin.on('error', () => resolve(''));
  });
}

function loadConfig(root) {
  const cfg = { enabled: true, format: true, typecheck: true, tests: false, commands: {} };
  try {
    const p = path.join(root, '.guardian.json');
    if (fs.existsSync(p)) {
      const j = JSON.parse(fs.readFileSync(p, 'utf8'));
      const g = j.gate || j;
      for (const k of ['enabled', 'format', 'typecheck', 'tests']) if (k in g) cfg[k] = g[k];
      if (j.commands) cfg.commands = j.commands;
    }
  } catch (_) {}
  return cfg;
}

function has(root, f) {
  try {
    return fs.existsSync(path.join(root, f));
  } catch (_) {
    return false;
  }
}

// Detect the project toolchain → { format, typecheck, test } shell commands.
// Only returns a command when we're confident it exists; unknown → undefined.
function detectToolchain(root) {
  const t = {};
  if (has(root, 'package.json')) {
    let scripts = {};
    try {
      scripts = (JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8')).scripts) || {};
    } catch (_) {}
    if (scripts.format) t.format = 'npm run format';
    else if (scripts.lint) t.format = 'npm run lint';
    if (scripts.typecheck) t.typecheck = 'npm run typecheck';
    else if (has(root, 'tsconfig.json')) t.typecheck = 'npx --no-install tsc --noEmit';
    if (scripts.test) t.test = 'npm test';
  } else if (has(root, 'Cargo.toml')) {
    t.format = 'cargo fmt --check';
    t.typecheck = 'cargo check -q';
    t.test = 'cargo test -q';
  } else if (has(root, 'go.mod')) {
    t.format = 'gofmt -l .';
    t.typecheck = 'go vet ./...';
    t.test = 'go test ./...';
  } else if (has(root, 'pyproject.toml') || has(root, 'setup.cfg')) {
    t.typecheck = 'python -m mypy .';
    t.test = 'python -m pytest -q';
  }
  return t;
}

function stateFile(root) {
  const h = crypto.createHash('sha1').update(root).digest('hex').slice(0, 12);
  return path.join(os.tmpdir(), `guardian-gate-${h}.json`);
}

function runStage(name, cmd, root) {
  try {
    execSync(cmd, { cwd: root, stdio: ['ignore', 'pipe', 'pipe'], timeout: 120000, encoding: 'utf8' });
    return { name, ok: true };
  } catch (e) {
    const out = `${(e.stdout || '')}\n${(e.stderr || '')}`.trim();
    // gofmt -l prints files but exits 0; treat non-empty stdout as failure
    return { name, ok: false, output: out.slice(0, 1200) };
  }
}

async function main() {
  const root = process.env.GROK_WORKSPACE_ROOT || process.cwd();
  // Escape hatches
  if (process.env.GUARDIAN_SKIP === '1') return process.exit(0);
  const cfg = loadConfig(root);
  if (!cfg.enabled) return process.exit(0);

  await readStdin(); // envelope not required for the gate; drain it

  const tc = { ...detectToolchain(root), ...cfg.commands };
  const stages = [];
  if (cfg.format && tc.format) stages.push(['format', tc.format]);
  if (cfg.typecheck && tc.typecheck) stages.push(['typecheck', tc.typecheck]);
  if (cfg.tests && tc.test) stages.push(['tests', tc.test]);
  if (stages.length === 0) return process.exit(0); // no toolchain → do nothing (fail-open)

  const failures = [];
  for (const [name, cmd] of stages) {
    const r = runStage(name, cmd, root);
    // gofmt special-case: exits 0 but lists unformatted files on stdout
    if (r.ok && name === 'format' && cmd.startsWith('gofmt') && (r.output || '').trim()) r.ok = false;
    if (!r.ok) failures.push(r);
  }

  if (failures.length === 0) return process.exit(0); // clean finish — allow

  // No-progress guard: if the identical failures repeat, stop blocking.
  const sig = crypto
    .createHash('sha1')
    .update(failures.map((f) => f.name + (f.output || '')).join('|'))
    .digest('hex');
  try {
    const sf = stateFile(root);
    const prev = fs.existsSync(sf) ? JSON.parse(fs.readFileSync(sf, 'utf8')) : {};
    if (prev.sig === sig) {
      fs.unlinkSync(sf);
      const note = `⚠️ Guardian: ${failures.map((f) => f.name).join(', ')} still failing (no change since last attempt). Allowing finish — fix these before shipping.`;
      process.stdout.write(JSON.stringify({ hookSpecificOutput: { hookEventName: 'Stop', additionalContext: note } }));
      return process.exit(0);
    }
    fs.writeFileSync(sf, JSON.stringify({ sig }));
  } catch (_) {}

  const summary = failures
    .map((f) => `❌ ${f.name} failed:\n${(f.output || '(no output)').split('\n').slice(0, 12).join('\n')}`)
    .join('\n\n');
  const reason = `🛡 Guardian: work isn't finished cleanly yet.\n\n${summary}\n\nFix the above, then finish. (Set "gate.enabled": false in .guardian.json, or GUARDIAN_SKIP=1, to bypass.)`;
  process.stdout.write(JSON.stringify({ decision: 'block', reason }));
  process.exit(0);
}

main().catch(() => process.exit(0)); // fail-open on any unhandled error
