#!/usr/bin/env node
// Integration tests for the Definition-of-Done gate (hooks/done-gate.js).
//
// Each case builds a REAL temp project in os.tmpdir() and runs done-gate.js as
// a child process with cwd = the project, stdin = a Stop-hook JSON envelope,
// and TMP/TEMP/TMPDIR pointed at a per-case sandbox so the gate's no-progress
// state file is isolated and inspectable.
//
// The gate's contract under test:
//   - passing checks        -> exit 0, no stdout (allow)
//   - failing check         -> {"decision":"block"} with truncated output
//   - GUARDIAN_SKIP=1       -> allow, silent
//   - gate.enabled: false   -> allow, silent
//   - malformed config      -> fail-open (defaults still apply)
//   - timeout               -> stage skipped, allow with a visible warning
//   - missing toolchain     -> stage skipped, allow with a visible warning
//   - repeated identical failure -> no-progress: allow with warning, then re-arm
//   - gofmt with unformatted files (exit 0 + stdout) -> block
//   - state file lands in os.tmpdir()
//   - the gate process ALWAYS exits 0 (decisions travel via stdout)
//
// Cases whose toolchain is absent on this machine (python/gofmt) SKIP loudly
// rather than fake a result. No test framework — just Node.
'use strict';
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync, execSync } = require('child_process');

const GATE = path.join(__dirname, '..', 'hooks', 'done-gate.js');
const ENVELOPE = JSON.stringify({ hook_event_name: 'Stop' });

const suiteRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'guardian-gate-test-'));
let caseNo = 0;
let failures = 0;
let skips = 0;

function makeCase(name) {
  caseNo++;
  const dir = path.join(suiteRoot, `case-${String(caseNo).padStart(2, '0')}-${name}`);
  const proj = path.join(dir, 'project');
  const tmp = path.join(dir, 'tmp');
  fs.mkdirSync(proj, { recursive: true });
  fs.mkdirSync(tmp, { recursive: true });
  return { name, proj, tmp };
}

function write(proj, file, content) {
  fs.writeFileSync(path.join(proj, file), content);
}

function runGate(tc, envOverrides) {
  const env = { ...process.env, ...envOverrides };
  delete env.GUARDIAN_SKIP; // never inherit from the host session
  env.GROK_WORKSPACE_ROOT = tc.proj;
  env.TMP = tc.tmp;
  env.TEMP = tc.tmp;
  env.TMPDIR = tc.tmp;
  if (envOverrides && envOverrides.GUARDIAN_SKIP) env.GUARDIAN_SKIP = envOverrides.GUARDIAN_SKIP;
  const r = spawnSync(process.execPath, [GATE], {
    cwd: tc.proj,
    env,
    input: ENVELOPE,
    encoding: 'utf8',
    timeout: 120000,
  });
  return { status: r.status, stdout: r.stdout || '', stderr: r.stderr || '' };
}

function check(tc, label, cond, detail) {
  if (cond) return;
  failures++;
  console.log(`FAIL [${tc.name}] ${label}`);
  if (detail !== undefined) console.log(`      ${String(detail).slice(0, 600)}`);
}

function toolAvailable(cmd) {
  try {
    execSync(cmd, { stdio: ['ignore', 'pipe', 'pipe'], timeout: 30000 });
    return true;
  } catch (_) {
    return false;
  }
}

// PATH with cargo/go directories removed, to simulate a missing toolchain.
function pathWithoutRustGo() {
  const sep = path.delimiter;
  return (process.env.PATH || process.env.Path || '')
    .split(sep)
    .filter((p) => !/cargo/i.test(p) && !/[\\/]go[\\/]?(bin)?[\\/]?$/i.test(p))
    .join(sep);
}

const nodeCmd = (js) => `node -e "${js}"`; // js must not contain double quotes

// ---------- 1. Node project, passing checks (real npm-script detection) ----------
{
  const tc = makeCase('node-pass');
  write(tc.proj, 'package.json', JSON.stringify({
    name: 'fixture-pass', version: '1.0.0',
    scripts: { format: nodeCmd('process.exit(0)'), typecheck: nodeCmd('process.exit(0)') },
  }, null, 2));
  const r = runGate(tc);
  check(tc, 'exit 0', r.status === 0, `status=${r.status} stderr=${r.stderr}`);
  check(tc, 'no output on clean pass', r.stdout.trim() === '', r.stdout);
}

// ---------- 2. Node project, failing typecheck blocks with output ----------
{
  const tc = makeCase('node-fail-blocks');
  write(tc.proj, 'package.json', JSON.stringify({ name: 'fixture-fail', version: '1.0.0', scripts: {} }, null, 2));
  write(tc.proj, '.guardian.json', JSON.stringify({
    commands: { typecheck: nodeCmd("console.error('TS2322: type mismatch'); process.exit(1)") },
  }));
  const r = runGate(tc);
  check(tc, 'exit 0 even on block', r.status === 0, `status=${r.status}`);
  let out = null;
  try { out = JSON.parse(r.stdout); } catch (_) {}
  check(tc, 'stdout is block JSON', out && out.decision === 'block', r.stdout);
  check(tc, 'reason names the failing stage', out && /typecheck failed/.test(out.reason), out && out.reason);
  check(tc, 'reason carries the tool output', out && /TS2322/.test(out.reason), out && out.reason);

  // ---------- 3. identical failure again -> no-progress allow + warning ----------
  const r2 = runGate(tc);
  check(tc, 'second run exit 0', r2.status === 0);
  let out2 = null;
  try { out2 = JSON.parse(r2.stdout); } catch (_) {}
  check(tc, 'second identical failure stops blocking', out2 && !out2.decision, r2.stdout);
  check(
    tc, 'no-progress warning is visible',
    out2 && out2.hookSpecificOutput && /still failing/.test(out2.hookSpecificOutput.additionalContext || ''),
    r2.stdout
  );

  // ---------- 4. third run re-arms (state file was consumed) ----------
  const r3 = runGate(tc);
  let out3 = null;
  try { out3 = JSON.parse(r3.stdout); } catch (_) {}
  check(tc, 'third run blocks again (re-armed)', out3 && out3.decision === 'block', r3.stdout);

  // ---------- 5. state file isolation: it lived in our sandboxed tmp ----------
  const stateFiles = fs.readdirSync(tc.tmp).filter((f) => /^guardian-gate-.*\.json$/.test(f));
  check(tc, 'state file written to os.tmpdir() sandbox', stateFiles.length === 1, fs.readdirSync(tc.tmp).join(','));
}

// ---------- 6. GUARDIAN_SKIP=1 bypasses everything ----------
{
  const tc = makeCase('guardian-skip');
  write(tc.proj, 'package.json', JSON.stringify({ name: 'x', version: '1.0.0', scripts: {} }));
  write(tc.proj, '.guardian.json', JSON.stringify({ commands: { typecheck: nodeCmd('process.exit(1)') } }));
  const r = runGate(tc, { GUARDIAN_SKIP: '1' });
  check(tc, 'exit 0', r.status === 0);
  check(tc, 'silent allow', r.stdout.trim() === '', r.stdout);
}

// ---------- 7. gate.enabled: false disables the gate ----------
{
  const tc = makeCase('gate-disabled');
  write(tc.proj, 'package.json', JSON.stringify({ name: 'x', version: '1.0.0', scripts: {} }));
  write(tc.proj, '.guardian.json', JSON.stringify({
    gate: { enabled: false },
    commands: { typecheck: nodeCmd('process.exit(1)') },
  }));
  const r = runGate(tc);
  check(tc, 'exit 0', r.status === 0);
  check(tc, 'silent allow', r.stdout.trim() === '', r.stdout);
}

// ---------- 8. malformed .guardian.json + no toolchain -> fail-open allow ----------
{
  const tc = makeCase('malformed-config-no-toolchain');
  write(tc.proj, '.guardian.json', '{ this is not JSON');
  const r = runGate(tc);
  check(tc, 'exit 0', r.status === 0, `status=${r.status} stderr=${r.stderr}`);
  check(tc, 'silent allow', r.stdout.trim() === '', r.stdout);
}

// ---------- 9. malformed config does NOT disable the gate (defaults apply) ----------
{
  const tc = makeCase('malformed-config-defaults-apply');
  write(tc.proj, '.guardian.json', '{ "gate": { "enabled": false '); // broken JSON: enabled:false must NOT take effect
  write(tc.proj, 'package.json', JSON.stringify({
    name: 'x', version: '1.0.0',
    scripts: { typecheck: nodeCmd("console.error('boom'); process.exit(1)") },
  }));
  const r = runGate(tc);
  let out = null;
  try { out = JSON.parse(r.stdout); } catch (_) {}
  check(tc, 'broken config falls back to defaults and still blocks', out && out.decision === 'block', r.stdout);
}

// ---------- 10. timeout -> skipped, allow, visible warning ----------
{
  const tc = makeCase('timeout-skips');
  write(tc.proj, 'package.json', JSON.stringify({ name: 'x', version: '1.0.0', scripts: {} }));
  write(tc.proj, '.guardian.json', JSON.stringify({
    gate: { timeout_ms: 400 },
    commands: { typecheck: nodeCmd('setTimeout(function(){}, 60000)') },
  }));
  const r = runGate(tc);
  check(tc, 'exit 0', r.status === 0, `status=${r.status}`);
  let out = null;
  try { out = JSON.parse(r.stdout); } catch (_) {}
  check(
    tc, 'timeout is a visible skip, not a block',
    out && !out.decision && out.hookSpecificOutput && /could not run typecheck/.test(out.hookSpecificOutput.additionalContext || ''),
    r.stdout
  );
}

// ---------- 11. Rust project, cargo missing from PATH -> skipped, allow, warning ----------
{
  const tc = makeCase('rust-missing-toolchain');
  write(tc.proj, 'Cargo.toml', '[package]\nname = "fixture"\nversion = "0.1.0"\nedition = "2021"\n');
  const r = runGate(tc, { PATH: pathWithoutRustGo(), Path: pathWithoutRustGo() });
  check(tc, 'exit 0', r.status === 0, `status=${r.status} stderr=${r.stderr}`);
  let out = null;
  try { out = JSON.parse(r.stdout); } catch (_) {}
  check(
    tc, 'missing cargo fails open with a visible warning',
    out && !out.decision && out.hookSpecificOutput && /could not run/.test(out.hookSpecificOutput.additionalContext || ''),
    r.stdout
  );
}

// ---------- 12. Go project, toolchain missing from PATH -> skipped, allow ----------
{
  const tc = makeCase('go-missing-toolchain');
  write(tc.proj, 'go.mod', 'module fixture\n\ngo 1.21\n');
  const r = runGate(tc, { PATH: pathWithoutRustGo(), Path: pathWithoutRustGo() });
  check(tc, 'exit 0', r.status === 0, `status=${r.status} stderr=${r.stderr}`);
  let out = null;
  try { out = JSON.parse(r.stdout); } catch (_) {}
  check(
    tc, 'missing go toolchain fails open with a visible warning',
    out && !out.decision && out.hookSpecificOutput && /could not run/.test(out.hookSpecificOutput.additionalContext || ''),
    r.stdout
  );
}

// ---------- 13. missing python module -> "No module named" fails open ----------
{
  const tc = makeCase('python-module-missing');
  if (!toolAvailable('python --version')) {
    skips++;
    console.log('SKIP [python-module-missing] python not on PATH');
  } else {
    write(tc.proj, 'package.json', JSON.stringify({ name: 'x', version: '1.0.0', scripts: {} }));
    write(tc.proj, '.guardian.json', JSON.stringify({
      commands: { typecheck: 'python -m definitely_not_a_real_module_zz .' },
    }));
    const r = runGate(tc);
    check(tc, 'exit 0', r.status === 0);
    let out = null;
    try { out = JSON.parse(r.stdout); } catch (_) {}
    check(
      tc, 'missing python module fails open with a visible warning',
      out && !out.decision && out.hookSpecificOutput && /could not run typecheck/.test(out.hookSpecificOutput.additionalContext || ''),
      r.stdout
    );
  }
}

// ---------- 14. Python project with mypy: real detection, failing type -> block ----------
{
  const tc = makeCase('python-mypy-real');
  if (!toolAvailable('python -m mypy --version')) {
    skips++;
    console.log('SKIP [python-mypy-real] mypy not installed');
  } else {
    write(tc.proj, 'pyproject.toml', '[project]\nname = "fixture"\nversion = "0.1.0"\n');
    write(tc.proj, 'bad.py', 'def f(x: int) -> str:\n    return x\n');
    const r = runGate(tc);
    check(tc, 'exit 0', r.status === 0);
    let out = null;
    try { out = JSON.parse(r.stdout); } catch (_) {}
    check(tc, 'mypy type error blocks the finish', out && out.decision === 'block', r.stdout.slice(0, 400));
    check(tc, 'reason carries mypy output', out && /bad\.py/.test(out.reason), out && out.reason);
  }
}

// ---------- 15. Go project with gofmt: unformatted file -> block (exit-0 + stdout case) ----------
{
  const tc = makeCase('gofmt-unformatted');
  if (!toolAvailable('gofmt --help') && !toolAvailable('gofmt -l .')) {
    skips++;
    console.log('SKIP [gofmt-unformatted] gofmt not on PATH');
  } else {
    write(tc.proj, 'go.mod', 'module fixture\n\ngo 1.21\n');
    write(tc.proj, 'main.go', 'package main\nfunc main() {\nprintln(  "hi"  )\n}\n'); // badly formatted
    write(tc.proj, '.guardian.json', JSON.stringify({ gate: { typecheck: false } })); // isolate the gofmt stage
    const r = runGate(tc);
    check(tc, 'exit 0', r.status === 0);
    let out = null;
    try { out = JSON.parse(r.stdout); } catch (_) {}
    check(tc, 'gofmt exit-0-with-output blocks', out && out.decision === 'block', r.stdout.slice(0, 400));
    check(tc, 'reason lists the unformatted file', out && /main\.go/.test(out.reason), out && out.reason);
  }
}

// ---------- 16. tests stage is opt-in and blocks when enabled and failing ----------
{
  const tc = makeCase('tests-opt-in');
  write(tc.proj, 'package.json', JSON.stringify({
    name: 'x', version: '1.0.0',
    scripts: { test: nodeCmd("console.error('1 test failed'); process.exit(1)") },
  }));
  const rDefault = runGate(tc); // tests default OFF -> nothing to run -> allow
  check(tc, 'tests are opt-in (default allow)', rDefault.stdout.trim() === '', rDefault.stdout);
  write(tc.proj, '.guardian.json', JSON.stringify({ gate: { tests: true } }));
  const rOn = runGate(tc);
  let out = null;
  try { out = JSON.parse(rOn.stdout); } catch (_) {}
  check(tc, 'enabled failing tests block', out && out.decision === 'block' && /tests failed/.test(out.reason), rOn.stdout.slice(0, 400));
}

// ---------- 17. huge failure output is truncated ----------
{
  const tc = makeCase('output-truncation');
  write(tc.proj, 'package.json', JSON.stringify({ name: 'x', version: '1.0.0', scripts: {} }));
  write(tc.proj, '.guardian.json', JSON.stringify({
    commands: { typecheck: nodeCmd("console.error(Array(5001).join('E')); process.exit(1)") },
  }));
  const r = runGate(tc);
  let out = null;
  try { out = JSON.parse(r.stdout); } catch (_) {}
  check(tc, 'block still fires', out && out.decision === 'block', r.stdout.slice(0, 200));
  check(tc, 'output truncated to the 1200-char cap', out && !out.reason.includes('E'.repeat(1300)), out && `reason length ${out.reason.length}`);
}

// ---------- 18. empty project (no toolchain at all) -> silent allow ----------
{
  const tc = makeCase('empty-project');
  const r = runGate(tc);
  check(tc, 'exit 0', r.status === 0);
  check(tc, 'silent allow', r.stdout.trim() === '', r.stdout);
}

// ---------- summary + cleanup ----------
try {
  fs.rmSync(suiteRoot, { recursive: true, force: true });
} catch (_) {}

const ran = caseNo - skips;
if (failures === 0) {
  console.log(`✓ done-gate integration: ${ran} cases passed${skips ? `, ${skips} skipped (toolchain absent)` : ''}`);
  process.exit(0);
} else {
  console.log(`\n✗ done-gate integration: ${failures} assertion failures across ${ran} cases`);
  process.exit(1);
}
