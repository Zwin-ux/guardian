#!/usr/bin/env node
// Manifest validation: both plugin manifests must parse, carry the required
// fields, and agree with package.json on name and version. Run in CI so a
// release can never ship with drifted metadata.
//
//   node tools/validate-manifests.js        -> exit 0 (valid) / 1 (problems listed)
'use strict';
const fs = require('fs');
const path = require('path');

const root = path.join(__dirname, '..');
const problems = [];

function readJson(rel) {
  const p = path.join(root, rel);
  try {
    return JSON.parse(fs.readFileSync(p, 'utf8'));
  } catch (e) {
    problems.push(`${rel}: cannot read/parse — ${e.message}`);
    return null;
  }
}

const pkg = readJson('package.json');
const manifests = ['.claude-plugin/plugin.json', '.grok-plugin/plugin.json'];

for (const rel of manifests) {
  const m = readJson(rel);
  if (!m || !pkg) continue;
  for (const field of ['name', 'version', 'description', 'license']) {
    if (!m[field]) problems.push(`${rel}: missing required field "${field}"`);
  }
  if (m.name && pkg.name && m.name !== pkg.name) {
    problems.push(`${rel}: name "${m.name}" != package.json name "${pkg.name}"`);
  }
  if (m.version && pkg.version && m.version !== pkg.version) {
    problems.push(`${rel}: version "${m.version}" != package.json version "${pkg.version}"`);
  }
}

// hooks.json must parse and reference files that exist
const hooks = readJson('hooks/hooks.json');
if (hooks) {
  const text = JSON.stringify(hooks);
  for (const f of ['guard.js', 'done-gate.js']) {
    if (!text.includes(f)) problems.push(`hooks/hooks.json: does not reference hooks/${f}`);
    if (!fs.existsSync(path.join(root, 'hooks', f))) problems.push(`hooks/${f}: referenced but missing`);
  }
}

if (problems.length) {
  console.error('manifest validation FAILED:');
  for (const p of problems) console.error(`  - ${p}`);
  process.exit(1);
}
console.log(`✓ manifests valid: ${manifests.join(', ')} agree with package.json v${pkg.version}`);
