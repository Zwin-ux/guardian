// Guardian core — command normalization and tokenization.
//
// Pure text/path utilities shared by the policy engine. No process, fs,
// network, or environment access. Every function is deterministic on its
// inputs so the engine stays testable on any OS.
'use strict';

// ---------- path helpers (OS-agnostic; the hook runs on win/mac/linux) ----------

function normalizePath(p) {
  p = String(p).replace(/\\/g, '/');
  const drive = /^([A-Za-z]:)/.exec(p);
  const prefix = drive ? drive[1] : '';
  if (drive) p = p.slice(2);
  const absolute = p.startsWith('/');
  const parts = p.split('/').filter((s) => s !== '' && s !== '.');
  const out = [];
  for (const seg of parts) {
    if (seg === '..') {
      if (out.length && out[out.length - 1] !== '..') out.pop();
      else if (!absolute) out.push('..');
    } else out.push(seg);
  }
  let res = (absolute ? '/' : '') + out.join('/');
  if (prefix) res = prefix + (res.startsWith('/') ? res : '/' + res);
  return res || (absolute ? '/' : '.');
}

function isAbsolute(p) {
  return /^([A-Za-z]:)?[\\/]/.test(p) || /^\/\//.test(p);
}

function expandHome(target, home) {
  let t = target;
  if (t === '~') return home;
  if (t.startsWith('~/')) t = home + t.slice(1);
  t = t
    .replace(/\$\{?HOME\}?/g, home)
    .replace(/\$env:USERPROFILE/gi, home)
    .replace(/%USERPROFILE%/gi, home);
  return t;
}

// ---------- tokenization ----------

// Split a command line on top-level separators, respecting single/double quotes.
// `seps` is a list of multi-char operators to split on.
function splitTop(line, seps) {
  const out = [];
  let cur = '';
  let quote = null;
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (quote) {
      cur += c;
      if (c === quote) quote = null;
      continue;
    }
    if (c === '"' || c === "'") {
      quote = c;
      cur += c;
      continue;
    }
    let matched = null;
    for (const s of seps) {
      if (line.startsWith(s, i)) {
        matched = s;
        break;
      }
    }
    if (matched) {
      out.push(cur);
      cur = '';
      i += matched.length - 1;
    } else cur += c;
  }
  out.push(cur);
  return out.map((s) => s.trim()).filter((s) => s.length);
}

// Split a raw command into its top-level segments (&&, ||, ;, newline).
function splitSegments(command) {
  return splitTop(String(command), ['&&', '||', ';', '\n']);
}

function stripQuotes(tok) {
  if (tok.length >= 2 && (tok[0] === '"' || tok[0] === "'") && tok[tok.length - 1] === tok[0]) {
    return tok.slice(1, -1);
  }
  return tok;
}

// Split a single command (no top-level operators) into argv, respecting quotes.
function tokenize(cmd) {
  const toks = [];
  let cur = '';
  let quote = null;
  let has = false;
  for (let i = 0; i < cmd.length; i++) {
    const c = cmd[i];
    if (quote) {
      if (c === quote) quote = null;
      else cur += c;
      has = true;
      continue;
    }
    if (c === '"' || c === "'") {
      quote = c;
      has = true;
      continue;
    }
    if (c === ' ' || c === '\t') {
      if (has) {
        toks.push(cur);
        cur = '';
        has = false;
      }
      continue;
    }
    cur += c;
    has = true;
  }
  if (has) toks.push(cur);
  return toks;
}

const WRAPPERS = new Set(['sudo', 'env', 'command', 'time', 'nice', 'exec', 'doas']);

// Resolve a command's argv to { cmd, args } with a bare command name:
// strip leading wrapper prefixes (sudo/env/...), a leading backslash, and an
// absolute path (/bin/rm -> rm). Case preserved (Windows compared case-insensitively later).
function bareCommand(argv) {
  let i = 0;
  while (i < argv.length && WRAPPERS.has(argv[i].toLowerCase())) i++;
  if (i >= argv.length) return { cmd: '', args: [] };
  let cmd = argv[i].replace(/^\\/, '');
  cmd = cmd.replace(/^.*[\\/]/, ''); // strip path
  cmd = cmd.replace(/\.exe$/i, '');
  return { cmd, args: argv.slice(i + 1) };
}

// Parse short/long flags out of args. Returns {flags:Set<char>, longs:Set, positionals:[]}.
function parseFlags(args) {
  const flags = new Set();
  const longs = new Set();
  const positionals = [];
  for (const a of args) {
    if (a.startsWith('--')) longs.add(a.slice(2).split('=')[0].toLowerCase());
    else if (a.startsWith('-') && a.length > 1 && !/^-\d/.test(a)) {
      for (const ch of a.slice(1)) flags.add(ch);
    } else positionals.push(a);
  }
  return { flags, longs, positionals };
}

// ---------- shell-wrapper unwrapping ----------

const POSIX_SHELLS = new Set(['sh', 'bash', 'dash', 'zsh', 'ksh']);
const POWERSHELLS = new Set(['pwsh', 'powershell']);

// POSIX shells: `-c` may appear inside a short-option cluster (`bash -lc`).
function isPosixCommandFlag(a) {
  return /^-[A-Za-z]+$/.test(a) && a.includes('c');
}

// PowerShell: `-Command` (any case) or its `-c` abbreviation.
function isPwshCommandFlag(a) {
  const l = a.toLowerCase();
  return l === '-c' || l === '-command';
}

// If this argv is a shell wrapper carrying an inner command string
// (`sh -c "..."`, `bash -lc "..."`, `powershell -Command ...`, `cmd /c ...`),
// return { shell, command }. Otherwise null.
//
// POSIX shells take only the next argument as the script (further args become
// $0, $1, ...). PowerShell -Command and cmd /c consume the rest of the line.
function unwrapShellStage(argv) {
  const { cmd, args } = bareCommand(argv);
  const c = cmd.toLowerCase();
  if (POSIX_SHELLS.has(c)) {
    const ci = args.findIndex(isPosixCommandFlag);
    if (ci >= 0 && args[ci + 1]) {
      return { shell: c, command: stripQuotes(args[ci + 1]) };
    }
    return null;
  }
  if (POWERSHELLS.has(c)) {
    const ci = args.findIndex(isPwshCommandFlag);
    if (ci >= 0 && args[ci + 1]) {
      return { shell: c, command: stripQuotes(args.slice(ci + 1).join(' ')) };
    }
    return null;
  }
  if (c === 'cmd') {
    const ci = args.findIndex((a) => a.toLowerCase() === '/c' || a.toLowerCase() === '/k');
    if (ci >= 0 && args[ci + 1]) {
      return { shell: 'cmd', command: stripQuotes(args.slice(ci + 1).join(' ')) };
    }
    return null;
  }
  return null;
}

module.exports = {
  normalizePath,
  isAbsolute,
  expandHome,
  splitTop,
  splitSegments,
  stripQuotes,
  tokenize,
  bareCommand,
  parseFlags,
  unwrapShellStage,
  WRAPPERS,
};
