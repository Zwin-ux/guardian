#!/usr/bin/env node
// Grok Build Guardian — blast-radius firewall (PreToolUse hook).
//
// Denies a shell command only when it crosses an unambiguous safety boundary:
// irreversible destruction (delete/format/wipe outside the repo or at a system
// root) or secret exfiltration / remote-code execution. Everything else is
// allowed. Threat model: a good-faith agent emitting a catastrophic command —
// NOT a human deliberately evading the guard. Therefore: FAIL-OPEN everywhere,
// no shell-variable resolution, and a hard bias to allow.
//
// Contract: reads the PreToolUse JSON envelope on stdin; on a block it prints
// {"decision":"deny","reason":"..."} to stdout; otherwise prints nothing.
// Always exits 0 — a deny is honored via stdout regardless of exit code, and
// any error must never block real work.
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

// ---------- classification ----------

const SYSTEM_DIRS = [
  '/etc', '/usr', '/var', '/bin', '/sbin', '/lib', '/lib64', '/boot',
  '/System', '/Library', '/opt', '/dev', '/proc', '/root',
];

function classifyTarget(rawTarget, ctx) {
  const raw = stripQuotes(rawTarget);
  if (raw === '/*' || raw === '/.' ) return { dangerous: true, label: raw };
  const expanded = expandHome(raw, ctx.home);
  const home = normalizePath(ctx.home);
  const workspace = normalizePath(ctx.workspace);
  const abs = isAbsolute(expanded) ? normalizePath(expanded) : normalizePath(workspace + '/' + expanded);

  // filesystem / drive root
  if (abs === '/' || /^[A-Za-z]:$/.test(abs) || /^[A-Za-z]:\/$/.test(abs)) {
    return { dangerous: true, label: raw };
  }
  // bare home
  if (abs === home) return { dangerous: true, label: '~ (home)' };
  // parent escape written literally
  if (raw === '..' || raw.startsWith('../') || raw.startsWith('..\\')) {
    return { dangerous: true, label: raw };
  }
  // system dir (exact or descendant)
  for (const d of SYSTEM_DIRS) {
    if (abs === d || abs.startsWith(d + '/')) return { dangerous: true, label: abs };
  }
  const lower = abs.toLowerCase();
  for (const d of ['/windows', '/users']) {
    // Windows system roots after drive strip, e.g. C:/Windows -> "/windows"
    const wabs = lower.replace(/^[a-z]:/, '');
    if (wabs === d || wabs.startsWith(d + '/')) {
      // allow deeper user paths inside the workspace; only bare-ish roots are dangerous
      if (wabs === d || wabs === d + '/') return { dangerous: true, label: abs };
    }
  }
  // deleting the whole workspace
  if (abs === workspace) return { dangerous: true, label: '. (workspace root)' };
  // outside the workspace
  if (abs !== workspace && !abs.startsWith(workspace + '/')) {
    return { dangerous: true, label: abs, outside: true };
  }
  return { dangerous: false, label: abs, abs, workspace };
}

function isDotGit(rawTarget, ctx) {
  const raw = stripQuotes(rawTarget);
  const expanded = expandHome(raw, ctx.home);
  const abs = isAbsolute(expanded)
    ? normalizePath(expanded)
    : normalizePath(normalizePath(ctx.workspace) + '/' + expanded);
  return abs.split('/').pop() === '.git';
}

// ---------- secret / network detection ----------

const PUBLIC_CERTS = new Set(['ca.pem', 'cert.pem', 'fullchain.pem', 'chain.pem']);
const ENV_EXCLUDE = /\.env\.(example|sample|template|dist)$|\.example$/i;
const SECRET_PATHS = [
  /(^|\/)\.aws\/credentials$/i,
  /(^|\/)\.config\/gcloud\//i,
  /(^|\/)\.kube\/config$/i,
  /(^|\/)\.netrc$/i,
  /(^|\/)\.npmrc$/i,
  /(^|\/)\.docker\/config\.json$/i,
  /(^|\/)\.config\/gh\/hosts\.yml$/i,
  /(^|\/)\.gitconfig$/i,
  /\.ssh\/id_/i,
];

function isSecretFile(token, home) {
  let t = stripQuotes(token).replace(/^@/, '');
  t = expandHome(t, home).replace(/\\/g, '/');
  const base = t.split('/').pop();
  if (!base) return false;
  if (ENV_EXCLUDE.test(base)) return false;
  if (base === '.env' || /^\.env\./i.test(base)) return true;
  if (/^id_(rsa|dsa|ecdsa|ed25519)$/i.test(base) || /^id_/.test(base)) return true;
  if (base.endsWith('.key')) return true;
  if (base.endsWith('.pem') && !PUBLIC_CERTS.has(base.toLowerCase())) return true;
  for (const re of SECRET_PATHS) if (re.test(t)) return true;
  return false;
}

const NETWORK_SINKS = new Set([
  'curl', 'wget', 'nc', 'ncat', 'netcat', 'ssh', 'scp', 'rsync', 'sftp',
  'http', 'https', 'iwr', 'irm', 'invoke-webrequest', 'invoke-restmethod',
]);
const FETCHERS = new Set(['curl', 'wget', 'iwr', 'irm', 'invoke-webrequest', 'invoke-restmethod']);
const EXEC_INTERPRETERS = new Set(['sh', 'bash', 'dash', 'ksh', 'zsh', 'pwsh', 'ruby', 'perl', 'node']);

function isStdinExecutingInterpreter(stage) {
  const { cmd, args } = bareCommand(stage.argv);
  const c = cmd.toLowerCase();
  if (EXEC_INTERPRETERS.has(c)) return true;
  if (c === 'python' || c === 'python3') {
    // `python -m module` is a formatter/module run, not stdin execution.
    if (args.includes('-m')) return false;
    return true; // bare, `-`, or `-c`
  }
  return false;
}

// upload-bound secret argument inside a curl/wget stage
function curlUploadsSecret(argv, home) {
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const m = /^(--data|--data-binary|--data-raw|-d|-F|--form|-T|--upload-file)$/.exec(a);
    if (m) {
      let val = argv[i + 1] || '';
      if (/^-F$|^--form$/.test(a)) {
        const eq = val.indexOf('=@');
        if (eq >= 0) val = val.slice(eq + 1);
        else continue;
      }
      if (val.startsWith('@') || a === '-T' || a === '--upload-file') {
        if (isSecretFile(val, home)) return stripQuotes(val).replace(/^@/, '');
      }
    }
    const pf = /^--post-file=(.+)$/.exec(a);
    if (pf && isSecretFile(pf[1], home)) return pf[1];
    // attached form: -d@file
    const dat = /^-d@?(.+)$/.exec(a);
    if (a.startsWith('-d') && a.length > 2 && isSecretFile(a.replace(/^-d@?/, ''), home)) {
      return a.replace(/^-d@?/, '');
    }
    if (dat && a !== '-d' && isSecretFile(dat[1], home)) return dat[1];
  }
  return null;
}

// ---------- the rules ----------

function evaluate(command, opts) {
  const ctx = {
    home: normalizePath(opts.home || process.env.HOME || process.env.USERPROFILE || '/home/user'),
    workspace: normalizePath(opts.workspace || process.env.GROK_WORKSPACE_ROOT || process.cwd()),
  };
  const deny = (reason) => ({ deny: true, reason });

  const segments = splitTop(command, ['&&', '||', ';', '\n']);
  for (const segment of segments) {
    const res = evalSegment(segment, ctx, 0);
    if (res) return res;
  }
  return { deny: false };
}

function evalSegment(segment, ctx, depth) {
  if (depth > 2) return null; // bounded unwrap
  const deny = (reason) => ({ deny: true, reason });

  // pipe stages
  const stageStrs = splitTop(segment, ['|']);
  const stages = stageStrs.map((s) => ({ str: s, argv: tokenize(s) }));

  // ---- pipe-structure rules (D6/D7/D8-piped/D9-piped) ----
  for (let i = 0; i < stages.length; i++) {
    const bc = bareCommand(stages[i].argv);
    const c = bc.cmd.toLowerCase();
    // D6/D7: fetch | interpreter/iex
    if (FETCHERS.has(c) && i < stages.length - 1) {
      for (let j = i + 1; j < stages.length; j++) {
        const nb = bareCommand(stages[j].argv);
        const nc = nb.cmd.toLowerCase();
        if (nc === 'iex' || nc === 'invoke-expression') {
          return deny('🛡 Blocked: piping a web response into Invoke-Expression runs unreviewed remote code.');
        }
        if (isStdinExecutingInterpreter(stages[j])) {
          return deny(`🛡 Blocked: piping downloaded content into ${nb.cmd} runs unreviewed remote code. Download to a file, review it, then run it.`);
        }
      }
    }
    // D8-piped: cat/Get-Content secret | network sink
    if ((c === 'cat' || c === 'get-content' || c === 'gc') && i < stages.length - 1) {
      const secret = bc.args.map(stripQuotes).find((a) => !a.startsWith('-') && isSecretFile(a, ctx.home));
      if (secret) {
        for (let j = i + 1; j < stages.length; j++) {
          const nc = bareCommand(stages[j].argv).cmd.toLowerCase();
          if (NETWORK_SINKS.has(nc)) {
            return deny(`🛡 Blocked: this sends ${secret} to the network. Credentials must never leave the machine.`);
          }
        }
      }
    }
    // D9-piped: env/printenv/set | network sink
    if ((c === 'env' || c === 'printenv' || c === 'set') && bc.args.length === 0 && i < stages.length - 1) {
      for (let j = i + 1; j < stages.length; j++) {
        const nc = bareCommand(stages[j].argv).cmd.toLowerCase();
        if (NETWORK_SINKS.has(nc)) {
          return deny('🛡 Blocked: sending the environment to the network leaks every secret in it (API keys, tokens).');
        }
      }
    }
  }

  // D9 literal: $(env) as an argument to a network sink
  if (/\$\((env|printenv|set)\)/.test(segment)) {
    for (const st of stages) {
      const nc = bareCommand(st.argv).cmd.toLowerCase();
      if (NETWORK_SINKS.has(nc)) {
        return deny('🛡 Blocked: sending the environment to the network leaks every secret in it (API keys, tokens).');
      }
    }
  }

  // ---- per-stage command rules ----
  for (const st of stages) {
    const r = evalStage(st.argv, segment, ctx, depth);
    if (r) return r;
  }
  return null;
}

function evalStage(argv, segment, ctx, depth) {
  const deny = (reason) => ({ deny: true, reason });
  if (!argv.length) return null;
  const { cmd, args } = bareCommand(argv);
  const c = cmd.toLowerCase();

  // unwrap one level of `sh -c "..."` / cmd /c "..."
  if (['sh', 'bash', 'dash', 'zsh', 'ksh', 'pwsh', 'powershell'].includes(c)) {
    const ci = args.findIndex((a) => a === '-c' || a.toLowerCase() === '-command');
    if (ci >= 0 && args[ci + 1]) {
      const inner = stripQuotes(args[ci + 1]);
      for (const seg of splitTop(inner, ['&&', '||', ';', '\n'])) {
        const r = evalSegment(seg, ctx, depth + 1);
        if (r) return r;
      }
    }
  }
  if (c === 'cmd' || c === 'cmd.exe') {
    const ci = args.findIndex((a) => a.toLowerCase() === '/c' || a.toLowerCase() === '/k');
    if (ci >= 0 && args[ci + 1]) {
      const inner = stripQuotes(args.slice(ci + 1).join(' '));
      for (const seg of splitTop(inner, ['&&', '||', ';', '\n'])) {
        const r = evalSegment(seg, ctx, depth + 1);
        if (r) return r;
      }
    }
  }

  const { flags, longs, positionals } = parseFlags(args);

  // D1/D2: recursive delete (rm / Remove-Item / rd / del)
  const isRm = c === 'rm';
  const isPwshDel = ['remove-item', 'ri', 'rd', 'rmdir', 'del', 'erase'].includes(c);
  const winRecurse = args.some((a) => /^\/s$/i.test(a)); // Windows `rd /s`, `del /s`
  const recursive = flags.has('r') || flags.has('R') || longs.has('recursive') || longs.has('recurse');
  const delTargets = positionals.filter((p) => !/^\/[a-zA-Z]$/.test(p)); // drop /s /q etc.
  if ((isRm && recursive) || (isPwshDel && (recursive || winRecurse))) {
    for (const t of delTargets) {
      if (isDotGit(t, ctx)) {
        return deny('🛡 Blocked: deleting .git destroys all history, branches, and stashes — unrecoverable. Reinitialize deliberately if you mean to.');
      }
      const cls = classifyTarget(t, ctx);
      if (cls.dangerous) {
        return deny(`🛡 Blocked: recursive delete targeting ${cls.label} — outside this repo / a system root. Irreversible. Use an explicit in-repo path if intended.`);
      }
    }
  }

  // D3: find <root> -delete / -exec rm
  if (c === 'find') {
    const hasDelete = args.includes('-delete') || (args.includes('-exec') && args.slice(args.indexOf('-exec')).some((a) => a === 'rm'));
    if (hasDelete) {
      const root = positionals[0];
      if (root) {
        const cls = classifyTarget(root, ctx);
        // only dangerous roots (/, ~, .., outside) — in-repo finds are fine
        if (cls.dangerous && cls.label !== '. (workspace root)') {
          return deny(`🛡 Blocked: find … -delete rooted at ${cls.label} — mass deletion outside this repo.`);
        }
      }
    }
  }

  // D4: raw device write / format
  if (c === 'dd' && args.some((a) => /^of=\/dev\//i.test(a))) {
    return deny('🛡 Blocked: writing to a raw device (dd of=/dev/…). This destroys a disk. Irreversible.');
  }
  if (/^mkfs(\.|$)/.test(c) || c === 'wipefs' || c === 'diskpart' || c === 'clear-disk' || c === 'format-volume') {
    return deny(`🛡 Blocked: ${cmd} formats/erases a filesystem or disk. Irreversible.`);
  }
  if (c === 'format' && positionals.some((p) => /^[A-Za-z]:/.test(p))) {
    return deny('🛡 Blocked: formatting a drive. Irreversible.');
  }
  if (c === 'shred' && positionals.some((p) => /^\/dev\//.test(stripQuotes(p)))) {
    return deny('🛡 Blocked: shredding a raw device. Irreversible.');
  }
  if (/>\s*\/dev\/(sd|disk|nvme|hd)/.test(segment)) {
    return deny('🛡 Blocked: redirecting output onto a raw disk device. Irreversible.');
  }

  // D5: git clean -x (wipes ignored files, incl. .env) — unless dry-run
  if (c === 'git' && args[0] === 'clean') {
    const gflags = new Set();
    for (const a of args.slice(1)) if (a.startsWith('-') && !a.startsWith('--')) for (const ch of a.slice(1)) gflags.add(ch);
    const dry = gflags.has('n') || args.includes('--dry-run');
    const force = gflags.has('f') || args.includes('--force');
    const wipesIgnored = gflags.has('x') || gflags.has('X');
    if (force && wipesIgnored && !dry) {
      return deny("🛡 Blocked: 'git clean -x' wipes gitignored files too — including .env, local configs, and caches. Drop -x, or run 'git clean -nfdx' to preview first.");
    }
  }

  // D11: chmod -R / chown -R at a dangerous root
  if ((c === 'chmod' || c === 'chown') && (flags.has('R') || flags.has('r') || longs.has('recursive'))) {
    for (const t of positionals) {
      const cls = classifyTarget(t, ctx);
      if (cls.dangerous) {
        return deny(`🛡 Blocked: recursive ${cmd} at ${cls.label} can brick the system (breaks permissions on system/home files). Scope it to a path inside this repo.`);
      }
    }
  }

  // D8-argform: curl/wget upload of a secret file; scp/rsync/sftp of a secret
  if (c === 'curl' || c === 'wget') {
    const secret = curlUploadsSecret(args, ctx.home);
    if (secret) return deny(`🛡 Blocked: this uploads ${secret} to the network. Credentials must never leave the machine.`);
  }
  if (c === 'scp' || c === 'rsync' || c === 'sftp') {
    const secret = positionals.map(stripQuotes).find((p) => !p.includes(':') && isSecretFile(p, ctx.home));
    if (secret) return deny(`🛡 Blocked: this copies ${secret} to a remote host. Credentials must never leave the machine.`);
  }
  if ((c === 'http' || c === 'https') && args.some((a) => a.startsWith('@') && isSecretFile(a, ctx.home))) {
    return deny('🛡 Blocked: this sends a credential file to the network via httpie.');
  }

  return null;
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
      const verdict = evaluate(command, {});
      if (verdict.deny) {
        process.stdout.write(JSON.stringify({ decision: 'deny', reason: verdict.reason }));
      }
    } catch (_) {
      // fail-open: never block on an internal error
    }
    process.exit(0);
  });
  process.stdin.on('error', () => process.exit(0));
}

if (require.main === module) runCli();
module.exports = { evaluate };
