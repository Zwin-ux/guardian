// Guardian core — the firewall rules as data.
//
// Each rule is a plain object: { id, category, scope, describe, evaluate }.
// `evaluate` returns null (no match) or { id?, reason, matchedText } — a rule
// "family" (e.g. recursive delete) may report one of several stable ids, listed
// in `ids`, chosen in the same order the original inline conditionals checked.
//
// Scopes:
//   pipeline — evaluated once per pipe-stage index i (stage-major, preserving
//              the historical first-match ordering across rules and stages)
//   segment  — evaluated once per top-level segment
//   stage    — evaluated once per pipe stage, after shell-wrapper unwrapping
//
// Rule ids are STABLE identifiers: tests, the mutation suite, THREAT_MODEL.md,
// and downstream consumers reference them. Never rename; add new ids instead.
//
// No process, fs, network, or environment access anywhere in this file.
'use strict';

const {
  normalizePath,
  isAbsolute,
  expandHome,
  stripQuotes,
  bareCommand,
} = require('./normalize-command.js');

// ---------- classification ----------

const SYSTEM_DIRS = [
  '/etc', '/usr', '/var', '/bin', '/sbin', '/lib', '/lib64', '/boot',
  '/System', '/Library', '/opt', '/dev', '/proc', '/root',
];

function classifyTarget(rawTarget, ctx) {
  const raw = stripQuotes(rawTarget);
  if (raw === '/*' || raw === '/.') return { dangerous: true, label: raw };
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
  const { cmd, args } = stage.bc;
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

// ---------- pipeline-scope rules (per pipe-stage index) ----------

const PIPELINE_RULES = [
  {
    id: 'PIPE_DOWNLOAD_TO_SHELL',
    ids: ['PIPE_DOWNLOAD_TO_IEX', 'PIPE_DOWNLOAD_TO_INTERPRETER'],
    category: 'remote-code',
    describe: 'Downloading content and piping it straight into a shell or Invoke-Expression runs unreviewed remote code.',
    evaluate(stages, i, ctx) {
      const c = stages[i].c;
      if (!FETCHERS.has(c) || i >= stages.length - 1) return null;
      for (let j = i + 1; j < stages.length; j++) {
        const nb = stages[j].bc;
        const nc = stages[j].c;
        if (nc === 'iex' || nc === 'invoke-expression') {
          return {
            id: 'PIPE_DOWNLOAD_TO_IEX',
            reason: '🛡 Blocked: piping a web response into Invoke-Expression runs unreviewed remote code.',
            matchedText: `${stages[i].str} | ${stages[j].str}`,
          };
        }
        if (isStdinExecutingInterpreter(stages[j])) {
          return {
            id: 'PIPE_DOWNLOAD_TO_INTERPRETER',
            reason: `🛡 Blocked: piping downloaded content into ${nb.cmd} runs unreviewed remote code. Download to a file, review it, then run it.`,
            matchedText: `${stages[i].str} | ${stages[j].str}`,
          };
        }
      }
      return null;
    },
  },
  {
    id: 'SECRET_FILE_PIPE_EXFIL',
    category: 'exfiltration',
    describe: 'Reading a credential file and piping it to a network tool exfiltrates the secret.',
    evaluate(stages, i, ctx) {
      const c = stages[i].c;
      if (!(c === 'cat' || c === 'get-content' || c === 'gc') || i >= stages.length - 1) return null;
      const secret = stages[i].bc.args
        .map(stripQuotes)
        .find((a) => !a.startsWith('-') && isSecretFile(a, ctx.home));
      if (!secret) return null;
      for (let j = i + 1; j < stages.length; j++) {
        if (NETWORK_SINKS.has(stages[j].c)) {
          return {
            reason: `🛡 Blocked: this sends ${secret} to the network. Credentials must never leave the machine.`,
            matchedText: `${stages[i].str} | ${stages[j].str}`,
          };
        }
      }
      return null;
    },
  },
  {
    id: 'ENV_PIPE_EXFIL',
    category: 'exfiltration',
    describe: 'Piping the process environment to a network tool leaks every secret in it.',
    evaluate(stages, i, ctx) {
      const c = stages[i].c;
      if (!(c === 'env' || c === 'printenv' || c === 'set')) return null;
      if (stages[i].bc.args.length !== 0 || i >= stages.length - 1) return null;
      for (let j = i + 1; j < stages.length; j++) {
        if (NETWORK_SINKS.has(stages[j].c)) {
          return {
            reason: '🛡 Blocked: sending the environment to the network leaks every secret in it (API keys, tokens).',
            matchedText: `${stages[i].str} | ${stages[j].str}`,
          };
        }
      }
      return null;
    },
  },
];

// ---------- segment-scope rules ----------

const SEGMENT_RULES = [
  {
    id: 'ENV_SUBSTITUTION_EXFIL',
    category: 'exfiltration',
    describe: 'Passing $(env) / $(printenv) / $(set) as an argument to a network tool leaks the environment.',
    evaluate(segment, stages, ctx) {
      const m = /\$\((env|printenv|set)\)/.exec(segment);
      if (!m) return null;
      for (const st of stages) {
        if (NETWORK_SINKS.has(st.c)) {
          return {
            reason: '🛡 Blocked: sending the environment to the network leaks every secret in it (API keys, tokens).',
            matchedText: m[0],
          };
        }
      }
      return null;
    },
  },
];

// ---------- stage-scope rules ----------

const STAGE_RULES = [
  {
    id: 'RECURSIVE_DELETE',
    ids: ['GIT_HISTORY_DELETE', 'RECURSIVE_DELETE_DANGEROUS_PATH'],
    category: 'destruction',
    describe: 'Recursive delete (rm -rf / Remove-Item -Recurse / rd /s) of .git, a system root, the home dir, or anything outside the workspace.',
    evaluate(stage, segment, ctx) {
      const c = stage.c;
      const { flags, longs, positionals } = stage.parsed;
      const isRm = c === 'rm';
      const isPwshDel = ['remove-item', 'ri', 'rd', 'rmdir', 'del', 'erase'].includes(c);
      const winRecurse = stage.bc.args.some((a) => /^\/s$/i.test(a)); // Windows `rd /s`, `del /s`
      const recursive = flags.has('r') || flags.has('R') || longs.has('recursive') || longs.has('recurse');
      if (!((isRm && recursive) || (isPwshDel && (recursive || winRecurse)))) return null;
      const delTargets = positionals.filter((p) => !/^\/[a-zA-Z]$/.test(p)); // drop /s /q etc.
      for (const t of delTargets) {
        if (isDotGit(t, ctx)) {
          return {
            id: 'GIT_HISTORY_DELETE',
            reason: '🛡 Blocked: deleting .git destroys all history, branches, and stashes — unrecoverable. Reinitialize deliberately if you mean to.',
            matchedText: stage.str,
          };
        }
        const cls = classifyTarget(t, ctx);
        if (cls.dangerous) {
          return {
            id: 'RECURSIVE_DELETE_DANGEROUS_PATH',
            reason: `🛡 Blocked: recursive delete targeting ${cls.label} — outside this repo / a system root. Irreversible. Use an explicit in-repo path if intended.`,
            matchedText: stage.str,
          };
        }
      }
      return null;
    },
  },
  {
    id: 'FIND_MASS_DELETE',
    category: 'destruction',
    describe: 'find rooted outside the workspace with -delete or -exec rm.',
    evaluate(stage, segment, ctx) {
      if (stage.c !== 'find') return null;
      const args = stage.bc.args;
      const hasDelete = args.includes('-delete') || (args.includes('-exec') && args.slice(args.indexOf('-exec')).some((a) => a === 'rm'));
      if (!hasDelete) return null;
      const root = stage.parsed.positionals[0];
      if (!root) return null;
      const cls = classifyTarget(root, ctx);
      // only dangerous roots (/, ~, .., outside) — in-repo finds are fine
      if (cls.dangerous && cls.label !== '. (workspace root)') {
        return {
          reason: `🛡 Blocked: find … -delete rooted at ${cls.label} — mass deletion outside this repo.`,
          matchedText: stage.str,
        };
      }
      return null;
    },
  },
  {
    id: 'RAW_DEVICE_WRITE',
    category: 'destruction',
    describe: 'dd writing to a raw device (of=/dev/...).',
    evaluate(stage, segment, ctx) {
      if (stage.c !== 'dd') return null;
      const hit = stage.bc.args.find((a) => /^of=\/dev\//i.test(a));
      if (!hit) return null;
      return {
        reason: '🛡 Blocked: writing to a raw device (dd of=/dev/…). This destroys a disk. Irreversible.',
        matchedText: stage.str,
      };
    },
  },
  {
    id: 'FILESYSTEM_FORMAT',
    category: 'destruction',
    describe: 'Formatting or wiping a filesystem/disk (mkfs, wipefs, diskpart, Clear-Disk, Format-Volume, format X:).',
    evaluate(stage, segment, ctx) {
      const c = stage.c;
      if (/^mkfs(\.|$)/.test(c) || c === 'wipefs' || c === 'diskpart' || c === 'clear-disk' || c === 'format-volume') {
        return {
          reason: `🛡 Blocked: ${stage.bc.cmd} formats/erases a filesystem or disk. Irreversible.`,
          matchedText: stage.str,
        };
      }
      if (c === 'format' && stage.parsed.positionals.some((p) => /^[A-Za-z]:/.test(p))) {
        return {
          reason: '🛡 Blocked: formatting a drive. Irreversible.',
          matchedText: stage.str,
        };
      }
      return null;
    },
  },
  {
    id: 'RAW_DEVICE_SHRED',
    category: 'destruction',
    describe: 'shred pointed at a raw device.',
    evaluate(stage, segment, ctx) {
      if (stage.c !== 'shred') return null;
      if (!stage.parsed.positionals.some((p) => /^\/dev\//.test(stripQuotes(p)))) return null;
      return {
        reason: '🛡 Blocked: shredding a raw device. Irreversible.',
        matchedText: stage.str,
      };
    },
  },
  {
    id: 'RAW_DEVICE_REDIRECT',
    category: 'destruction',
    describe: 'Redirecting output onto a raw disk device (> /dev/sdX).',
    evaluate(stage, segment, ctx) {
      const m = />\s*\/dev\/(sd|disk|nvme|hd)/.exec(segment);
      if (!m) return null;
      return {
        reason: '🛡 Blocked: redirecting output onto a raw disk device. Irreversible.',
        matchedText: m[0],
      };
    },
  },
  {
    id: 'GIT_CLEAN_IGNORED_WIPE',
    category: 'destruction',
    describe: 'git clean -fx wipes gitignored files (.env, local configs) too.',
    evaluate(stage, segment, ctx) {
      if (stage.c !== 'git' || stage.bc.args[0] !== 'clean') return null;
      const args = stage.bc.args;
      const gflags = new Set();
      for (const a of args.slice(1)) if (a.startsWith('-') && !a.startsWith('--')) for (const ch of a.slice(1)) gflags.add(ch);
      const dry = gflags.has('n') || args.includes('--dry-run');
      const force = gflags.has('f') || args.includes('--force');
      const wipesIgnored = gflags.has('x') || gflags.has('X');
      if (force && wipesIgnored && !dry) {
        return {
          reason: "🛡 Blocked: 'git clean -x' wipes gitignored files too — including .env, local configs, and caches. Drop -x, or run 'git clean -nfdx' to preview first.",
          matchedText: stage.str,
        };
      }
      return null;
    },
  },
  {
    id: 'RECURSIVE_CHMOD_CHOWN_DANGEROUS_PATH',
    category: 'destruction',
    describe: 'chmod -R / chown -R at a system root, home, or outside the workspace.',
    evaluate(stage, segment, ctx) {
      const c = stage.c;
      if (!(c === 'chmod' || c === 'chown')) return null;
      const { flags, longs, positionals } = stage.parsed;
      if (!(flags.has('R') || flags.has('r') || longs.has('recursive'))) return null;
      for (const t of positionals) {
        const cls = classifyTarget(t, ctx);
        if (cls.dangerous) {
          return {
            reason: `🛡 Blocked: recursive ${stage.bc.cmd} at ${cls.label} can brick the system (breaks permissions on system/home files). Scope it to a path inside this repo.`,
            matchedText: stage.str,
          };
        }
      }
      return null;
    },
  },
  {
    id: 'SECRET_FILE_UPLOAD',
    category: 'exfiltration',
    describe: 'Uploading a credential file via curl/wget data flags, scp/rsync/sftp, or httpie.',
    evaluate(stage, segment, ctx) {
      const c = stage.c;
      if (c === 'curl' || c === 'wget') {
        const secret = curlUploadsSecret(stage.bc.args, ctx.home);
        if (secret) {
          return {
            reason: `🛡 Blocked: this uploads ${secret} to the network. Credentials must never leave the machine.`,
            matchedText: stage.str,
          };
        }
        return null;
      }
      if (c === 'scp' || c === 'rsync' || c === 'sftp') {
        const secret = stage.parsed.positionals.map(stripQuotes).find((p) => !p.includes(':') && isSecretFile(p, ctx.home));
        if (secret) {
          return {
            reason: `🛡 Blocked: this copies ${secret} to a remote host. Credentials must never leave the machine.`,
            matchedText: stage.str,
          };
        }
        return null;
      }
      if ((c === 'http' || c === 'https') && stage.bc.args.some((a) => a.startsWith('@') && isSecretFile(a, ctx.home))) {
        return {
          reason: '🛡 Blocked: this sends a credential file to the network via httpie.',
          matchedText: stage.str,
        };
      }
      return null;
    },
  },
];

const ALL_RULES = [...PIPELINE_RULES, ...SEGMENT_RULES, ...STAGE_RULES];

// Every stable id a decision can carry (family entries expand to their `ids`).
const RULE_IDS = ALL_RULES.flatMap((r) => r.ids || [r.id]);

module.exports = {
  PIPELINE_RULES,
  SEGMENT_RULES,
  STAGE_RULES,
  ALL_RULES,
  RULE_IDS,
  // helpers exported for tests
  classifyTarget,
  isDotGit,
  isSecretFile,
  curlUploadsSecret,
  NETWORK_SINKS,
  FETCHERS,
  EXEC_INTERPRETERS,
};
