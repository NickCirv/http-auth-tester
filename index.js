#!/usr/bin/env node
/**
 * http-auth-tester — Test HTTP authentication endpoints
 * Zero external dependencies. Built-in modules only.
 * Security: auth values always redacted in output.
 */

import { request as httpsRequest } from 'https';
import { request as httpRequest } from 'http';
import { URL } from 'url';
import { createHash, randomBytes } from 'crypto';

const VERSION = '1.0.0';

// ─── Colors ───────────────────────────────────────────────────────────────────
const isTTY = process.stdout.isTTY;
const c = {
  green:  (s) => isTTY ? `\x1b[32m${s}\x1b[0m` : s,
  red:    (s) => isTTY ? `\x1b[31m${s}\x1b[0m` : s,
  yellow: (s) => isTTY ? `\x1b[33m${s}\x1b[0m` : s,
  cyan:   (s) => isTTY ? `\x1b[36m${s}\x1b[0m` : s,
  bold:   (s) => isTTY ? `\x1b[1m${s}\x1b[0m` : s,
  dim:    (s) => isTTY ? `\x1b[2m${s}\x1b[0m` : s,
};

// ─── Argument Parser ──────────────────────────────────────────────────────────
function parseArgs(argv) {
  const args = { flags: {}, positional: [] };
  let i = 0;
  while (i < argv.length) {
    const arg = argv[i];
    if (arg.startsWith('--')) {
      const key = arg.slice(2);
      const next = argv[i + 1];
      if (next === undefined || next.startsWith('--')) {
        args.flags[key] = true;
      } else {
        args.flags[key] = next;
        i++;
      }
    } else {
      args.positional.push(arg);
    }
    i++;
  }
  return args;
}

// ─── HTTP Request ─────────────────────────────────────────────────────────────
function makeRequest(opts) {
  return new Promise((resolve, reject) => {
    const { url, method, headers, body, timeout } = opts;
    let parsed;
    try {
      parsed = new URL(url);
    } catch {
      return reject(new Error(`Invalid URL: ${url}`));
    }

    const isHttps = parsed.protocol === 'https:';
    const reqFn = isHttps ? httpsRequest : httpRequest;
    const port = parsed.port || (isHttps ? 443 : 80);

    const reqOptions = {
      hostname: parsed.hostname,
      port: parseInt(port, 10),
      path: parsed.pathname + parsed.search,
      method: method || 'GET',
      headers: headers || {},
      timeout: parseInt(timeout, 10) || 10000,
      rejectUnauthorized: false,
    };

    const req = reqFn(reqOptions, (res) => {
      const chunks = [];
      res.on('data', (chunk) => chunks.push(chunk));
      res.on('end', () => {
        const rawBody = Buffer.concat(chunks).toString('utf8');
        resolve({
          status: res.statusCode,
          statusText: res.statusMessage,
          headers: res.headers,
          body: rawBody,
        });
      });
    });

    req.on('timeout', () => {
      req.destroy();
      reject(new Error(`Request timed out after ${timeout}ms`));
    });

    req.on('error', (err) => reject(err));

    if (body) {
      req.write(body);
    }
    req.end();
  });
}

// ─── Digest Auth ──────────────────────────────────────────────────────────────
function parseWwwAuthenticate(header) {
  if (!header) return null;
  const scheme = header.split(' ')[0].toLowerCase();
  if (scheme !== 'digest') return null;
  const params = {};
  const re = /(\w+)="([^"]*)"/g;
  let m;
  while ((m = re.exec(header)) !== null) {
    params[m[1]] = m[2];
  }
  return params;
}

function md5(str) {
  return createHash('md5').update(str).digest('hex');
}

async function digestAuth(url, user, pass, method, extraHeaders, timeout) {
  const challenge = await makeRequest({ url, method, headers: extraHeaders || {}, timeout });
  if (challenge.status !== 401) {
    return { ...challenge, digestSkipped: true };
  }

  const wwwHeader = challenge.headers['www-authenticate'] || '';
  const params = parseWwwAuthenticate(wwwHeader);
  if (!params) {
    return { ...challenge, digestSkipped: true, note: 'Not a Digest challenge' };
  }

  const { realm, nonce, qop, opaque } = params;
  const algorithm = (params.algorithm || 'MD5').toUpperCase();
  const cnonce = randomBytes(8).toString('hex');
  const nc = '00000001';

  const parsed = new URL(url);
  const uri = parsed.pathname + parsed.search;

  const ha1 = algorithm === 'MD5-SESS'
    ? md5(`${md5(`${user}:${realm}:${pass}`)}:${nonce}:${cnonce}`)
    : md5(`${user}:${realm}:${pass}`);

  const ha2 = md5(`${method}:${uri}`);

  let response;
  if (qop === 'auth' || qop === 'auth-int') {
    response = md5(`${ha1}:${nonce}:${nc}:${cnonce}:${qop}:${ha2}`);
  } else {
    response = md5(`${ha1}:${nonce}:${ha2}`);
  }

  let authHeader = `Digest username="${user}", realm="${realm}", nonce="${nonce}", uri="${uri}", response="${response}"`;
  if (qop) authHeader += `, qop=${qop}, nc=${nc}, cnonce="${cnonce}"`;
  if (opaque) authHeader += `, opaque="${opaque}"`;

  const headers = { ...(extraHeaders || {}), Authorization: authHeader };
  return makeRequest({ url, method, headers, timeout });
}

// ─── Redact helpers ───────────────────────────────────────────────────────────
function redactHeaders(headers) {
  const redacted = {};
  const sensitiveKeys = ['authorization', 'x-api-key', 'cookie', 'set-cookie', 'proxy-authorization'];
  for (const [k, v] of Object.entries(headers)) {
    if (sensitiveKeys.includes(k.toLowerCase())) {
      redacted[k] = '[REDACTED]';
    } else {
      redacted[k] = v;
    }
  }
  return redacted;
}

// ─── Output ───────────────────────────────────────────────────────────────────
function statusColor(status, expected) {
  const ok = status === expected;
  if (ok) return c.green(`✔ ${status}`);
  if (status >= 400 && status < 500) return c.red(`✘ ${status}`);
  if (status >= 500) return c.red(`✘ ${status}`);
  return c.yellow(`~ ${status}`);
}

function printResult(label, result, opts = {}) {
  const { expected = 200, verbose = false, jsonMode = false } = opts;
  if (jsonMode) return;

  const ok = result.status === expected;
  const icon = ok ? c.green('✔') : c.red('✘');
  const statusStr = statusColor(result.status, expected);

  process.stdout.write(`  ${icon} ${c.bold(label.padEnd(12))} ${statusStr}`);

  if (result.note) {
    process.stdout.write(c.dim(` (${result.note})`));
  }
  process.stdout.write('\n');

  if (verbose) {
    process.stdout.write(c.dim('    Request headers (redacted):\n'));
    if (opts.reqHeaders) {
      for (const [k, v] of Object.entries(redactHeaders(opts.reqHeaders))) {
        process.stdout.write(c.dim(`      ${k}: ${v}\n`));
      }
    }
    process.stdout.write(c.dim('    Response headers:\n'));
    for (const [k, v] of Object.entries(redactHeaders(result.headers || {}))) {
      process.stdout.write(c.dim(`      ${k}: ${v}\n`));
    }
  }
}

// ─── Auth method runners ──────────────────────────────────────────────────────
async function runBasic(url, opts) {
  const user = process.env.BASIC_USER || opts.user;
  const pass = process.env.BASIC_PASS || opts.pass;

  if (!user || !pass) {
    throw new Error('Basic auth requires --user and --pass (or env BASIC_USER / BASIC_PASS)');
  }

  const token = Buffer.from(`${user}:${pass}`).toString('base64');
  const headers = {
    Authorization: `Basic ${token}`,
    ...(opts.body ? { 'Content-Type': 'application/json' } : {}),
  };

  const result = await makeRequest({
    url, method: opts.method, headers, body: opts.body, timeout: opts.timeout,
  });

  return { result, reqHeaders: headers };
}

async function runBearer(url, opts) {
  const token = process.env.TOKEN || opts.token;

  if (!token) {
    throw new Error('Bearer auth requires --token (or env TOKEN)');
  }

  const headers = {
    Authorization: `Bearer ${token}`,
    ...(opts.body ? { 'Content-Type': 'application/json' } : {}),
  };

  const result = await makeRequest({
    url, method: opts.method, headers, body: opts.body, timeout: opts.timeout,
  });

  return { result, reqHeaders: headers };
}

async function runApiKey(url, opts) {
  const key = process.env.API_KEY || opts.key;
  const header = opts.header || 'X-API-Key';

  if (!key) {
    throw new Error('API key auth requires --key (or env API_KEY)');
  }

  const headers = {
    [header]: key,
    ...(opts.body ? { 'Content-Type': 'application/json' } : {}),
  };

  const result = await makeRequest({
    url, method: opts.method, headers, body: opts.body, timeout: opts.timeout,
  });

  return { result, reqHeaders: headers };
}

async function runQuery(url, opts) {
  const key = process.env.API_KEY || opts.key;
  const param = opts.param || 'api_key';

  if (!key) {
    throw new Error('Query param auth requires --key (or env API_KEY)');
  }

  const parsed = new URL(url);
  parsed.searchParams.set(param, key);
  const targetUrl = parsed.toString();

  const headers = opts.body ? { 'Content-Type': 'application/json' } : {};

  const result = await makeRequest({
    url: targetUrl, method: opts.method, headers, body: opts.body, timeout: opts.timeout,
  });

  return { result, reqHeaders: headers };
}

async function runDigest(url, opts) {
  const user = process.env.BASIC_USER || opts.user;
  const pass = process.env.BASIC_PASS || opts.pass;

  if (!user || !pass) {
    throw new Error('Digest auth requires --user and --pass (or env BASIC_USER / BASIC_PASS)');
  }

  const extraHeaders = opts.body ? { 'Content-Type': 'application/json' } : {};
  const result = await digestAuth(url, user, pass, opts.method, extraHeaders, opts.timeout);

  return { result, reqHeaders: { Authorization: '[DIGEST - computed, value redacted]' } };
}

// ─── Commands ─────────────────────────────────────────────────────────────────
async function cmdSingle(command, url, parsed, globalOpts) {
  let runner;
  switch (command) {
    case 'basic':   runner = runBasic; break;
    case 'bearer':  runner = runBearer; break;
    case 'apikey':  runner = runApiKey; break;
    case 'query':   runner = runQuery; break;
    case 'digest':  runner = runDigest; break;
    default: throw new Error(`Unknown command: ${command}`);
  }

  const { result, reqHeaders } = await runner(url, { ...parsed.flags, ...globalOpts });
  printResult(command, result, { ...globalOpts, reqHeaders });

  if (globalOpts.jsonMode) {
    const out = {
      command,
      url,
      status:   result.status,
      expected: globalOpts.expected,
      ok:       result.status === globalOpts.expected,
      body:     result.body,
    };
    if (globalOpts.verbose) {
      out.responseHeaders = redactHeaders(result.headers || {});
    }
    process.stdout.write(JSON.stringify(out, null, 2) + '\n');
  }

  return result;
}

async function cmdAll(url, parsed, globalOpts) {
  process.stdout.write(c.bold(`\nTesting all auth methods against ${c.cyan(url)}\n\n`));
  const results = {};

  const methods = [
    { name: 'none',   fn: () => makeRequest({ url, method: globalOpts.method, headers: {}, timeout: globalOpts.timeout }).then(r => ({ result: r, reqHeaders: {} })) },
    { name: 'basic',  fn: () => runBasic(url,   { ...parsed.flags, ...globalOpts }) },
    { name: 'bearer', fn: () => runBearer(url,  { ...parsed.flags, ...globalOpts }) },
    { name: 'apikey', fn: () => runApiKey(url,  { ...parsed.flags, ...globalOpts }) },
    { name: 'query',  fn: () => runQuery(url,   { ...parsed.flags, ...globalOpts }) },
    { name: 'digest', fn: () => runDigest(url,  { ...parsed.flags, ...globalOpts }) },
  ];

  for (const m of methods) {
    let res;
    try {
      res = await m.fn();
    } catch (err) {
      res = {
        result: { status: 0, statusText: err.message, headers: {}, body: '' },
        reqHeaders: {},
      };
    }
    results[m.name] = res.result;
    printResult(m.name, res.result, { ...globalOpts, reqHeaders: res.reqHeaders });
  }

  if (globalOpts.jsonMode) {
    const out = {};
    for (const [name, r] of Object.entries(results)) {
      out[name] = { status: r.status, ok: r.status === globalOpts.expected };
    }
    process.stdout.write(JSON.stringify(out, null, 2) + '\n');
  }

  const anyOk = Object.values(results).some(r => r.status === globalOpts.expected);
  return anyOk ? { status: globalOpts.expected } : { status: 0 };
}

// ─── Help ─────────────────────────────────────────────────────────────────────
function printHelp() {
  process.stdout.write(`
${c.bold('http-auth-tester')} v${VERSION} — Test HTTP authentication endpoints
${c.dim('Zero external dependencies. Auth values always redacted in output.')}

${c.bold('USAGE')}
  http-auth-tester <command> <url> [options]
  hat <command> <url> [options]

${c.bold('COMMANDS')}
  ${c.cyan('basic')}   <url>   Test HTTP Basic auth
  ${c.cyan('bearer')}  <url>   Test Bearer token auth
  ${c.cyan('apikey')}  <url>   Test API key in request header
  ${c.cyan('query')}   <url>   Test API key in query string
  ${c.cyan('digest')}  <url>   Test HTTP Digest auth
  ${c.cyan('all')}     <url>   Try all methods, report which succeed

${c.bold('CREDENTIALS (env vars take priority over flags)')}
  BASIC_USER / --user <u>       Username for basic/digest auth
  BASIC_PASS / --pass <p>       Password for basic/digest auth
  TOKEN / --token <t>           Bearer token
  API_KEY / --key <k>           API key value

${c.bold('OPTIONS')}
  --header <name>               Header name for apikey (default: X-API-Key)
  --param  <name>               Query param name (default: api_key)
  --expect <code>               Expected HTTP status (default: 200)
  --method <GET|POST|PUT|...>   HTTP method (default: GET)
  --body   <json>               Request body (for POST/PUT)
  --timeout <ms>                Request timeout ms (default: 10000)
  --verbose                     Show request/response headers (redacted)
  --json                        Output results as JSON
  --version                     Print version
  --help                        Show this help

${c.bold('EXAMPLES')}
  BASIC_USER=admin BASIC_PASS=secret hat basic https://api.example.com/me
  hat bearer https://api.example.com/me --token mytoken
  hat apikey https://api.example.com/me --header X-API-Key --key mykey
  hat query  https://api.example.com/search --param api_key --key mykey
  hat all    https://api.example.com/me --expect 200 --json
  hat basic  https://api.example.com/me --expect 401 --verbose
  TOKEN=abc hat bearer https://httpbin.org/bearer --expect 200

${c.bold('EXIT CODES')}
  0   Response status matches --expect
  1   Status mismatch, network error, or missing credentials
`);
}

// ─── Main ─────────────────────────────────────────────────────────────────────
async function main() {
  const argv = process.argv.slice(2);
  const parsed = parseArgs(argv);

  if (parsed.flags.version || parsed.flags.v) {
    process.stdout.write(`http-auth-tester v${VERSION}\n`);
    process.exit(0);
  }

  if (parsed.flags.help || parsed.flags.h || parsed.positional.length === 0) {
    printHelp();
    process.exit(0);
  }

  const [command, url] = parsed.positional;

  if (!url) {
    process.stderr.write(c.red(`Error: URL is required.\n`));
    printHelp();
    process.exit(1);
  }

  const globalOpts = {
    expected: parseInt(parsed.flags.expect, 10) || 200,
    method:   (parsed.flags.method || 'GET').toUpperCase(),
    body:     parsed.flags.body || null,
    timeout:  parseInt(parsed.flags.timeout, 10) || 10000,
    verbose:  !!parsed.flags.verbose,
    jsonMode: !!parsed.flags.json,
    user:     parsed.flags.user,
    pass:     parsed.flags.pass,
    token:    parsed.flags.token,
    key:      parsed.flags.key,
    header:   parsed.flags.header,
    param:    parsed.flags.param,
  };

  let result;
  try {
    if (command !== 'all') {
      process.stdout.write(c.bold(`\nTesting ${c.cyan(command)} auth against ${c.cyan(url)}\n\n`));
    }

    if (command === 'all') {
      result = await cmdAll(url, parsed, globalOpts);
    } else {
      result = await cmdSingle(command, url, parsed, globalOpts);
    }

    process.stdout.write('\n');

    if (result.status !== globalOpts.expected) {
      process.exit(1);
    }
  } catch (err) {
    process.stderr.write(c.red(`Error: ${err.message}\n`));
    process.exit(1);
  }
}

main();
