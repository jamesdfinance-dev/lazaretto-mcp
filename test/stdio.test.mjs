// End-to-end tests of the stdio server as a client runs it: index.mjs is
// spawned as a child process and driven over stdio with the SDK's own client,
// against an in-process HTTP stub standing in for the Lazaretto API
// (LAZARETTO_BASE_URL). Nothing here touches the network.
import { test, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';

const INDEX = fileURLToPath(new URL('../index.mjs', import.meta.url));
const KEY = 'test-key-123';
const LOCKFILE = JSON.stringify({
  name: 'fixture',
  lockfileVersion: 3,
  packages: { '': { name: 'fixture' }, 'node_modules/chalk': { version: '5.6.1' } },
});

// ---- the stub API ----------------------------------------------------------

/** Every request the stub saw since the last reset. */
let seen = [];
/** "METHOD /path" to a function of the request returning {status, json} or
 *  {status, text}. Anything unrouted is a 599, which no test expects. */
let routes = {};

const stub = createServer(async (req, res) => {
  let raw = '';
  for await (const chunk of req) raw += chunk;
  const path = req.url.split('?')[0];
  const r = { method: req.method, url: req.url, path, headers: req.headers, body: raw };
  seen.push(r);
  const route = Object.entries(routes).find(([k]) => {
    const [m, p] = k.split(' ');
    return m === req.method && (p.endsWith('*') ? path.startsWith(p.slice(0, -1)) : path === p);
  });
  const out = route ? route[1](r) : { status: 599, text: `unrouted ${req.method} ${path}` };
  if (out.json !== undefined) {
    res.writeHead(out.status, { 'content-type': 'application/json' });
    res.end(JSON.stringify(out.json));
  } else {
    res.writeHead(out.status, { 'content-type': 'text/html' });
    res.end(out.text ?? '');
  }
});

let BASE;
let workdir;
const clients = {};

async function connect(env) {
  const client = new Client({ name: 'stdio-test', version: '0.0.0' });
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [INDEX],
    // Only these plus the SDK's minimal default environment: a key in the
    // developer's shell must not leak into a "no key" run.
    env: { LAZARETTO_BASE_URL: BASE, ...env },
    cwd: workdir,
  });
  await client.connect(transport);
  return client;
}

before(async () => {
  await new Promise((r) => stub.listen(0, '127.0.0.1', r));
  BASE = `http://127.0.0.1:${stub.address().port}`;
  workdir = mkdtempSync(join(tmpdir(), 'lazaretto-mcp-test-'));
  writeFileSync(join(workdir, 'package-lock.json'), LOCKFILE);
  [clients.none, clients.blank, clients.keyed] = await Promise.all([
    connect({}),
    connect({ LAZARETTO_API_KEY: '   ' }),
    connect({ LAZARETTO_API_KEY: KEY }),
  ]);
});

after(async () => {
  await Promise.all(Object.values(clients).map((c) => c.close()));
  await new Promise((r) => stub.close(r));
  rmSync(workdir, { recursive: true, force: true });
});

beforeEach(() => {
  seen = [];
  routes = {};
});

/** Call a tool and parse its JSON text result. */
async function call(client, name, args) {
  const r = await client.callTool({ name, arguments: args });
  const text = r.content?.[0]?.text ?? '';
  let body;
  try {
    body = JSON.parse(text);
  } catch {
    body = undefined;
  }
  return { isError: r.isError === true, body, text };
}

/** Invalid arguments: newer SDKs answer with an isError result, older ones
 *  throw. Either way the call must not succeed. */
async function rejects(client, name, args) {
  try {
    const r = await client.callTool({ name, arguments: args });
    assert.equal(r.isError, true, `expected ${name} to reject ${JSON.stringify(args)}`);
  } catch (e) {
    assert.match(String(e?.message ?? e), /invalid|validation/i);
  }
}

const ids = (n) => Array.from({ length: n }, (_, i) => `pkg-${i}@1.0.${i}`);
const x402Challenge = () => ({
  x402Version: 1,
  error: 'payment_required',
  accepts: [{ scheme: 'exact', network: 'base', maxAmountRequired: '10000', payTo: '0xabc' }],
  extensions: { bazaar: { info: {} } },
  hint: { message: 'Payment required.', free_trial: 'POST /v1/trial' },
});

// ---- no key, blank key ------------------------------------------------------

test('no key: scan_lockfile_deep sends nothing and says how to get a key', async () => {
  const r = await call(clients.none, 'scan_lockfile_deep', {});
  assert.equal(r.isError, true);
  assert.equal(r.body.payment_required, true);
  assert.equal(r.body.not_an_all_clear, true);
  assert.match(r.body.detail, /\/buy/);
  assert.match(r.body.detail, /\/v1\/trial/);
  assert.equal(seen.length, 0, 'nothing may be sent without a key');
});

test('no key: a keyless 402 drops the x402 challenge and says where per-call payment goes', async () => {
  routes['POST /v1/scan'] = () => ({ status: 402, json: x402Challenge() });
  const r = await call(clients.none, 'scan_artifact', { target_type: 'npm_package', ref: 'chalk@5.6.1' });
  assert.equal(r.isError, true);
  assert.equal(r.body.payment_required, true);
  assert.equal(r.body.not_an_all_clear, true);
  assert.equal(r.body.accepts, undefined);
  assert.equal(r.body.x402Version, undefined);
  assert.equal(r.body.extensions, undefined);
  assert.deepEqual(r.body.hint, x402Challenge().hint, 'the rest of the service answer is kept');
  assert.equal(
    r.body.per_call_payment,
    `Per-call x402 payment must be made by the agent's own HTTP client against ${BASE}/v1/scan, not through this tool.`,
  );
  assert.match(r.body.detail, /^A full scan is paid\. Set LAZARETTO_API_KEY/);
  assert.equal(seen.length, 1);
  assert.equal(seen[0].headers['x-api-key'], undefined);
});

test('no key: a keyless 401 is a paywall, not a rejected key', async () => {
  routes['POST /v1/scan'] = () => ({ status: 401, json: { error: 'api_key_required' } });
  const r = await call(clients.none, 'scan_mcp_server', { url: 'https://example.com/mcp' });
  assert.equal(r.isError, true);
  assert.equal(r.body.payment_required, true);
  assert.equal(r.body.error, 'api_key_required');
  assert.match(r.body.detail, /^Scanning a server is paid\. Set LAZARETTO_API_KEY/);
  assert.doesNotMatch(r.body.detail, /not accepted/);
  assert.deepEqual(JSON.parse(seen[0].body), {
    target: { type: 'mcp_server', ref: 'https://example.com/mcp' },
    depth: 'full',
  });
});

test('blank key: treated as no key, never sent', async () => {
  const deep = await call(clients.blank, 'scan_lockfile_deep', {});
  assert.equal(deep.body.payment_required, true);
  assert.equal(seen.length, 0);

  routes['POST /v1/scan'] = () => ({ status: 401, json: { error: 'api_key_required' } });
  const r = await call(clients.blank, 'check_mcp_tools', { tools_json: '{"tools":[]}' });
  assert.equal(r.body.payment_required, true);
  assert.doesNotMatch(r.body.detail, /not accepted/);
  assert.equal(seen[0].headers['x-api-key'], undefined);
});

// ---- keyed ------------------------------------------------------------------

test('keyed 402: the service reason comes first and is closed with a period', async () => {
  routes['POST /v1/scan'] = () => ({ status: 402, json: { error: 'insufficient_credits', detail: 'This key has no credits left' } });
  const r = await call(clients.keyed, 'check_mcp_tools', { tools_json: '{"tools":[]}' });
  assert.equal(r.isError, true);
  assert.equal(r.body.payment_required, true);
  assert.equal(r.body.error, 'insufficient_credits');
  assert.equal(r.body.detail, `This key has no credits left. Buy more credits by card at ${BASE}/buy.`);
  assert.equal(seen[0].headers['x-api-key'], KEY);

  routes['POST /v1/scan'] = () => ({ status: 402, json: { error: 'daily_limit_reached', detail: 'Daily limit reached.' } });
  const again = await call(clients.keyed, 'scan_artifact', { target_type: 'npm_package', ref: 'chalk@5.6.1' });
  assert.equal(again.body.detail, `Daily limit reached. Buy more credits by card at ${BASE}/buy.`);
});

test('keyed 402 on a batch keeps the source and is not an all-clear', async () => {
  routes['POST /v1/scan/batch'] = () => ({
    status: 402,
    json: { error: 'insufficient_credits', detail: 'A batch scan costs one credit per package', ways_to_pay: { card: 'x' } },
  });
  const r = await call(clients.keyed, 'scan_lockfile_deep', {});
  assert.equal(r.isError, true);
  assert.equal(r.body.payment_required, true);
  assert.equal(r.body.not_an_all_clear, true);
  assert.equal(r.body.source, 'package-lock.json');
  assert.deepEqual(r.body.ways_to_pay, { card: 'x' });
  assert.equal(r.body.detail, `A batch scan costs one credit per package. Buy more credits by card at ${BASE}/buy.`);
});

test('keyed 401: the key was not accepted', async () => {
  routes['POST /v1/scan'] = () => ({ status: 401, json: { error: 'invalid_api_key' } });
  const r = await call(clients.keyed, 'scan_artifact', { target_type: 'npm_package', ref: 'chalk@5.6.1' });
  assert.equal(r.isError, true);
  assert.equal(r.body.payment_required, undefined);
  assert.equal(r.body.error, 'invalid_api_key');
  assert.equal(r.body.not_an_all_clear, true);
  assert.match(r.body.detail, /LAZARETTO_API_KEY was not accepted/);
});

test('a JSON 400 keeps the service error and detail', async () => {
  routes['POST /v1/scan'] = () => ({ status: 400, json: { error: 'invalid_request', detail: 'ref must be name@version' } });
  const r = await call(clients.keyed, 'scan_artifact', { target_type: 'npm_package', ref: 'chalk' });
  assert.equal(r.isError, true);
  assert.equal(r.body.error, 'invalid_request');
  assert.equal(r.body.detail, 'ref must be name@version');
  assert.equal(r.body.not_an_all_clear, true);
});

test('a non-JSON 5xx is an error and never an all-clear, on every paid tool', async () => {
  routes['POST /v1/scan'] = () => ({ status: 502, text: '<html>Bad Gateway</html>' });
  routes['POST /v1/scan/batch'] = () => ({ status: 502, text: '<html>Bad Gateway</html>' });
  const calls = [
    ['scan_artifact', { target_type: 'npm_package', ref: 'chalk@5.6.1' }],
    ['scan_mcp_server', { url: 'https://example.com/mcp' }],
    ['check_mcp_tools', { tools_json: '{"tools":[]}' }],
    ['scan_lockfile_deep', {}],
  ];
  for (const [name, args] of calls) {
    const r = await call(clients.keyed, name, args);
    assert.equal(r.isError, true, name);
    assert.equal(r.body.not_an_all_clear, true, name);
    assert.match(r.body.detail, /could not complete the scan/, name);
  }
});

test('an unreadable 200 is an error, not a result', async () => {
  routes['POST /v1/scan'] = () => ({ status: 200, text: 'not json' });
  const r = await call(clients.keyed, 'scan_artifact', { target_type: 'npm_package', ref: 'chalk@5.6.1' });
  assert.equal(r.isError, true);
  assert.equal(r.body.not_an_all_clear, true);
});

test('a transport failure is an error and never an all-clear', async () => {
  const dead = await connect({ LAZARETTO_API_KEY: KEY, LAZARETTO_BASE_URL: 'http://127.0.0.1:1' });
  try {
    for (const [name, args] of [
      ['scan_artifact', { target_type: 'npm_package', ref: 'chalk@5.6.1' }],
      ['scan_lockfile_deep', { packages: ['chalk@5.6.1'] }],
    ]) {
      const r = await call(dead, name, args);
      assert.equal(r.isError, true, name);
      assert.equal(r.body.error, 'request_failed', name);
      assert.equal(r.body.not_an_all_clear, true, name);
    }
  } finally {
    await dead.close();
  }
});

// ---- find_attestation -------------------------------------------------------

test('find_attestation: a hit is returned as a result', async () => {
  const hit = { found: true, subject: 'chalk@5.6.1', verdict: 'clear', attestation: 'a.b.c', contradicted: null, stale_rules: false };
  routes['GET /v1/attestations/*'] = () => ({ status: 200, json: hit });
  const r = await call(clients.none, 'find_attestation', { subject: 'chalk@5.6.1' });
  assert.equal(r.isError, false);
  assert.deepEqual(r.body, hit);
  assert.equal(seen[0].url, '/v1/attestations/chalk%405.6.1');
});

test('find_attestation: a 404 miss is an answer, not an error', async () => {
  routes['GET /v1/attestations/*'] = () => ({ status: 404, json: { found: false, subject: 'chalk@5.6.1' } });
  const r = await call(clients.none, 'find_attestation', { subject: 'chalk@5.6.1' });
  assert.equal(r.isError, false);
  assert.equal(r.body.found, false);
});

test('find_attestation: a contradicted verdict is flagged as an error', async () => {
  routes['GET /v1/attestations/*'] = () => ({
    status: 200,
    json: { found: true, verdict: 'clear', attestation: 'a.b.c', contradicted: { source: 'known_bad' } },
  });
  const r = await call(clients.none, 'find_attestation', { subject: 'chalk@5.6.1' });
  assert.equal(r.isError, true);
  assert.deepEqual(r.body.contradicted, { source: 'known_bad' });
});

test('find_attestation: a non-JSON 5xx is an error, not a verdict', async () => {
  routes['GET /v1/attestations/*'] = () => ({ status: 503, text: '<html>down</html>' });
  const r = await call(clients.none, 'find_attestation', { subject: 'chalk@5.6.1' });
  assert.equal(r.isError, true);
  assert.equal(r.body.error, 'lookup_failed');
  assert.match(r.body.detail, /not a verdict/);
});

test('find_attestation: bare and upper-case hashes are normalized', async () => {
  routes['GET /v1/attestations/*'] = () => ({ status: 404, json: { found: false } });
  const hex = 'AB'.repeat(32);
  const want = `/v1/attestations/sha256%3A${hex.toLowerCase()}`;
  for (const subject of [hex, `sha256:${hex}`, `SHA256:${hex}`, hex.toLowerCase()]) {
    seen = [];
    const r = await call(clients.none, 'find_attestation', { subject });
    assert.equal(r.isError, false, subject);
    assert.equal(seen[0].url, want, subject);
  }
});

// ---- scan_lockfile_deep -----------------------------------------------------

test('scan_lockfile_deep reads the lockfile from the working directory', async () => {
  routes['POST /v1/scan/batch'] = () => ({
    status: 200,
    json: { requested: 1, scanned: 1, complete_coverage: true, not_scanned: null, results: [] },
  });
  const r = await call(clients.keyed, 'scan_lockfile_deep', {});
  assert.equal(r.isError, false);
  assert.equal(r.body.source, 'package-lock.json');
  assert.equal(r.body.next_call, undefined);
  assert.equal(seen[0].headers['content-type'], 'text/plain');
  assert.equal(seen[0].headers['x-api-key'], KEY);
  assert.equal(seen[0].body, LOCKFILE);
});

test('scan_lockfile_deep with packages sends the list, not the lockfile, and surfaces what is left', async () => {
  const left = ids(30);
  routes['POST /v1/scan/batch'] = () => ({
    status: 200,
    json: {
      requested: 2,
      scanned: 2,
      complete_coverage: false,
      not_scanned: {
        count: 30,
        reasons: ['capped at 25 packages per call; send the rest in another call'],
        by_reason: { credits: 0, time: 5, cap: 25 },
        packages: left,
      },
      results: [],
    },
  });
  const r = await call(clients.keyed, 'scan_lockfile_deep', {
    packages: ['chalk@5.6.1', '@babel/core@7.24.0'],
    lockfile: 'ignored when packages is set',
  });
  assert.equal(r.isError, false);
  assert.equal(r.body.source, '(packages input)');
  assert.equal(seen.length, 1);
  assert.equal(seen[0].headers['content-type'], 'application/json');
  assert.equal(seen[0].headers['x-api-key'], KEY);
  assert.deepEqual(JSON.parse(seen[0].body), {
    packages: [
      { name: 'chalk', version: '5.6.1' },
      { name: '@babel/core', version: '7.24.0' },
    ],
  });
  assert.deepEqual(r.body.not_scanned.packages, left, 'the full list is kept');
  assert.deepEqual(r.body.next_call.packages, left.slice(0, 25));
  assert.match(r.body.next_call.detail, /same lockfile or list rescans/);
  assert.match(r.body.next_call.detail, /`packages` set to the next up to 25 entries of not_scanned\.packages/);
  assert.doesNotMatch(r.body.next_call.detail, /ran short of credits/);
});

test('scan_lockfile_deep: out of time and short of credits, with a list longer than shown', async () => {
  routes['POST /v1/scan/batch'] = () => ({
    status: 200,
    json: {
      complete_coverage: false,
      not_scanned: {
        count: 250,
        reasons: ['ran out of time', 'not enough credits on this key to scan the rest'],
        by_reason: { credits: 240, time: 10, cap: 0 },
        packages: ids(200),
      },
      results: [],
    },
  });
  const r = await call(clients.keyed, 'scan_lockfile_deep', {});
  assert.equal(r.body.next_call.packages.length, 25);
  assert.match(r.body.next_call.detail, /240 of them were left because this key ran short of credits/);
  assert.match(r.body.next_call.detail, new RegExp(`${BASE}/buy`));
  assert.match(r.body.next_call.detail, /lists only the first 200 of the 250/);
});

test('scan_lockfile_deep: an older service with no packages list gets no next_call', async () => {
  routes['POST /v1/scan/batch'] = () => ({
    status: 200,
    json: { complete_coverage: false, not_scanned: { count: 3, reasons: ['capped'] }, results: [] },
  });
  const r = await call(clients.keyed, 'scan_lockfile_deep', {});
  assert.equal(r.isError, false);
  assert.equal(r.body.next_call, undefined);
});

test('scan_lockfile_deep rejects a malformed or oversized packages list without sending it', async () => {
  await rejects(clients.keyed, 'scan_lockfile_deep', { packages: ['chalk'] });
  await rejects(clients.keyed, 'scan_lockfile_deep', { packages: ['@scope/name'] });
  await rejects(clients.keyed, 'scan_lockfile_deep', { packages: [] });
  await rejects(clients.keyed, 'scan_lockfile_deep', { packages: ids(26) });
  assert.equal(seen.length, 0);
});
