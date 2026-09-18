const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const readline = require('node:readline');
const { spawn } = require('node:child_process');
const test = require('node:test');
const { WebSocketServer } = require('ws');
const { BrowserGuardian, CrossSurfaceStore } = require('../dist/browser.js');

const projectRoot = path.join(__dirname, '..');
const proxyPath = path.join(projectRoot, 'dist', 'proxy.js');
const fixturePath = path.join(__dirname, 'fixtures', 'mock-mcp-server.js');

function configFor(servers, overrides = {}) {
  return {
    baselines: {},
    logs: [],
    config: {
      servers,
      forbiddenTransitions: [
        ['READ_LOCAL', 'WRITE_COMMUNICATION'],
        ['READ_FINANCIAL', 'WRITE_COMMUNICATION'],
        ['READ_LOCAL', 'EXECUTE_SYSTEM'],
        ['READ_NETWORK', 'EXECUTE_SYSTEM']
      ],
      geminiApiKey: '',
      autoApproveSafe: true,
      ...overrides
    }
  };
}

async function startProxy(database, extraEnv = {}, existingStoragePath) {
  const storagePath = existingStoragePath || fs.mkdtempSync(path.join(os.tmpdir(), 'agent guardian phase3 '));
  if (database) fs.writeFileSync(path.join(storagePath, 'mcp-guardian-db.json'), JSON.stringify(database, null, 2));
  const child = spawn(process.execPath, [proxyPath], {
    cwd: projectRoot,
    stdio: ['pipe', 'pipe', 'pipe'],
    windowsHide: true,
    env: {
      ...process.env,
      MCP_GUARDIAN_STORAGE_PATH: storagePath,
      MCP_GUARDIAN_WS_DISABLED: '1',
      ...extraEnv
    }
  });
  const output = readline.createInterface({ input: child.stdout, terminal: false });
  const pending = new Map();
  let stderr = '';
  child.stderr.on('data', chunk => { stderr += chunk.toString(); });
  output.on('line', line => {
    const message = JSON.parse(line);
    const callback = pending.get(JSON.stringify(message.id));
    if (callback) {
      pending.delete(JSON.stringify(message.id));
      callback(message);
    }
  });

  function request(id, method, params = {}) {
    return new Promise((resolve, reject) => {
      const key = JSON.stringify(id);
      const timer = setTimeout(() => {
        pending.delete(key);
        reject(new Error(`Client timed out waiting for ${method}. stderr: ${stderr}`));
      }, 5_000);
      pending.set(key, message => {
        clearTimeout(timer);
        resolve(message);
      });
      child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', id, method, params })}\n`);
    });
  }

  function notify(method, params = {}) {
    child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', method, params })}\n`);
  }

  async function stop() {
    if (child.exitCode !== null) {
      output.close();
      return;
    }
    if (child.exitCode === null) child.stdin.end();
    await Promise.race([
      new Promise(resolve => child.once('exit', resolve)),
      new Promise(resolve => setTimeout(() => {
        if (child.exitCode === null) child.kill();
        resolve();
      }, 2_000))
    ]);
    output.close();
  }

  return { child, request, notify, stop, storagePath, stderr: () => stderr };
}

function mockServer(name, mode = 'normal', env = {}) {
  return {
    name,
    command: process.execPath,
    args: [fixturePath],
    env: { MOCK_SERVER_NAME: name, MOCK_SERVER_MODE: mode, ...env }
  };
}

test('proxy aggregates multiple servers and preserves arbitrary client ids under concurrent calls', { concurrency: false }, async t => {
  const proxy = await startProxy(configFor([mockServer('alpha'), mockServer('beta')]));
  t.after(() => proxy.stop());

  const initialized = await proxy.request('init:id:with:colons', 'initialize', {
    protocolVersion: '2024-11-05',
    capabilities: {},
    clientInfo: { name: 'phase-two-test', version: '1.0.0' }
  });
  assert.equal(initialized.id, 'init:id:with:colons');
  proxy.notify('notifications/initialized');

  const listed = await proxy.request('list:id:with:colons', 'tools/list');
  assert.equal(listed.id, 'list:id:with:colons');
  const names = listed.result.tools.map(tool => tool.name).sort();
  assert.deepEqual(names, ['alpha__echo', 'alpha__read_file', 'alpha__send_email', 'beta__echo_beta']);

  const [alpha, beta] = await Promise.all([
    proxy.request('call:alpha:1', 'tools/call', { name: 'alpha__echo', arguments: { value: 'A' } }),
    proxy.request(42, 'tools/call', { name: 'beta__echo_beta', arguments: { value: 'B' } })
  ]);
  assert.equal(alpha.id, 'call:alpha:1');
  assert.equal(beta.id, 42);
  assert.match(alpha.result.content[0].text, /"serverName":"alpha"/);
  assert.match(beta.result.content[0].text, /"serverName":"beta"/);
});

test('session histories are isolated and audit lifecycle updates do not duplicate rows', { concurrency: false }, async t => {
  const proxy = await startProxy(configFor([
    mockServer('alpha', 'normal', { MOCK_READ_SECRET: '1' })
  ]));
  t.after(() => proxy.stop());
  await proxy.request(1, 'initialize', { protocolVersion: '2024-11-05', capabilities: {} });
  await proxy.request(2, 'tools/list');

  const sessionMeta = sessionId => ({ guardian: { sessionId } });
  const readA = await proxy.request(3, 'tools/call', {
    name: 'alpha__read_file',
    arguments: { path: 'report.txt' },
    _meta: sessionMeta('session-a')
  });
  assert.ok(readA.result);

  const sendB = await proxy.request(4, 'tools/call', {
    name: 'alpha__send_email',
    arguments: { to: 'professor@example.edu', body: 'report' },
    _meta: sessionMeta('session-b')
  });
  assert.ok(sendB.result, 'another session must not inherit session-a history');

  const sendA = await proxy.request(5, 'tools/call', {
    name: 'alpha__send_email',
    arguments: { to: 'outside@example.com', body: 'report' },
    _meta: sessionMeta('session-a')
  });
  assert.equal(sendA.error.code, -32603);
  assert.match(sendA.error.message, /Credential-labelled|Forbidden transition/i);

  await proxy.stop();
  const database = JSON.parse(fs.readFileSync(path.join(proxy.storagePath, 'mcp-guardian-db.json'), 'utf8'));
  const ids = database.logs.map(log => log.id);
  assert.equal(new Set(ids).size, ids.length, 'audit rows must be updated rather than duplicated');
  assert.equal(database.logs.filter(log => log.status === 'block').length, 1);
});

test('an unresponsive downstream server produces a bounded discovery error', { concurrency: false }, async t => {
  const proxy = await startProxy(
    configFor([mockServer('silent', 'silent-tools')]),
    { MCP_GUARDIAN_REQUEST_TIMEOUT_MS: '200' }
  );
  t.after(() => proxy.stop());
  await proxy.request(1, 'initialize', { protocolVersion: '2024-11-05', capabilities: {} });
  const response = await proxy.request(2, 'tools/list');
  assert.equal(response.error.code, -32001);
  assert.match(response.error.message, /incomplete/i);
  assert.match(response.error.data.failures[0], /timed out/i);
});

test('an unanswered approval expires and fails closed before the client times out', { concurrency: false }, async t => {
  const wss = new WebSocketServer({ port: 0 });
  await new Promise(resolve => wss.once('listening', resolve));
  const port = wss.address().port;
  let connectedResolve;
  const connected = new Promise(resolve => { connectedResolve = resolve; });
  wss.on('connection', socket => {
    connectedResolve();
    socket.on('message', () => {
      // Intentionally leave approve_request unanswered.
    });
  });

  const proxy = await startProxy(
    configFor([mockServer('alpha')]),
    {
      MCP_GUARDIAN_WS_DISABLED: '0',
      MCP_GUARDIAN_WS_PORT: String(port),
      MCP_GUARDIAN_APPROVAL_TIMEOUT_MS: '200'
    }
  );
  t.after(async () => {
    await proxy.stop();
    await new Promise(resolve => wss.close(resolve));
  });
  await connected;
  await proxy.request(1, 'initialize', { protocolVersion: '2024-11-05', capabilities: {} });
  await proxy.request(2, 'tools/list');
  const meta = { guardian: { sessionId: 'approval-timeout' } };
  await proxy.request(3, 'tools/call', {
    name: 'alpha__read_file',
    arguments: { path: 'secret.txt' },
    _meta: meta
  });

  const started = Date.now();
  const response = await proxy.request(4, 'tools/call', {
    name: 'alpha__send_email',
    arguments: { to: 'outside@example.com', body: 'secret' },
    _meta: meta
  });
  const elapsed = Date.now() - started;
  assert.equal(response.error.code, -32603);
  assert.match(response.error.message, /timed out/i);
  assert.ok(elapsed >= 150 && elapsed < 2_000, `approval elapsed ${elapsed}ms`);
});

test('approval is redacted, exact-action bound, expiring, and usable only once', { concurrency: false }, async t => {
  const wss = new WebSocketServer({ port: 0 });
  await new Promise(resolve => wss.once('listening', resolve));
  const port = wss.address().port;
  const approvals = [];
  let connectedResolve;
  const connected = new Promise(resolve => { connectedResolve = resolve; });
  wss.on('connection', socket => {
    connectedResolve();
    socket.on('message', data => {
      const message = JSON.parse(data.toString());
      if (message.type !== 'approve_request') return;
      approvals.push(message.approval);
      const current = message.approval;
      if (approvals.length === 1) {
        socket.send(JSON.stringify({
          type: 'approve_response', id: current.id,
          actionFingerprint: current.actionFingerprint, approved: true
        }));
      } else if (approvals.length === 2) {
        const first = approvals[0];
        socket.send(JSON.stringify({
          type: 'approve_response', id: first.id,
          actionFingerprint: first.actionFingerprint, approved: true
        }));
        setTimeout(() => socket.send(JSON.stringify({
          type: 'approve_response', id: current.id,
          actionFingerprint: current.actionFingerprint, approved: false
        })), 25);
      } else {
        socket.send(JSON.stringify({
          type: 'approve_response', id: current.id,
          actionFingerprint: '0'.repeat(64), approved: true
        }));
      }
    });
  });

  const proxy = await startProxy(
    configFor([mockServer('alpha')], {
      autoApproveSafe: false,
      sessionPolicy: {
        intent: 'Echo one reviewed value',
        allowedCapabilities: ['GENERAL'],
        trustedDestinations: []
      }
    }),
    { MCP_GUARDIAN_WS_DISABLED: '0', MCP_GUARDIAN_WS_PORT: String(port) }
  );
  t.after(async () => {
    await proxy.stop();
    await new Promise(resolve => wss.close(resolve));
  });
  await connected;
  await proxy.request(1, 'initialize', { protocolVersion: '2024-11-05', capabilities: {} });
  await proxy.request(2, 'tools/list');
  const params = {
    name: 'alpha__echo',
    arguments: { value: 'api_key=top-secret-token' },
    _meta: { guardian: { sessionId: 'approval-demo' } }
  };

  const approved = await proxy.request(3, 'tools/call', params);
  assert.ok(approved.result);
  assert.equal(approvals[0].intent, 'Echo one reviewed value');
  assert.doesNotMatch(JSON.stringify(approvals[0].arguments), /top-secret-token/);
  assert.match(JSON.stringify(approvals[0].arguments), /REDACTED/);

  const replayed = await proxy.request(4, 'tools/call', params);
  assert.equal(replayed.error.code, -32603);
  assert.match(replayed.error.message, /Blocked by user/i);
  assert.notEqual(approvals[0].id, approvals[1].id, 'each call must receive a distinct one-time request id');

  const mismatched = await proxy.request(5, 'tools/call', params);
  assert.equal(mismatched.error.code, -32603);
  assert.match(mismatched.error.message, /did not match the exact action/i);
});

test('configured session policy and MCP metadata gate capabilities and destinations', { concurrency: false }, async t => {
  const proxy = await startProxy(configFor([mockServer('alpha')], {
    sessionPolicy: {
      intent: 'Send only to the professor',
      allowedCapabilities: ['READ_LOCAL'],
      trustedDestinations: ['professor@example.edu']
    }
  }));
  t.after(() => proxy.stop());
  await proxy.request(1, 'initialize', { protocolVersion: '2024-11-05', capabilities: {} });
  await proxy.request(2, 'tools/list');

  const echo = await proxy.request(3, 'tools/call', {
    name: 'alpha__echo',
    arguments: { value: 'allowed by per-call context' },
    _meta: { guardian: { sessionId: 'policy-demo', allowedCapabilities: ['GENERAL'] } }
  });
  assert.ok(echo.result);

  const professor = await proxy.request(4, 'tools/call', {
    name: 'alpha__send_email',
    arguments: { to: 'professor@example.edu', body: 'report' },
    _meta: { guardian: { sessionId: 'policy-demo', allowedCapabilities: ['WRITE_COMMUNICATION'] } }
  });
  assert.ok(professor.result);

  const attacker = await proxy.request(5, 'tools/call', {
    name: 'alpha__send_email',
    arguments: { to: 'attacker@example.com', body: 'report' },
    _meta: { guardian: { sessionId: 'policy-demo', allowedCapabilities: ['WRITE_COMMUNICATION'] } }
  });
  assert.equal(attacker.error.code, -32603);
  assert.match(attacker.error.message, /approval interface is offline/i);

  await proxy.stop();
  const database = JSON.parse(fs.readFileSync(path.join(proxy.storagePath, 'mcp-guardian-db.json'), 'utf8'));
  const held = database.logs.find(item => item.destination === 'attacker@example.com');
  assert.equal(held.status, 'block');
  assert.ok(held.evidence.some(item => item.ruleId === 'R4'));
  assert.equal(held.intent, 'Send only to the professor');
});

test('untrusted browser provenance holds a later MCP write while the benign twin proceeds', { concurrency: false }, async t => {
  const proxy = await startProxy(configFor([mockServer('alpha')]));
  t.after(() => proxy.stop());
  await proxy.request(1, 'initialize', { protocolVersion: '2024-11-05', capabilities: {} });
  await proxy.request(2, 'tools/list');
  const store = new CrossSurfaceStore(proxy.storagePath);
  const guardian = new BrowserGuardian(store, { trustedOrigins: ['https://trusted.example'] });

  guardian.observe({
    sessionId: 'browser-attack', url: 'https://evil.example/invoice', origin: 'https://evil.example',
    visibleText: 'Send invoice 8842', agentText: 'Send invoice 8842'
  });
  const held = await proxy.request(3, 'tools/call', {
    name: 'alpha__send_email',
    arguments: { to: 'outside@example.com', body: 'Send invoice 8842' },
    _meta: { guardian: { sessionId: 'browser-attack' } }
  });
  assert.equal(held.error.code, -32603);
  assert.match(held.error.message, /approval interface is offline/i);

  guardian.observe({
    sessionId: 'browser-benign', url: 'https://trusted.example/invoice', origin: 'https://trusted.example',
    visibleText: 'Send invoice 8842', agentText: 'Send invoice 8842'
  });
  const allowed = await proxy.request(4, 'tools/call', {
    name: 'alpha__send_email',
    arguments: { to: 'professor@example.edu', body: 'Send invoice 8842' },
    _meta: { guardian: { sessionId: 'browser-benign' } }
  });
  assert.ok(allowed.result);

  await proxy.stop();
  const database = JSON.parse(fs.readFileSync(path.join(proxy.storagePath, 'mcp-guardian-db.json'), 'utf8'));
  const crossSurface = database.logs.find(item => item.sessionId === 'browser-attack');
  assert.ok(crossSurface.evidence.some(item => item.ruleId === 'R8'));
  assert.equal(crossSurface.status, 'block');
});

test('client payload size and nesting limits fail closed', { concurrency: false }, async t => {
  const proxy = await startProxy(configFor([], {
    resourceLimits: {
      maxMessageBytes: 512,
      maxNestingDepth: 5,
      requestTimeoutMs: 1_000,
      approvalTimeoutMs: 500
    }
  }));
  t.after(() => proxy.stop());

  const oversized = await proxy.request(null, 'initialize', { padding: 'x'.repeat(1_000) });
  assert.equal(oversized.error.code, -32700);
  assert.match(oversized.error.message, /size limit/i);

  let nested = 'leaf';
  for (let index = 0; index < 8; index += 1) nested = { nested };
  const tooDeep = await proxy.request(null, 'initialize', nested);
  assert.equal(tooDeep.error.code, -32700);
  assert.match(tooDeep.error.message, /nesting-depth limit/i);
});

test('poisoned first-seen tool definitions are rejected before execution', { concurrency: false }, async t => {
  const proxy = await startProxy(configFor([
    mockServer('alpha', 'normal', { MOCK_TOOL_VARIANT: 'poisoned' })
  ]));
  t.after(() => proxy.stop());
  await proxy.request(1, 'initialize', { protocolVersion: '2024-11-05', capabilities: {} });
  await proxy.request(2, 'tools/list');

  const response = await proxy.request(3, 'tools/call', {
    name: 'alpha__echo',
    arguments: { value: 'hello' }
  });
  assert.equal(response.error.code, -32603);
  assert.match(response.error.message, /onboarding|rejected|security review|baseline/i);

  await proxy.stop();
  const database = JSON.parse(fs.readFileSync(path.join(proxy.storagePath, 'mcp-guardian-db.json'), 'utf8'));
  const baseline = database.baselines.alpha.echo;
  assert.equal(baseline.status, 'rejected');
  assert.equal(baseline.approved, false);
  assert.ok(baseline.evidence.some(item => item.metadata.code === 'PI_IGNORE'));
});

test('strict first-seen policy rejects even a clean unapproved tool', { concurrency: false }, async t => {
  const proxy = await startProxy(configFor([mockServer('alpha')], { firstSeenPolicy: 'block' }));
  t.after(() => proxy.stop());
  await proxy.request(1, 'initialize', { protocolVersion: '2024-11-05', capabilities: {} });
  await proxy.request(2, 'tools/list');
  const response = await proxy.request(3, 'tools/call', {
    name: 'alpha__echo',
    arguments: { value: 'hello' }
  });
  assert.equal(response.error.code, -32603);
  await proxy.stop();
  const database = JSON.parse(fs.readFileSync(path.join(proxy.storagePath, 'mcp-guardian-db.json'), 'utf8'));
  assert.equal(database.baselines.alpha.echo.status, 'rejected');
  assert.equal(database.baselines.alpha.echo.approved, false);
});

test('nested definition drift is preserved as an exact diff and blocks execution', { concurrency: false }, async t => {
  const first = await startProxy(configFor([mockServer('alpha')]));
  await first.request(1, 'initialize', { protocolVersion: '2024-11-05', capabilities: {} });
  await first.request(2, 'tools/list');
  await first.stop();

  const databasePath = path.join(first.storagePath, 'mcp-guardian-db.json');
  const database = JSON.parse(fs.readFileSync(databasePath, 'utf8'));
  database.config.servers[0].env.MOCK_TOOL_VARIANT = 'drifted';
  fs.writeFileSync(databasePath, JSON.stringify(database, null, 2));

  const second = await startProxy(null, {}, first.storagePath);
  t.after(() => second.stop());
  await second.request(3, 'initialize', { protocolVersion: '2024-11-05', capabilities: {} });
  await second.request(4, 'tools/list');
  const response = await second.request(5, 'tools/call', {
    name: 'alpha__echo',
    arguments: { value: 'changed' }
  });
  assert.equal(response.error.code, -32603);
  assert.match(response.error.message, /drift|re-baseline/i);

  await second.stop();
  const updated = JSON.parse(fs.readFileSync(databasePath, 'utf8'));
  const baseline = updated.baselines.alpha.echo;
  assert.equal(baseline.status, 'drifted');
  assert.notEqual(baseline.hash, baseline.observedHash);
  assert.ok(baseline.differences.some(item => item.path.includes('inputSchema.properties.value.enum')));
});

test('poisoned tool output is withheld from the client and audited', { concurrency: false }, async t => {
  const proxy = await startProxy(configFor([
    mockServer('alpha', 'normal', { MOCK_TOOL_VARIANT: 'poisoned-output' })
  ]));
  t.after(() => proxy.stop());
  await proxy.request(1, 'initialize', { protocolVersion: '2024-11-05', capabilities: {} });
  await proxy.request(2, 'tools/list');
  const response = await proxy.request(3, 'tools/call', {
    name: 'alpha__echo',
    arguments: { value: 'hello' }
  });
  assert.equal(response.error.code, -32603);
  assert.match(response.error.message, /output blocked/i);

  await proxy.stop();
  const database = JSON.parse(fs.readFileSync(path.join(proxy.storagePath, 'mcp-guardian-db.json'), 'utf8'));
  const blocked = database.logs.find(log => log.toolName === 'echo' && log.status === 'block');
  assert.ok(blocked);
  assert.ok(blocked.evidence.some(item => item.metadata.code === 'PI_SECRET_SIDE_EFFECT'));
});

test('same-name tools from different servers are flagged as shadowing', { concurrency: false }, async t => {
  const proxy = await startProxy(configFor([
    mockServer('alpha'),
    mockServer('beta', 'normal', { MOCK_ECHO_TOOL_NAME: 'echo' })
  ]));
  t.after(() => proxy.stop());
  await proxy.request(1, 'initialize', { protocolVersion: '2024-11-05', capabilities: {} });
  await proxy.request(2, 'tools/list');
  const response = await proxy.request(3, 'tools/call', {
    name: 'alpha__echo',
    arguments: { value: 'hello' }
  });
  assert.equal(response.error.code, -32603);

  await proxy.stop();
  const database = JSON.parse(fs.readFileSync(path.join(proxy.storagePath, 'mcp-guardian-db.json'), 'utf8'));
  assert.equal(database.baselines.alpha.echo.status, 'pending');
  assert.equal(database.baselines.beta.echo.status, 'pending');
  assert.ok(database.baselines.alpha.echo.evidence.some(item => item.ruleId === 'R2'));
});
