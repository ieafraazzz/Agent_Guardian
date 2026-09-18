const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const readline = require('node:readline');
const { spawn } = require('node:child_process');
const test = require('node:test');
const { WebSocketServer } = require('ws');

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

async function startProxy(database, extraEnv = {}) {
  const storagePath = fs.mkdtempSync(path.join(os.tmpdir(), 'agent guardian phase2 '));
  fs.writeFileSync(path.join(storagePath, 'mcp-guardian-db.json'), JSON.stringify(database, null, 2));
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

function mockServer(name, mode = 'normal') {
  return {
    name,
    command: process.execPath,
    args: [fixturePath],
    env: { MOCK_SERVER_NAME: name, MOCK_SERVER_MODE: mode }
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
  assert.deepEqual(names, ['alpha__echo', 'alpha__read_file', 'alpha__send_email', 'beta__echo']);

  const [alpha, beta] = await Promise.all([
    proxy.request('call:alpha:1', 'tools/call', { name: 'alpha__echo', arguments: { value: 'A' } }),
    proxy.request(42, 'tools/call', { name: 'beta__echo', arguments: { value: 'B' } })
  ]);
  assert.equal(alpha.id, 'call:alpha:1');
  assert.equal(beta.id, 42);
  assert.match(alpha.result.content[0].text, /"serverName":"alpha"/);
  assert.match(beta.result.content[0].text, /"serverName":"beta"/);
});

test('session histories are isolated and audit lifecycle updates do not duplicate rows', { concurrency: false }, async t => {
  const proxy = await startProxy(configFor([mockServer('alpha')]));
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
  assert.match(sendA.error.message, /approval interface is offline/i);

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
