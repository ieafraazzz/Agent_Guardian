import * as crypto from 'crypto';
import * as os from 'os';
import * as path from 'path';
import * as readline from 'readline';
import { ChildProcess, spawn } from 'child_process';
import WebSocket from 'ws';
import { GuardianDb } from './db';
import {
  autoAssignCategory,
  checkTransition,
  computeToolHash,
  scanHeuristics,
  scanSemantic
} from './detector';
import {
  AuditLog,
  DownstreamServerConfig,
  ExtensionMessage,
  ProxyMessage,
  ResourceLimits
} from './types';

type JsonRpcId = string | number | null;

interface DownstreamRuntime {
  config: DownstreamServerConfig;
  signature: string;
  process: ChildProcess;
  reader: readline.Interface;
}

interface PendingDownstreamRequest {
  serverName: string;
  method: string;
  timer: NodeJS.Timeout;
  resolve: (message: any) => void;
  reject: (error: Error) => void;
}

interface PendingApproval {
  timer: NodeJS.Timeout;
  resolve: (approved: boolean) => void;
  log: AuditLog;
}

interface SessionState {
  categories: string[];
  lastCallTime: number;
}

const DEFAULT_LIMITS: ResourceLimits = {
  maxMessageBytes: 1_048_576,
  maxNestingDepth: 64,
  requestTimeoutMs: Number(process.env.MCP_GUARDIAN_REQUEST_TIMEOUT_MS) || 10_000,
  approvalTimeoutMs: Number(process.env.MCP_GUARDIAN_APPROVAL_TIMEOUT_MS) || 20_000
};
const SESSION_TIMEOUT_MS = 2 * 60 * 1000;
const STORAGE_PATH = process.env.MCP_GUARDIAN_STORAGE_PATH || path.join(os.homedir(), '.mcp-guardian');
const WS_DISABLED = process.env.MCP_GUARDIAN_WS_DISABLED === '1';
const WS_PORT = Number(process.env.MCP_GUARDIAN_WS_PORT) || 1337;

const db = new GuardianDb(STORAGE_PATH);
const downstreams = new Map<string, DownstreamRuntime>();
const pendingDownstream = new Map<string, PendingDownstreamRequest>();
const pendingApprovals = new Map<string, PendingApproval>();
const sessions = new Map<string, SessionState>();
const toolsMapping = new Map<string, { serverName: string; originalName: string }>();

let requestSequence = 0;
let ws: WebSocket | null = null;
let wsConnected = false;
let wsReconnectTimer: NodeJS.Timeout | undefined;
let shuttingDown = false;

const clientReader = readline.createInterface({ input: process.stdin, terminal: false });

function limits(): ResourceLimits {
  return { ...DEFAULT_LIMITS, ...(db.getConfig().resourceLimits || {}) };
}

function nextRequestId(): string {
  requestSequence += 1;
  return `guardian-${process.pid}-${requestSequence}-${crypto.randomBytes(6).toString('hex')}`;
}

function writeToClient(message: any): void {
  const serialized = JSON.stringify(message);
  if (Buffer.byteLength(serialized, 'utf8') > limits().maxMessageBytes) {
    process.stdout.write(JSON.stringify({
      jsonrpc: '2.0',
      id: message?.id ?? null,
      error: { code: -32002, message: 'Guardian response exceeded configured size limit' }
    }) + '\n');
    return;
  }
  process.stdout.write(serialized + '\n');
}

function writeError(id: JsonRpcId, code: number, message: string, data?: unknown): void {
  writeToClient({ jsonrpc: '2.0', id, error: { code, message, ...(data === undefined ? {} : { data }) } });
}

function validateIncomingLine(line: string): any {
  if (Buffer.byteLength(line, 'utf8') > limits().maxMessageBytes) {
    throw new Error('Message exceeded configured size limit');
  }
  const parsed = JSON.parse(line);
  if (exceedsDepth(parsed, limits().maxNestingDepth)) {
    throw new Error('Message exceeded configured nesting-depth limit');
  }
  return parsed;
}

function exceedsDepth(value: unknown, maximum: number): boolean {
  const pending: Array<{ value: unknown; depth: number }> = [{ value, depth: 0 }];
  while (pending.length > 0) {
    const current = pending.pop()!;
    if (current.depth > maximum) return true;
    if (current.value === null || typeof current.value !== 'object') continue;
    const children = Array.isArray(current.value)
      ? current.value
      : Object.values(current.value as Record<string, unknown>);
    for (const child of children) pending.push({ value: child, depth: current.depth + 1 });
  }
  return false;
}

function resolveCommand(command: string): string {
  if (process.platform !== 'win32' || path.extname(command)) return command;
  const lower = command.toLowerCase();
  return lower === 'npm' || lower === 'npx' || lower === 'pnpm' || lower === 'yarn'
    ? `${command}.cmd`
    : command;
}

function serverSignature(config: DownstreamServerConfig): string {
  return JSON.stringify({ command: config.command, args: config.args || [], env: config.env || {} });
}

function connectToExtension(): void {
  if (WS_DISABLED || shuttingDown || ws) return;
  const socket = new WebSocket(`ws://127.0.0.1:${WS_PORT}`);
  ws = socket;

  socket.on('open', () => {
    if (ws !== socket) return;
    wsConnected = true;
    console.error(`[MCP-Guardian-Proxy] Connected to VS Code extension on port ${WS_PORT}`);
    sendToExtension({
      type: 'sync_state',
      baselines: db.getBaselines(),
      logs: db.getLogs(),
      config: db.getConfig()
    });
  });

  socket.on('message', data => {
    try {
      handleExtensionMessage(validateIncomingLine(data.toString()) as ExtensionMessage);
    } catch (error) {
      console.error('[MCP-Guardian-Proxy] Invalid extension message:', error);
    }
  });

  const disconnected = () => {
    if (ws !== socket) return;
    wsConnected = false;
    ws = null;
    if (!shuttingDown) wsReconnectTimer = setTimeout(connectToExtension, 3_000);
  };
  socket.on('close', disconnected);
  socket.on('error', disconnected);
}

function sendToExtension(message: ProxyMessage): void {
  if (!ws || !wsConnected || ws.readyState !== WebSocket.OPEN) return;
  const serialized = JSON.stringify(message);
  if (Buffer.byteLength(serialized, 'utf8') <= limits().maxMessageBytes) ws.send(serialized);
}

function handleExtensionMessage(message: ExtensionMessage): void {
  switch (message.type) {
    case 'approve_response': {
      const pending = pendingApprovals.get(message.id);
      if (!pending) return;
      clearTimeout(pending.timer);
      pendingApprovals.delete(message.id);
      pending.resolve(message.approved);
      return;
    }
    case 'approve_drift':
      db.approveDrift(message.serverName, message.toolName, message.newHash);
      sendState();
      return;
    case 'set_category':
      db.setToolCategory(message.serverName, message.toolName, message.category);
      sendState();
      return;
    case 'update_config':
      db.updateConfig(message.config);
      syncDownstreamServers();
      return;
    case 'request_state':
      sendState();
  }
}

function sendState(): void {
  sendToExtension({
    type: 'sync_state',
    baselines: db.getBaselines(),
    logs: db.getLogs(),
    config: db.getConfig()
  });
}

function syncDownstreamServers(): void {
  const configured = db.getConfig().servers || [];
  const seen = new Set<string>();

  for (const server of configured) {
    if (!server.name || seen.has(server.name)) {
      console.error(`[MCP-Guardian-Proxy] Ignoring invalid or duplicate server name '${server.name}'`);
      continue;
    }
    seen.add(server.name);
    const current = downstreams.get(server.name);
    const signature = serverSignature(server);
    if (current && current.signature === signature) continue;
    if (current) stopDownstreamServer(server.name, 'configuration changed');
    startDownstreamServer(server);
  }

  for (const name of downstreams.keys()) {
    if (!seen.has(name)) stopDownstreamServer(name, 'removed from configuration');
  }
}

function startDownstreamServer(config: DownstreamServerConfig): void {
  const args = config.args || [];
  const command = resolveCommand(config.command);
  console.error(`[MCP-Guardian-Proxy] Starting downstream server '${config.name}' via ${command}`);

  let child: ChildProcess;
  try {
    child = spawn(command, args, {
      env: { ...process.env, ...(config.env || {}) },
      stdio: ['pipe', 'pipe', 'inherit'],
      shell: false,
      windowsHide: true
    });
  } catch (error) {
    sendToExtension({
      type: 'downstream_status',
      serverName: config.name,
      status: 'error',
      error: error instanceof Error ? error.message : 'Failed to start server'
    });
    return;
  }

  if (!child.stdout || !child.stdin) {
    child.kill();
    throw new Error(`Downstream server '${config.name}' did not expose piped stdio`);
  }

  const reader = readline.createInterface({ input: child.stdout, terminal: false });
  const runtime: DownstreamRuntime = { config, signature: serverSignature(config), process: child, reader };
  downstreams.set(config.name, runtime);

  reader.on('line', line => handleDownstreamLine(config.name, line));
  child.once('spawn', () => {
    sendToExtension({ type: 'downstream_status', serverName: config.name, status: 'connected' });
  });
  child.once('error', error => {
    console.error(`[MCP-Guardian-Proxy] Server '${config.name}' error:`, error.message);
    sendToExtension({ type: 'downstream_status', serverName: config.name, status: 'error', error: error.message });
    failPendingForServer(config.name, new Error(`Server '${config.name}' failed: ${error.message}`));
  });
  child.once('close', code => {
    if (downstreams.get(config.name)?.process === child) downstreams.delete(config.name);
    reader.close();
    failPendingForServer(config.name, new Error(`Server '${config.name}' exited with code ${code}`));
    sendToExtension({ type: 'downstream_status', serverName: config.name, status: 'disconnected' });
  });
}

function stopDownstreamServer(name: string, reason: string): void {
  const runtime = downstreams.get(name);
  if (!runtime) return;
  downstreams.delete(name);
  runtime.reader.close();
  runtime.process.kill();
  failPendingForServer(name, new Error(`Server '${name}' stopped: ${reason}`));
}

function failPendingForServer(serverName: string, error: Error): void {
  for (const [id, pending] of pendingDownstream.entries()) {
    if (pending.serverName !== serverName) continue;
    clearTimeout(pending.timer);
    pendingDownstream.delete(id);
    pending.reject(error);
  }
}

function handleDownstreamLine(serverName: string, line: string): void {
  let message: any;
  try {
    message = validateIncomingLine(line);
  } catch (error) {
    console.error(`[MCP-Guardian-Proxy] Rejected invalid output from '${serverName}':`, error);
    failPendingForServer(serverName, error instanceof Error ? error : new Error('Invalid downstream output'));
    return;
  }

  if (typeof message.id === 'string' && pendingDownstream.has(message.id)) {
    const pending = pendingDownstream.get(message.id)!;
    if (pending.serverName !== serverName) {
      console.error(`[MCP-Guardian-Proxy] Ignored response-id collision from '${serverName}'`);
      return;
    }
    clearTimeout(pending.timer);
    pendingDownstream.delete(message.id);
    pending.resolve(message);
    return;
  }

  if (message.id === undefined) writeToClient(message);
  else console.error(`[MCP-Guardian-Proxy] Ignored unknown response id from '${serverName}'`);
}

function requestDownstream(serverName: string, method: string, params: unknown): Promise<any> {
  const runtime = downstreams.get(serverName);
  if (!runtime || !runtime.process.stdin?.writable) {
    return Promise.reject(new Error(`Server '${serverName}' is not running`));
  }
  const id = nextRequestId();
  const request = { jsonrpc: '2.0', id, method, params };
  const serialized = JSON.stringify(request);
  if (Buffer.byteLength(serialized, 'utf8') > limits().maxMessageBytes) {
    return Promise.reject(new Error('Downstream request exceeded configured size limit'));
  }

  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      pendingDownstream.delete(id);
      reject(new Error(`Server '${serverName}' timed out handling '${method}'`));
    }, limits().requestTimeoutMs);
    pendingDownstream.set(id, { serverName, method, timer, resolve, reject });
    runtime.process.stdin!.write(serialized + '\n', error => {
      if (!error) return;
      clearTimeout(timer);
      pendingDownstream.delete(id);
      reject(error);
    });
  });
}

function notifyDownstreams(method: string, params?: unknown): void {
  const serialized = JSON.stringify({ jsonrpc: '2.0', method, ...(params === undefined ? {} : { params }) }) + '\n';
  for (const runtime of downstreams.values()) runtime.process.stdin?.write(serialized);
}

clientReader.on('line', line => {
  if (!line.trim()) return;
  let message: any;
  try {
    message = validateIncomingLine(line);
  } catch (error) {
    writeError(null, -32700, error instanceof Error ? error.message : 'Invalid JSON');
    return;
  }
  void handleClientRequest(message).catch(error => {
    console.error('[MCP-Guardian-Proxy] Request failed:', error);
    writeError(message.id ?? null, -32603, error instanceof Error ? error.message : 'Internal Guardian error');
  });
});

clientReader.on('close', () => void shutdown('stdin closed'));
process.once('SIGINT', () => void shutdown('SIGINT'));
process.once('SIGTERM', () => void shutdown('SIGTERM'));

async function handleClientRequest(message: any): Promise<void> {
  if (message?.jsonrpc !== '2.0') {
    writeError(message?.id ?? null, -32600, 'Invalid JSON-RPC version');
    return;
  }
  if (typeof message.method !== 'string') {
    writeError(message.id ?? null, -32600, 'JSON-RPC method must be a string');
    return;
  }

  if (message.method === 'initialize') {
    for (const name of downstreams.keys()) {
      void requestDownstream(name, 'initialize', message.params || {}).catch(error => {
        console.error(`[MCP-Guardian-Proxy] Downstream initialize failed for '${name}':`, error.message);
      });
    }
    writeToClient({
      jsonrpc: '2.0',
      id: message.id,
      result: {
        protocolVersion: '2024-11-05',
        capabilities: { tools: {}, resources: {} },
        serverInfo: { name: 'mcp-guardian-proxy', version: '1.1.0' }
      }
    });
    return;
  }

  if (message.method === 'notifications/initialized') {
    notifyDownstreams('notifications/initialized', message.params);
    return;
  }

  if (message.id === undefined) {
    notifyDownstreams(message.method, message.params);
    return;
  }

  if (message.method === 'tools/list') {
    await handleToolsList(message);
    return;
  }

  if (message.method === 'tools/call') {
    await handleToolCall(message);
    return;
  }

  const firstServer = downstreams.keys().next().value as string | undefined;
  if (!firstServer) {
    writeError(message.id ?? null, -32000, 'No downstream MCP servers available');
    return;
  }
  try {
    const response = await requestDownstream(firstServer, message.method, message.params || {});
    writeToClient({ jsonrpc: '2.0', id: message.id, ...(response.error ? { error: response.error } : { result: response.result }) });
  } catch (error) {
    writeError(message.id ?? null, -32001, error instanceof Error ? error.message : 'Downstream request failed');
  }
}

async function handleToolsList(message: any): Promise<void> {
  const serverNames = Array.from(downstreams.keys());
  if (serverNames.length === 0) {
    writeToClient({ jsonrpc: '2.0', id: message.id, result: { tools: [] } });
    return;
  }

  const results = await Promise.allSettled(
    serverNames.map(async serverName => ({
      serverName,
      response: await requestDownstream(serverName, 'tools/list', message.params || {})
    }))
  );
  const failures = results
    .filter((result): result is PromiseRejectedResult => result.status === 'rejected')
    .map(result => result.reason instanceof Error ? result.reason.message : String(result.reason));
  if (failures.length > 0) {
    writeError(message.id ?? null, -32001, 'Tool discovery was incomplete', { failures });
    return;
  }

  const aggregatedTools: any[] = [];
  for (const result of results as PromiseFulfilledResult<{ serverName: string; response: any }>[]) {
    if (result.value.response.error) {
      writeError(message.id ?? null, -32001, `Server '${result.value.serverName}' rejected tools/list`, result.value.response.error);
      return;
    }
    registerTools(result.value.serverName, result.value.response.result?.tools || [], aggregatedTools);
  }
  writeToClient({ jsonrpc: '2.0', id: message.id, result: { tools: aggregatedTools } });
}

function registerTools(serverName: string, tools: any[], output: any[]): void {
  for (const tool of tools) {
    const prefixedName = `${serverName}__${tool.name}`;
    toolsMapping.set(prefixedName, { serverName, originalName: tool.name });
    const currentHash = computeToolHash(tool);
    const baseline = db.getToolBaseline(serverName, tool.name);
    let statusText = 'SAFE';
    let isDrift = false;
    let isInjection = false;
    const reasons: string[] = [];

    if (!baseline) {
      const now = new Date().toISOString();
      db.setToolBaseline(serverName, tool.name, {
        name: tool.name,
        description: tool.description || '',
        inputSchema: tool.inputSchema || {},
        hash: currentHash,
        category: autoAssignCategory(tool.name, tool.description),
        approved: true,
        firstSeen: now,
        lastSeen: now
      });
    } else {
      if (baseline.hash !== currentHash) {
        isDrift = true;
        statusText = 'DRIFT';
        reasons.push('Metadata hash changed from the approved baseline');
      }
      baseline.lastSeen = new Date().toISOString();
      db.setToolBaseline(serverName, tool.name, baseline);
    }

    const heuristic = scanHeuristics(tool.description || '');
    if (heuristic.suspicious) {
      isInjection = true;
      statusText = 'INJECTION';
      reasons.push(heuristic.reason || 'Heuristic prompt injection detected');
    }

    output.push({ ...tool, name: prefixedName, description: `[MCP-Guardian: ${statusText}] ${tool.description || ''}` });
    if (isDrift || isInjection) {
      const auditLog: AuditLog = {
        id: crypto.randomUUID(),
        timestamp: new Date().toISOString(),
        serverName,
        toolName: tool.name,
        category: baseline?.category || 'GENERAL',
        arguments: {},
        status: 'block',
        reason: reasons.join('; '),
        drift: isDrift || undefined,
        promptInjection: isInjection || undefined
      };
      persistLog(auditLog);
    }
  }
}

async function handleToolCall(message: any): Promise<void> {
  const prefixedName = message.params?.name;
  if (typeof prefixedName !== 'string') {
    writeError(message.id ?? null, -32602, 'tools/call requires a tool name');
    return;
  }
  const mapping = toolsMapping.get(prefixedName);
  if (!mapping) {
    writeError(message.id ?? null, -32601, `Tool '${prefixedName}' was not discovered`);
    return;
  }

  const args = message.params?.arguments || {};
  const sessionId = extractSessionId(message.params?._meta);
  const session = sessionState(sessionId);
  const baseline = db.getToolBaseline(mapping.serverName, mapping.originalName);
  const category = baseline?.category || 'GENERAL';
  const reasons: string[] = [];
  let isDrift = false;
  let isInjection = false;
  let isViolation = false;

  if (baseline && !baseline.approved) {
    isDrift = true;
    reasons.push('Tool contains metadata drift since baseline approval');
  }
  const heuristic = scanHeuristics(JSON.stringify(args));
  if (heuristic.suspicious) {
    isInjection = true;
    reasons.push(`Prompt-injection pattern in arguments: ${heuristic.reason}`);
  }
  const previousCategory = session.categories.at(-1);
  if (checkTransition(previousCategory, category, db.getConfig().forbiddenTransitions)) {
    isViolation = true;
    reasons.push(`Forbidden transition: ${previousCategory} -> ${category}`);
  }
  session.categories.push(category);
  session.lastCallTime = Date.now();

  const auditLog: AuditLog = {
    id: crypto.randomUUID(),
    timestamp: new Date().toISOString(),
    serverName: mapping.serverName,
    toolName: mapping.originalName,
    category,
    arguments: args,
    status: reasons.length > 0 ? 'pending' : 'allow',
    reason: reasons.join('; ') || undefined,
    drift: isDrift || undefined,
    promptInjection: isInjection || undefined,
    isCategoryTransitionViolation: isViolation || undefined,
    sessionId
  };

  if (reasons.length === 0 && db.getConfig().geminiApiKey && baseline) {
    const semantic = await scanSemantic(mapping.originalName, baseline.description, db.getConfig().geminiApiKey!);
    if (semantic.suspicious) {
      isInjection = true;
      reasons.push(`Semantic scan flagged description: ${semantic.reason}`);
      auditLog.status = 'pending';
      auditLog.reason = reasons.join('; ');
      auditLog.promptInjection = true;
    }
  }

  if (reasons.length === 0 && db.getConfig().autoApproveSafe) {
    persistLog(auditLog);
    await forwardToolCall(message.id, mapping.serverName, mapping.originalName, args);
    return;
  }

  persistLog(auditLog);
  if (!wsConnected) {
    auditLog.status = 'block';
    auditLog.reason = 'Blocked: approval interface is offline';
    persistLog(auditLog);
    writeError(message.id ?? null, -32603, 'Execution blocked because approval interface is offline');
    return;
  }

  sendToExtension({
    type: 'approve_request',
    id: auditLog.id,
    serverName: mapping.serverName,
    toolName: mapping.originalName,
    arguments: args,
    reason: auditLog.reason || 'Manual confirmation required',
    driftDetails: isDrift && baseline ? { oldHash: baseline.hash, newHash: baseline.hash } : undefined
  });

  const approved = await waitForApproval(auditLog);
  if (!approved) {
    auditLog.status = 'block';
    if (auditLog.reason?.includes('approval interface')) {
      // Preserve the offline reason.
    } else if (auditLog.reason?.includes('timed out')) {
      // Preserve the timeout reason.
    } else {
      auditLog.reason = 'Blocked by user';
    }
    persistLog(auditLog);
    writeError(message.id ?? null, -32603, auditLog.reason);
    return;
  }

  auditLog.status = 'allow';
  auditLog.reason = `${auditLog.reason || 'Manual confirmation required'}; approved once by user`;
  persistLog(auditLog);
  await forwardToolCall(message.id, mapping.serverName, mapping.originalName, args);
}

function extractSessionId(meta: unknown): string {
  if (!meta || typeof meta !== 'object') return 'default';
  const guardian = (meta as Record<string, unknown>).guardian;
  if (!guardian || typeof guardian !== 'object') return 'default';
  const sessionId = (guardian as Record<string, unknown>).sessionId;
  return typeof sessionId === 'string' && sessionId.trim() ? sessionId : 'default';
}

function sessionState(sessionId: string): SessionState {
  const now = Date.now();
  const existing = sessions.get(sessionId);
  if (!existing || now - existing.lastCallTime > SESSION_TIMEOUT_MS) {
    const created = { categories: [], lastCallTime: now };
    sessions.set(sessionId, created);
    return created;
  }
  return existing;
}

function waitForApproval(log: AuditLog): Promise<boolean> {
  return new Promise(resolve => {
    const timer = setTimeout(() => {
      pendingApprovals.delete(log.id);
      log.status = 'block';
      log.reason = 'Blocked: approval request timed out';
      persistLog(log);
      resolve(false);
    }, limits().approvalTimeoutMs);
    pendingApprovals.set(log.id, { timer, resolve, log });
  });
}

async function forwardToolCall(clientId: JsonRpcId, serverName: string, toolName: string, args: unknown): Promise<void> {
  try {
    const response = await requestDownstream(serverName, 'tools/call', { name: toolName, arguments: args });
    writeToClient({ jsonrpc: '2.0', id: clientId, ...(response.error ? { error: response.error } : { result: response.result }) });
  } catch (error) {
    writeError(clientId, -32001, error instanceof Error ? error.message : 'Downstream tool call failed');
  }
}

function persistLog(log: AuditLog): void {
  db.addLog(log);
  sendToExtension({ type: 'log', log });
}

async function shutdown(reason: string): Promise<void> {
  if (shuttingDown) return;
  shuttingDown = true;
  console.error(`[MCP-Guardian-Proxy] Shutting down: ${reason}`);
  if (wsReconnectTimer) clearTimeout(wsReconnectTimer);
  ws?.close();
  ws = null;
  wsConnected = false;

  for (const pending of pendingApprovals.values()) {
    clearTimeout(pending.timer);
    pending.log.status = 'block';
    pending.log.reason = 'Blocked: Guardian shut down before approval';
    db.addLog(pending.log);
    pending.resolve(false);
  }
  pendingApprovals.clear();

  for (const pending of pendingDownstream.values()) {
    clearTimeout(pending.timer);
    pending.reject(new Error('Guardian shut down'));
  }
  pendingDownstream.clear();

  for (const name of Array.from(downstreams.keys())) stopDownstreamServer(name, reason);
}

connectToExtension();
syncDownstreamServers();
console.error('[MCP-Guardian-Proxy] Standalone proxy active on stdin/stdout.');
