import * as crypto from 'crypto';
import * as os from 'os';
import * as path from 'path';
import * as readline from 'readline';
import { ChildProcess, spawn } from 'child_process';
import WebSocket from 'ws';
import { GuardianDb } from './db';
import {
  autoAssignCategory,
  checkTransition
} from './detector';
import { DataLabel, Evidence, InspectionSummary } from './core/types';
import { scanSemanticSandboxed } from './semantic-sandbox';
import { AcceptedRiskStore } from './security/accepted-risks';
import {
  coarseTaint,
  createDataFlowState,
  matchInput,
  recordOutput,
  SessionDataFlowState
} from './security/data-flow';
import { inspectOnboarding, shadowingEvidence } from './security/onboarding';
import { inspectStructuredText } from './security/text-inspection';
import { diffToolDefinitions, fingerprintTool, snapshotTool } from './security/tool-integrity';
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
  dataFlow: SessionDataFlowState;
}

const DEFAULT_LIMITS: ResourceLimits = {
  maxMessageBytes: 1_048_576,
  maxNestingDepth: 64,
  requestTimeoutMs: Number(process.env.MCP_GUARDIAN_REQUEST_TIMEOUT_MS) || 10_000,
  approvalTimeoutMs: Number(process.env.MCP_GUARDIAN_APPROVAL_TIMEOUT_MS) || 20_000,
  maxScanStrings: 2_000,
  maxDiffEntries: 100
};
const SESSION_TIMEOUT_MS = 2 * 60 * 1000;
const STORAGE_PATH = process.env.MCP_GUARDIAN_STORAGE_PATH || path.join(os.homedir(), '.mcp-guardian');
const WS_DISABLED = process.env.MCP_GUARDIAN_WS_DISABLED === '1';
const WS_PORT = Number(process.env.MCP_GUARDIAN_WS_PORT) || 1337;

const db = new GuardianDb(STORAGE_PATH);
const acceptedRisks = new AcceptedRiskStore(STORAGE_PATH);
const downstreams = new Map<string, DownstreamRuntime>();
const pendingDownstream = new Map<string, PendingDownstreamRequest>();
const pendingApprovals = new Map<string, PendingApproval>();
const sessions = new Map<string, SessionState>();
const toolsMapping = new Map<string, { serverName: string; originalName: string }>();
const toolOwners = new Map<string, Set<string>>();

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
    if (!response.error && (message.method.startsWith('resources/') || message.method.startsWith('prompts/'))) {
      const eventId = `${message.method}:${crypto.randomUUID()}`;
      const inspection = inspectStructuredText(
        response.result,
        `mcp.${message.method.replace('/', '.')}`,
        eventId,
        limits().maxScanStrings
      );
      const evidence = inspection.evidence.filter(finding => !acceptedRisks.isAccepted(finding));
      if (inspection.truncated || evidence.some(finding => finding.severity === 'high' || finding.severity === 'critical')) {
        writeError(message.id ?? null, -32603, 'MCP content blocked by Agent Guardian', {
          method: message.method,
          incomplete: inspection.truncated,
          evidence: evidence.map(finding => ({ id: finding.id, message: finding.message, severity: finding.severity }))
        });
        return;
      }
    }
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
  toolOwners.clear();
  for (const result of results as PromiseFulfilledResult<{ serverName: string; response: any }>[]) {
    if (result.value.response.error) {
      writeError(message.id ?? null, -32001, `Server '${result.value.serverName}' rejected tools/list`, result.value.response.error);
      return;
    }
    registerTools(result.value.serverName, result.value.response.result?.tools || [], aggregatedTools);
  }
  applyShadowingRules();
  writeToClient({ jsonrpc: '2.0', id: message.id, result: { tools: aggregatedTools } });
}

function registerTools(serverName: string, tools: any[], output: any[]): void {
  const serverConfig = downstreams.get(serverName)?.config;
  if (!serverConfig) return;
  for (const tool of tools) {
    const prefixedName = `${serverName}__${tool.name}`;
    toolsMapping.set(prefixedName, { serverName, originalName: tool.name });
    if (!toolOwners.has(tool.name)) toolOwners.set(tool.name, new Set());
    toolOwners.get(tool.name)!.add(serverName);
    const eventId = `discovery:${serverName}:${tool.name}:${crypto.randomUUID()}`;
    const observedDefinition = snapshotTool(tool);
    const currentHash = fingerprintTool(observedDefinition);
    const baseline = db.getToolBaseline(serverName, tool.name);
    const onboarding = inspectOnboarding(
      serverConfig,
      observedDefinition,
      eventId,
      acceptedRisks,
      limits().maxScanStrings
    );
    let statusText = 'SAFE';
    let isDrift = false;
    const reasons: string[] = [];

    if (!baseline) {
      const now = new Date().toISOString();
      const firstSeenPolicy = db.getConfig().firstSeenPolicy || 'approve-safe';
      const approved = onboarding.safe && firstSeenPolicy === 'approve-safe';
      const status = !onboarding.safe || firstSeenPolicy === 'block'
        ? 'rejected'
        : approved
          ? 'approved'
          : 'pending';
      db.setToolBaseline(serverName, tool.name, {
        name: tool.name,
        description: tool.description || '',
        inputSchema: tool.inputSchema || {},
        hash: currentHash,
        category: autoAssignCategory(tool.name, tool.description),
        approved,
        firstSeen: now,
        lastSeen: now,
        status,
        trustedDefinition: observedDefinition,
        observedDefinition,
        observedHash: currentHash,
        differences: [],
        inspection: onboarding.inspection,
        evidence: onboarding.evidence
      });
      if (!approved) {
        statusText = status === 'rejected' ? 'REJECTED' : 'PENDING';
        reasons.push(status === 'rejected'
          ? 'Onboarding scan rejected the first-seen tool definition'
          : 'First-seen tool requires explicit approval');
      }
    } else {
      const trustedDefinition = baseline.trustedDefinition || snapshotTool(baseline);
      if (baseline.hash !== currentHash) {
        isDrift = true;
        statusText = 'DRIFT';
        reasons.push('Metadata hash changed from the approved baseline');
        const diff = diffToolDefinitions(trustedDefinition, observedDefinition, limits().maxDiffEntries);
        baseline.approved = false;
        baseline.status = 'drifted';
        baseline.differences = diff.differences;
        if (diff.truncated) reasons.push('Schema diff was truncated at the configured limit');
      } else if (!onboarding.safe) {
        baseline.approved = false;
        baseline.status = 'rejected';
        statusText = 'REJECTED';
        reasons.push('Security scan rejected the observed tool definition');
      }
      baseline.trustedDefinition = trustedDefinition;
      baseline.observedDefinition = observedDefinition;
      baseline.observedHash = currentHash;
      baseline.inspection = onboarding.inspection;
      baseline.evidence = onboarding.evidence;
      baseline.lastSeen = new Date().toISOString();
      db.setToolBaseline(serverName, tool.name, baseline);
    }

    for (const finding of onboarding.evidence) reasons.push(finding.message);

    output.push({ ...tool, name: prefixedName, description: `[MCP-Guardian: ${statusText}] ${tool.description || ''}` });
    const stored = db.getToolBaseline(serverName, tool.name);
    if (isDrift || onboarding.evidence.length > 0 || !stored?.approved) {
      const auditLog: AuditLog = {
        id: crypto.randomUUID(),
        timestamp: new Date().toISOString(),
        serverName,
        toolName: tool.name,
        category: baseline?.category || 'GENERAL',
        arguments: {},
        status: 'block',
        reason: uniqueReasons(reasons).join('; '),
        drift: isDrift || undefined,
        promptInjection: onboarding.evidence.length > 0 || undefined,
        evidence: onboarding.evidence,
        inspection: onboarding.inspection
      };
      persistLog(auditLog);
    }
  }
}

function applyShadowingRules(): void {
  for (const [toolName, owners] of toolOwners.entries()) {
    if (owners.size < 2) continue;
    const serverNames = Array.from(owners);
    const finding = shadowingEvidence(toolName, serverNames, `shadow:${toolName}`);
    if (acceptedRisks.isAccepted(finding)) continue;
    for (const serverName of serverNames) {
      const baseline = db.getToolBaseline(serverName, toolName);
      if (!baseline) continue;
      baseline.approved = false;
      baseline.status = 'pending';
      baseline.evidence = deduplicateEvidence([...(baseline.evidence || []), finding]);
      db.setToolBaseline(serverName, toolName, baseline);
      persistLog({
        id: crypto.randomUUID(),
        timestamp: new Date().toISOString(),
        serverName,
        toolName,
        category: baseline.category,
        arguments: {},
        status: 'block',
        reason: finding.message,
        evidence: [finding]
      });
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
  const callEventId = `call:${sessionId}:${crypto.randomUUID()}`;
  const reasons: string[] = [];
  const evidence: Evidence[] = [];
  let isDrift = false;
  let isInjection = false;
  let isViolation = false;
  let hardBlock = false;

  if (!baseline) {
    hardBlock = true;
    reasons.push('Tool has no onboarding baseline');
    evidence.push(makeEvidence('mcp.integrity', 'R2', 'critical', 'Tool has no onboarding baseline', callEventId));
  } else if (!baseline.approved) {
    const status = baseline.status || 'pending';
    isDrift = status === 'drifted';
    hardBlock = status === 'drifted' || status === 'rejected';
    const reason = status === 'drifted'
      ? 'Tool definition drifted and must be explicitly re-baselined'
      : status === 'rejected'
        ? 'Tool definition failed onboarding security checks'
        : 'Tool is unknown or shadowed and requires explicit approval';
    reasons.push(reason);
    evidence.push(...(baseline.evidence || []));
    evidence.push(makeEvidence('mcp.integrity', status === 'drifted' ? 'R1' : 'R2', hardBlock ? 'critical' : 'high', reason, callEventId, {
      status,
      observedHash: baseline.observedHash,
      trustedHash: baseline.hash
    }));
  }
  const argumentInspection = inspectStructuredText(
    args,
    'mcp.arguments',
    callEventId,
    limits().maxScanStrings
  );
  const argumentEvidence = argumentInspection.evidence.filter(finding => !acceptedRisks.isAccepted(finding));
  if (argumentEvidence.length > 0) {
    isInjection = true;
    evidence.push(...argumentEvidence);
    reasons.push(...argumentEvidence.map(finding => finding.message));
  }
  if (argumentInspection.truncated) {
    hardBlock = true;
    reasons.push('Argument inspection was incomplete because the string limit was reached');
  }
  const previousCategory = session.categories.at(-1);
  if (checkTransition(previousCategory, category, db.getConfig().forbiddenTransitions)) {
    isViolation = true;
    const reason = `Forbidden transition: ${previousCategory} -> ${category}`;
    reasons.push(reason);
    evidence.push(makeEvidence('mcp.behavior', undefined, 'high', reason, callEventId));
  }

  const flowMatch = matchInput(session.dataFlow, args);
  const outbound = category === 'WRITE_COMMUNICATION' || category === 'EXECUTE_SYSTEM';
  const coarseLabels = outbound ? coarseTaint(session.dataFlow) : [];
  const flowLabels = new Set<DataLabel>([...flowMatch.labels, ...coarseLabels]);
  if (outbound && flowLabels.has('credential')) {
    hardBlock = true;
    const reason = `Credential-labelled session data is flowing to ${category}`;
    reasons.push(reason);
    evidence.push(makeEvidence('mcp.data-flow', 'R5', 'critical', reason, callEventId, {
      dataLabel: 'credential',
      match: flowMatch.exact ? 'exact-fingerprint' : 'coarse-session-taint'
    }));
  } else if (outbound && (flowLabels.has('sensitive') || flowLabels.has('personal') || flowLabels.has('financial'))) {
    const reason = `Sensitive session data may be flowing to ${category}`;
    reasons.push(reason);
    evidence.push(makeEvidence('mcp.data-flow', 'R4', 'high', reason, callEventId, {
      dataLabel: flowLabels.has('financial') ? 'financial' : flowLabels.has('personal') ? 'personal' : 'sensitive',
      match: flowMatch.exact ? 'exact-fingerprint' : 'coarse-session-taint'
    }));
  }
  session.categories.push(category);
  session.lastCallTime = Date.now();

  if (evidence.some(finding => finding.ruleId === 'R9') && reasons.length > 1) hardBlock = true;

  const inspection: InspectionSummary = inspectionSummary(
    argumentInspection.stringsInspected,
    argumentInspection.truncated,
    argumentInspection.truncated ? 'Argument string limit reached' : undefined
  );

  const auditLog: AuditLog = {
    id: crypto.randomUUID(),
    timestamp: new Date().toISOString(),
    serverName: mapping.serverName,
    toolName: mapping.originalName,
    category,
    arguments: args,
    status: reasons.length > 0 ? 'pending' : 'allow',
    reason: uniqueReasons(reasons).join('; ') || undefined,
    drift: isDrift || undefined,
    promptInjection: isInjection || undefined,
    isCategoryTransitionViolation: isViolation || undefined,
    sessionId,
    evidence: deduplicateEvidence(evidence),
    dataLabels: Array.from(flowLabels),
    inspection
  };

  if (!hardBlock && db.getConfig().geminiApiKey && baseline) {
    const semantic = await scanSemanticSandboxed(
      mapping.originalName,
      JSON.stringify({ definition: baseline.observedDefinition || baseline.trustedDefinition, arguments: args }),
      db.getConfig().geminiApiKey!,
      Math.min(limits().requestTimeoutMs, 4_000)
    );
    if (semantic.suspicious) {
      isInjection = true;
      reasons.push(`Semantic scan flagged description: ${semantic.reason}`);
      evidence.push(makeEvidence('mcp.semantic-sandbox', undefined, 'high', semantic.reason || 'Semantic scan flagged content', callEventId));
    } else if (!semantic.complete) {
      reasons.push(semantic.reason || 'Semantic inspection was incomplete');
    }
    auditLog.status = reasons.length > 0 ? 'pending' : 'allow';
    auditLog.reason = uniqueReasons(reasons).join('; ') || undefined;
    auditLog.evidence = deduplicateEvidence(evidence);
    auditLog.promptInjection = isInjection || undefined;
    auditLog.inspection = {
      ...inspection,
      complete: inspection.complete && semantic.complete,
      partial: inspection.partial + (semantic.complete ? 0 : 1),
      total: inspection.total + 1,
      completed: inspection.completed + (semantic.complete ? 1 : 0),
      reasons: semantic.complete ? inspection.reasons : [...inspection.reasons, semantic.reason || 'Semantic inspection incomplete']
    };
  }

  if (hardBlock) {
    auditLog.status = 'block';
    auditLog.reason = uniqueReasons(reasons).join('; ');
    auditLog.evidence = deduplicateEvidence(evidence);
    persistLog(auditLog);
    writeError(message.id ?? null, -32603, auditLog.reason || 'Execution blocked by Guardian policy');
    return;
  }

  if (reasons.length === 0 && db.getConfig().autoApproveSafe) {
    persistLog(auditLog);
    await forwardToolCall(message.id, mapping.serverName, mapping.originalName, args, auditLog, session, category);
    return;
  }

  auditLog.status = 'pending';
  auditLog.reason = uniqueReasons(reasons).join('; ') || 'Manual confirmation required';
  auditLog.evidence = deduplicateEvidence(evidence);
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
    reason: auditLog.reason,
    driftDetails: isDrift && baseline ? { oldHash: baseline.hash, newHash: baseline.observedHash || baseline.hash } : undefined
  });

  const approved = await waitForApproval(auditLog);
  if (!approved) {
    auditLog.status = 'block';
    if (!auditLog.reason?.includes('timed out')) auditLog.reason = 'Blocked by user';
    persistLog(auditLog);
    writeError(message.id ?? null, -32603, auditLog.reason);
    return;
  }

  auditLog.status = 'allow';
  auditLog.reason = `${auditLog.reason}; approved once by user`;
  persistLog(auditLog);
  await forwardToolCall(message.id, mapping.serverName, mapping.originalName, args, auditLog, session, category);
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
    const created = { categories: [], lastCallTime: now, dataFlow: createDataFlowState() };
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

async function forwardToolCall(
  clientId: JsonRpcId,
  serverName: string,
  toolName: string,
  args: unknown,
  auditLog: AuditLog,
  session: SessionState,
  category: string
): Promise<void> {
  try {
    const response = await requestDownstream(serverName, 'tools/call', { name: toolName, arguments: args });
    if (response.error) {
      writeToClient({ jsonrpc: '2.0', id: clientId, error: response.error });
      return;
    }

    const outputEventId = `result:${auditLog.sessionId || 'default'}:${crypto.randomUUID()}`;
    const outputInspection = inspectStructuredText(
      response.result,
      'mcp.tool-result',
      outputEventId,
      limits().maxScanStrings
    );
    const outputEvidence = outputInspection.evidence.filter(finding => !acceptedRisks.isAccepted(finding));
    const inheritedLabels: DataLabel[] = category === 'READ_NETWORK' ? ['untrusted'] : [];
    const dataLabels = recordOutput(session.dataFlow, response.result, inheritedLabels);
    auditLog.dataLabels = Array.from(new Set([...(auditLog.dataLabels || []), ...dataLabels]));
    auditLog.evidence = deduplicateEvidence([...(auditLog.evidence || []), ...outputEvidence]);
    auditLog.inspection = mergeInspection(
      auditLog.inspection,
      inspectionSummary(
        outputInspection.stringsInspected,
        outputInspection.truncated,
        outputInspection.truncated ? 'Tool-result string limit reached' : undefined
      )
    );

    let semanticIncomplete = false;
    if (db.getConfig().geminiApiKey) {
      const semantic = await scanSemanticSandboxed(
        toolName,
        JSON.stringify(response.result),
        db.getConfig().geminiApiKey!,
        Math.min(limits().requestTimeoutMs, 4_000)
      );
      if (semantic.suspicious) {
        outputEvidence.push(makeEvidence(
          'mcp.semantic-sandbox',
          undefined,
          'high',
          semantic.reason || 'Semantic scan flagged tool output',
          outputEventId
        ));
      }
      semanticIncomplete = !semantic.complete;
      if (semanticIncomplete) {
        auditLog.inspection.complete = false;
        auditLog.inspection.partial += 1;
        auditLog.inspection.total += 1;
        auditLog.inspection.reasons.push(semantic.reason || 'Semantic output inspection incomplete');
      }
    }

    const dangerousOutput = outputInspection.truncated || outputEvidence.some(finding =>
      finding.severity === 'high' || finding.severity === 'critical'
    );
    if (dangerousOutput) {
      auditLog.status = 'block';
      auditLog.promptInjection = outputEvidence.length > 0 || undefined;
      auditLog.evidence = deduplicateEvidence([...(auditLog.evidence || []), ...outputEvidence]);
      auditLog.reason = uniqueReasons([
        auditLog.reason || '',
        ...outputEvidence.map(finding => finding.message),
        outputInspection.truncated ? 'Tool output inspection was incomplete' : ''
      ]).join('; ');
      persistLog(auditLog);
      writeError(clientId, -32603, 'Tool output blocked by Agent Guardian', {
        reason: auditLog.reason,
        evidenceIds: outputEvidence.map(finding => finding.id)
      });
      return;
    }

    if (semanticIncomplete) {
      auditLog.reason = uniqueReasons([auditLog.reason || '', 'Semantic output inspection incomplete']).join('; ');
    }
    persistLog(auditLog);
    writeToClient({ jsonrpc: '2.0', id: clientId, result: response.result });
  } catch (error) {
    writeError(clientId, -32001, error instanceof Error ? error.message : 'Downstream tool call failed');
  }
}

function inspectionSummary(stringsInspected: number, truncated: boolean, reason?: string): InspectionSummary {
  return {
    complete: !truncated,
    total: 1,
    completed: truncated ? 0 : 1,
    partial: truncated ? 1 : 0,
    skipped: 0,
    failed: 0,
    outOfScope: 0,
    reasons: reason ? [reason] : []
  };
}

function mergeInspection(
  first: InspectionSummary | undefined,
  second: InspectionSummary
): InspectionSummary {
  if (!first) return second;
  return {
    complete: first.complete && second.complete,
    total: first.total + second.total,
    completed: first.completed + second.completed,
    partial: first.partial + second.partial,
    skipped: first.skipped + second.skipped,
    failed: first.failed + second.failed,
    outOfScope: first.outOfScope + second.outOfScope,
    reasons: uniqueReasons([...first.reasons, ...second.reasons])
  };
}

function makeEvidence(
  detectorId: string,
  ruleId: string | undefined,
  severity: Evidence['severity'],
  message: string,
  eventId: string,
  metadata?: Record<string, unknown>
): Evidence {
  return {
    id: crypto.createHash('sha256').update(`${detectorId}\0${ruleId || ''}\0${eventId}\0${message}`).digest('hex'),
    detectorId,
    detectorVersion: '1.0.0',
    ruleId,
    severity,
    confidence: 1,
    message,
    eventIds: [eventId],
    provenance: { lane: 'mcp' },
    metadata
  };
}

function deduplicateEvidence(evidence: Evidence[]): Evidence[] {
  return Array.from(new Map(evidence.map(finding => [finding.id, finding])).values());
}

function uniqueReasons(reasons: string[]): string[] {
  return Array.from(new Set(reasons.map(reason => reason.trim()).filter(Boolean)));
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
