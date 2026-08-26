import * as readline from 'readline';
import { spawn, ChildProcess } from 'child_process';
import * as path from 'path';
import * as os from 'os';
import WebSocket from 'ws';
import { GuardianDb } from './db';
import {
  computeToolHash,
  scanHeuristics,
  scanSemantic,
  checkTransition,
  autoAssignCategory
} from './detector';
import { DownstreamServerConfig, AuditLog, ToolBaseline, ExtensionMessage, ProxyMessage } from './types';

// Use home directory for database sharing between extension and proxy
const STORAGE_PATH = path.join(os.homedir(), '.mcp-guardian');
const db = new GuardianDb(STORAGE_PATH);

// Process state
const downstreamProcesses: Record<string, ChildProcess> = {};
const pendingApprovals: Record<string, {
  resolve: (value: boolean) => void;
  reject: (reason?: any) => void;
  log: AuditLog;
}> = {};

let ws: WebSocket | null = null;
let wsConnected = false;
let wsPort = 1337;

// Call Graph state (rolling session list of categories)
let sessionCallGraph: string[] = [];
let lastCallTime = Date.now();
const SESSION_TIMEOUT = 2 * 60 * 1000; // 2 minutes session idle time

// Tools mappings: prefixedName -> { serverName, originalName }
const toolsMapping: Record<string, { serverName: string; originalName: string }> = {};

// Start WebSocket connection to VS Code Extension
function connectToExtension() {
  ws = new WebSocket(`ws://localhost:${wsPort}`);

  ws.on('open', () => {
    wsConnected = true;
    console.error(`[MCP-Guardian-Proxy] Connected to VS Code extension on port ${wsPort}`);
    // Sync state
    sendToExtension({
      type: 'sync_state',
      baselines: db.getBaselines(),
      logs: db.getLogs(),
      config: db.getConfig()
    });
  });

  ws.on('message', (data) => {
    try {
      const msg: ExtensionMessage = JSON.parse(data.toString());
      handleExtensionMessage(msg);
    } catch (e) {
      console.error('[MCP-Guardian-Proxy] Failed to parse WebSocket message:', e);
    }
  });

  ws.on('close', () => {
    wsConnected = false;
    ws = null;
    // Attempt reconnect after 3 seconds
    setTimeout(connectToExtension, 3000);
  });

  ws.on('error', () => {
    wsConnected = false;
    ws = null;
  });
}

function sendToExtension(msg: ProxyMessage) {
  if (ws && wsConnected) {
    ws.send(JSON.stringify(msg));
  }
}

function handleExtensionMessage(msg: ExtensionMessage) {
  switch (msg.type) {
    case 'approve_response': {
      const pending = pendingApprovals[msg.id];
      if (pending) {
        pending.resolve(msg.approved);
        delete pendingApprovals[msg.id];
      }
      break;
    }
    case 'approve_drift': {
      db.approveDrift(msg.serverName, msg.toolName, msg.newHash);
      sendToExtension({
        type: 'sync_state',
        baselines: db.getBaselines(),
        logs: db.getLogs(),
        config: db.getConfig()
      });
      break;
    }
    case 'set_category': {
      db.setToolCategory(msg.serverName, msg.toolName, msg.category);
      sendToExtension({
        type: 'sync_state',
        baselines: db.getBaselines(),
        logs: db.getLogs(),
        config: db.getConfig()
      });
      break;
    }
    case 'update_config': {
      db.updateConfig(msg.config);
      // Restart changed servers or align config
      syncDownstreamServers();
      break;
    }
    case 'request_state': {
      sendToExtension({
        type: 'sync_state',
        baselines: db.getBaselines(),
        logs: db.getLogs(),
        config: db.getConfig()
      });
      break;
    }
  }
}

// Downstream processes manager
function syncDownstreamServers() {
  const config = db.getConfig();
  const currentServers = config.servers;

  // Stop servers no longer in config
  for (const name of Object.keys(downstreamProcesses)) {
    if (!currentServers.some(s => s.name === name)) {
      console.error(`[MCP-Guardian-Proxy] Stopping downstream server: ${name}`);
      downstreamProcesses[name].kill();
      delete downstreamProcesses[name];
      sendToExtension({ type: 'downstream_status', serverName: name, status: 'disconnected' });
    }
  }

  // Start/Restart servers
  for (const server of currentServers) {
    if (!downstreamProcesses[server.name]) {
      startDownstreamServer(server);
    }
  }
}

function startDownstreamServer(server: DownstreamServerConfig) {
  console.error(`[MCP-Guardian-Proxy] Starting downstream server: ${server.name} via ${server.command} ${server.args.join(' ')}`);
  
  sendToExtension({ type: 'downstream_status', serverName: server.name, status: 'connected' });

  // Spawn downstream server with standard I/O piped
  const childEnv = { ...process.env, ...(server.env || {}) };
  const child = spawn(server.command, server.args, {
    env: childEnv,
    stdio: ['pipe', 'pipe', 'inherit'],
    shell: true
  });

  downstreamProcesses[server.name] = child;

  const rl = readline.createInterface({
    input: child.stdout,
    terminal: false
  });

  rl.on('line', (line) => {
    if (!line.trim()) return;
    try {
      const msg = JSON.parse(line);
      handleDownstreamResponse(server.name, msg);
    } catch (e) {
      console.error(`[MCP-Guardian-Proxy] Error parsing message from ${server.name}:`, line, e);
    }
  });

  child.on('close', (code) => {
    console.error(`[MCP-Guardian-Proxy] Server ${server.name} exited with code ${code}`);
    delete downstreamProcesses[server.name];
    sendToExtension({ type: 'downstream_status', serverName: server.name, status: 'disconnected' });
  });

  child.on('error', (err) => {
    console.error(`[MCP-Guardian-Proxy] Server ${server.name} error:`, err);
    sendToExtension({ type: 'downstream_status', serverName: server.name, status: 'error', error: err.message });
  });
}

// Client Standard I/O (JSON-RPC listener)
const clientRl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
  terminal: false
});

clientRl.on('line', (line) => {
  if (!line.trim()) return;
  try {
    const msg = JSON.parse(line);
    handleClientRequest(msg);
  } catch (e) {
    console.error('[MCP-Guardian-Proxy] Error parsing client request:', line, e);
  }
});

function writeToClient(msg: any) {
  process.stdout.write(JSON.stringify(msg) + '\n');
}

// Core JSON-RPC Routing Logic
async function handleClientRequest(msg: any) {
  if (msg.jsonrpc !== '2.0') {
    writeToClient({ jsonrpc: '2.0', id: msg.id || null, error: { code: -32600, message: 'Invalid JSON-RPC version' } });
    return;
  }

  // Handle client request
  if (msg.method === 'initialize') {
    // Reply immediately to initialize client, but initialize downstreams too
    const clientCapabilities = msg.params.capabilities || {};
    
    // Send initialize downstream
    for (const [name, proc] of Object.entries(downstreamProcesses)) {
      proc.stdin?.write(JSON.stringify({
        jsonrpc: '2.0',
        id: `init:${name}:${msg.id}`,
        method: 'initialize',
        params: msg.params
      }) + '\n');
    }

    // Proxy responds to the client
    writeToClient({
      jsonrpc: '2.0',
      id: msg.id,
      result: {
        protocolVersion: '2024-11-05',
        capabilities: {
          tools: {},
          resources: {}
        },
        serverInfo: {
          name: 'mcp-guardian-proxy',
          version: '1.0.0'
        }
      }
    });

    // Send initialized notification downstream
    setTimeout(() => {
      for (const proc of Object.values(downstreamProcesses)) {
        proc.stdin?.write(JSON.stringify({
          jsonrpc: '2.0',
          method: 'notifications/initialized'
        }) + '\n');
      }
    }, 1000);

    return;
  }

  if (msg.method === 'tools/list') {
    // We aggregate tools across all servers
    // Wait for all servers to return tools
    const servers = Object.keys(downstreamProcesses);
    if (servers.length === 0) {
      writeToClient({ jsonrpc: '2.0', id: msg.id, result: { tools: [] } });
      return;
    }

    // Keep track of aggregation context
    const aggregatedTools: any[] = [];
    let pendingResponsesCount = servers.length;

    // We override client request routing
    const aggregatorId = `tools:${msg.id}`;
    
    // Set up a listener for downstream responses
    const handleAggregatedResponse = (serverName: string, resultTools: any[]) => {
      for (const t of resultTools) {
        const prefixedName = `${serverName}__${t.name}`;
        toolsMapping[prefixedName] = { serverName, originalName: t.name };
        
        // Run security Layer 1 & Layer 2 checks
        const currentHash = computeToolHash(t);
        const baseline = db.getToolBaseline(serverName, t.name);

        let statusText = 'SAFE';
        let isDrift = false;
        let isInjection = false;
        let scanReason = '';

        if (!baseline) {
          // New tool, store it
          const category = autoAssignCategory(t.name, t.description);
          db.setToolBaseline(serverName, t.name, {
            name: t.name,
            description: t.description || '',
            inputSchema: t.inputSchema || {},
            hash: currentHash,
            category: category,
            approved: true,
            firstSeen: new Date().toISOString(),
            lastSeen: new Date().toISOString()
          });
        } else {
          // Compare hash (Drift detector - Layer 1)
          if (baseline.hash !== currentHash) {
            isDrift = true;
            statusText = 'DRIFT';
            scanReason = `Metadata hash changed from baseline! (Rug Pull detected)`;
          }
          baseline.lastSeen = new Date().toISOString();
          db.setToolBaseline(serverName, t.name, baseline);
        }

        // Prompt Injection Scan (Layer 2)
        const heuristicResult = scanHeuristics(t.description || '');
        if (heuristicResult.suspicious) {
          isInjection = true;
          statusText = 'INJECTION';
          scanReason = heuristicResult.reason || 'Heuristic prompt injection detected';
        }

        // Update aggregated list. We rename it so the client uses the prefixed version
        aggregatedTools.push({
          ...t,
          name: prefixedName,
          description: `[MCP-Guardian: ${statusText}] ${t.description || ''}`
        });

        // Audit log for tools discovery if anything suspicious is found
        if (isDrift || isInjection) {
          const logId = crypto.randomUUID();
          const auditLog: AuditLog = {
            id: logId,
            timestamp: new Date().toISOString(),
            serverName,
            toolName: t.name,
            category: baseline?.category || 'GENERAL',
            arguments: {},
            status: 'block',
            reason: scanReason,
            drift: isDrift,
            promptInjection: isInjection
          };
          db.addLog(auditLog);
          sendToExtension({ type: 'log', log: auditLog });
        }
      }

      pendingResponsesCount--;
      if (pendingResponsesCount === 0) {
        writeToClient({
          jsonrpc: '2.0',
          id: msg.id,
          result: { tools: aggregatedTools }
        });
      }
    };

    // Store callbacks globally
    (global as any)[aggregatorId] = handleAggregatedResponse;

    for (const [name, proc] of Object.entries(downstreamProcesses)) {
      proc.stdin?.write(JSON.stringify({
        jsonrpc: '2.0',
        id: `agg_tools:${name}:${msg.id}`,
        method: 'tools/list',
        params: {}
      }) + '\n');
    }

    return;
  }

  if (msg.method === 'tools/call') {
    const prefixedName = msg.params.name;
    const mapping = toolsMapping[prefixedName];

    if (!mapping) {
      writeToClient({
        jsonrpc: '2.0',
        id: msg.id,
        error: { code: -32601, message: `Tool ${prefixedName} not found` }
      });
      return;
    }

    const { serverName, originalName } = mapping;
    const args = msg.params.arguments || {};

    // 1. Session boundary check
    const now = Date.now();
    if (now - lastCallTime > SESSION_TIMEOUT) {
      sessionCallGraph = [];
    }
    lastCallTime = now;

    // 2. Fetch baseline details
    const baseline = db.getToolBaseline(serverName, originalName);
    const category = baseline?.category || 'GENERAL';

    // 3. Security evaluation
    let isSuspicious = false;
    let warningReason = '';
    let isDrift = false;
    let isInjection = false;
    let isViolation = false;

    // Layer 1 check: tool drift
    if (baseline && !baseline.approved) {
      isSuspicious = true;
      isDrift = true;
      warningReason = 'Tool contains metadata drift since initial baseline registration.';
    }

    // Layer 2 check: inputs/args prompt injection scan
    const argString = JSON.stringify(args);
    const heuristicScan = scanHeuristics(argString);
    if (heuristicScan.suspicious) {
      isSuspicious = true;
      isInjection = true;
      warningReason = `Prompt injection payload scanned in inputs: ${heuristicScan.reason}`;
    }

    // Layer 3 check: call-graph transitions
    const prevCategory = sessionCallGraph[sessionCallGraph.length - 1];
    const forbiddenList = db.getConfig().forbiddenTransitions;
    if (checkTransition(prevCategory, category, forbiddenList)) {
      isSuspicious = true;
      isViolation = true;
      warningReason = `Forbidden transition: ${prevCategory} -> ${category} detected! Potential exfiltration/escalation vector.`;
    }

    // Track state
    sessionCallGraph.push(category);

    const logId = crypto.randomUUID();
    const auditLog: AuditLog = {
      id: logId,
      timestamp: new Date().toISOString(),
      serverName,
      toolName: originalName,
      category,
      arguments: args,
      status: isSuspicious ? 'pending' : 'allow',
      reason: warningReason || undefined,
      drift: isDrift || undefined,
      promptInjection: isInjection || undefined,
      isCategoryTransitionViolation: isViolation || undefined
    };

    // If API scanning is enabled, run semantic LLM scan in parallel
    const apiKey = db.getConfig().geminiApiKey;
    if (!isSuspicious && apiKey && baseline) {
      try {
        const semanticScan = await scanSemantic(originalName, baseline.description, apiKey);
        if (semanticScan.suspicious) {
          isSuspicious = true;
          isInjection = true;
          warningReason = `LLM scan flagged description: ${semanticScan.reason}`;
          auditLog.status = 'pending';
          auditLog.reason = warningReason;
          auditLog.promptInjection = true;
        }
      } catch (e) {
        console.error('[MCP-Guardian-Proxy] Semantic scan failed', e);
      }
    }

    // If safe and autoApproveSafe is true, proceed directly
    if (!isSuspicious && db.getConfig().autoApproveSafe) {
      db.addLog(auditLog);
      sendToExtension({ type: 'log', log: auditLog });
      forwardToolCall(serverName, originalName, msg.id, args);
      return;
    }

    // Block/Hold request for manual approval
    auditLog.status = 'pending';
    db.addLog(auditLog);
    sendToExtension({ type: 'log', log: auditLog });

    if (!wsConnected) {
      console.error(`[MCP-Guardian-Proxy] Shield warning: Extension offline. Blocking suspicious call automatically.`);
      auditLog.status = 'block';
      auditLog.reason = 'Blocked: VS Code extension is offline during security intercept.';
      db.addLog(auditLog);
      writeToClient({
        jsonrpc: '2.0',
        id: msg.id,
        error: { code: -32603, message: 'Execution blocked (Security Extension offline)' }
      });
      return;
    }

    console.error(`[MCP-Guardian-Proxy] Intercepted suspicious call: ${prefixedName}. Waiting for approval...`);

    // Notify extension of pending approval
    sendToExtension({
      type: 'approve_request',
      id: logId,
      serverName,
      toolName: originalName,
      arguments: args,
      reason: warningReason || 'Configuration requires manual tool call confirmation.',
      driftDetails: isDrift ? { newHash: computeToolHash(baseline || { name: originalName, description: '' }) } : undefined
    });

    // Create deferred promise to block execution until user replies
    const approvalPromise = new Promise<boolean>((resolve, reject) => {
      pendingApprovals[logId] = { resolve, reject, log: auditLog };
    });

    const approved = await approvalPromise;

    if (approved) {
      auditLog.status = 'allow';
      db.addLog(auditLog);
      sendToExtension({ type: 'log', log: auditLog });
      forwardToolCall(serverName, originalName, msg.id, args);
    } else {
      auditLog.status = 'block';
      auditLog.reason = 'Blocked by user.';
      db.addLog(auditLog);
      sendToExtension({ type: 'log', log: auditLog });
      writeToClient({
        jsonrpc: '2.0',
        id: msg.id,
        error: { code: -32603, message: 'Execution blocked by user/policy' }
      });
    }

    return;
  }

  // General fallback proxy routing for other messages (e.g. resources)
  // For requests we don't handle directly, send to the first active downstream process
  const firstServer = Object.keys(downstreamProcesses)[0];
  if (firstServer && downstreamProcesses[firstServer]) {
    const proc = downstreamProcesses[firstServer];
    proc.stdin?.write(JSON.stringify({
      ...msg,
      id: `gen:${firstServer}:${msg.id}`
    }) + '\n');
  } else {
    writeToClient({
      jsonrpc: '2.0',
      id: msg.id,
      error: { code: -32000, message: 'No downstream MCP servers available' }
    });
  }
}

function forwardToolCall(serverName: string, toolName: string, clientId: any, args: any) {
  const proc = downstreamProcesses[serverName];
  if (proc) {
    proc.stdin?.write(JSON.stringify({
      jsonrpc: '2.0',
      id: `call:${serverName}:${clientId}`,
      method: 'tools/call',
      params: {
        name: toolName,
        arguments: args
      }
    }) + '\n');
  } else {
    writeToClient({
      jsonrpc: '2.0',
      id: clientId,
      error: { code: -32000, message: `Server ${serverName} is not running` }
    });
  }
}

// Handle responses from Downstream MCP Servers
function handleDownstreamResponse(serverName: string, msg: any) {
  if (typeof msg.id !== 'string') {
    // If it's a notification, send it to the client (we can prefix logs if we want)
    writeToClient(msg);
    return;
  }

  const idParts = msg.id.split(':');
  const type = idParts[0];

  if (type === 'init') {
    // Suppress initialization responses from downstreams since we already initialized client
    return;
  }

  if (type === 'agg_tools') {
    // Aggregator callback
    const clientId = idParts[2];
    const callbackKey = `tools:${clientId}`;
    const cb = (global as any)[callbackKey];
    if (cb) {
      cb(serverName, msg.result?.tools || []);
      delete (global as any)[callbackKey];
    }
    return;
  }

  if (type === 'call') {
    const clientId = idParts[2];
    // Write response back to LLM client
    writeToClient({
      jsonrpc: '2.0',
      id: isNaN(clientId) ? clientId : Number(clientId),
      result: msg.result,
      error: msg.error
    });
    return;
  }

  if (type === 'gen') {
    const clientId = idParts[2];
    writeToClient({
      jsonrpc: '2.0',
      id: isNaN(clientId) ? clientId : Number(clientId),
      result: msg.result,
      error: msg.error
    });
    return;
  }

  // Default passthrough
  writeToClient(msg);
}

// Initialization
connectToExtension();
syncDownstreamServers();

console.error('[MCP-Guardian-Proxy] Standalone proxy daemon is active and listening to stdin/stdout.');
