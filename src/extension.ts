import * as vscode from 'vscode';
import * as path from 'path';
import * as fs from 'fs';
import * as os from 'os';
import { WebSocketServer, WebSocket } from 'ws';
import { GuardianDb } from './db';
import { GuardianConfig, ExtensionMessage, ProxyMessage, AuditLog } from './types';

let wss: WebSocketServer | null = null;
let activeProxySocket: WebSocket | null = null;
let db: GuardianDb;
let webviewPanel: vscode.WebviewView | null = null;

export function activate(context: vscode.ExtensionContext) {
  console.log('MCP Guardian is active.');

  // Initialize DB in global home directory for cross-process accessibility
  const storagePath = path.join(os.homedir(), '.mcp-guardian');
  db = new GuardianDb(storagePath);

  // Sync extension config with VS Code settings
  syncSettingsFromVscode();

  // Listen to configuration changes
  context.subscriptions.push(
    vscode.workspace.onDidChangeConfiguration((e) => {
      if (e.affectsConfiguration('mcp-guardian')) {
        syncSettingsFromVscode();
      }
    })
  );

  // Start WebSocket Server
  const wsPort = 1337;
  startWebSocketServer(wsPort);

  // Register Webview Provider
  const provider = new GuardianWebviewProvider(context.extensionUri);
  context.subscriptions.push(
    vscode.window.registerWebviewViewProvider('mcp-guardian.dashboard', provider)
  );

  // Register Commands
  context.subscriptions.push(
    vscode.commands.registerCommand('mcp-guardian.openDashboard', () => {
      vscode.commands.executeCommand('workbench.view.extension.mcp-guardian-explorer');
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand('mcp-guardian.approveTool', (logId: string) => {
      respondToPendingRequest(logId, true);
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand('mcp-guardian.denyTool', (logId: string) => {
      respondToPendingRequest(logId, false);
    })
  );
}

export function deactivate() {
  if (wss) {
    wss.close();
  }
}

function syncSettingsFromVscode() {
  const config = vscode.workspace.getConfiguration('mcp-guardian');
  const servers = config.get<any[]>('servers') || [];
  const forbiddenTransitions = config.get<[string, string][]>('forbiddenTransitions') || [];
  const geminiApiKey = config.get<string>('geminiApiKey') || '';
  const autoApproveSafe = config.get<boolean>('autoApproveSafe') ?? true;

  db.updateConfig({
    servers,
    forbiddenTransitions,
    geminiApiKey,
    autoApproveSafe
  });

  // Sync to proxy
  sendToProxy({
    type: 'update_config',
    config: db.getConfig()
  });
}

function startWebSocketServer(port: number) {
  try {
    wss = new WebSocketServer({ port });
    console.log(`WebSocket server started on ws://localhost:${port}`);

    wss.on('connection', (ws) => {
      console.log('Proxy connected to WS server');
      activeProxySocket = ws;

      // Sync state immediately
      ws.send(JSON.stringify({
        type: 'sync_state',
        baselines: db.getBaselines(),
        logs: db.getLogs(),
        config: db.getConfig()
      }));

      ws.on('message', (message) => {
        try {
          const data: ProxyMessage = JSON.parse(message.toString());
          handleProxyMessage(data);
        } catch (e) {
          console.error('Failed to parse message from proxy:', e);
        }
      });

      ws.on('close', () => {
        console.log('Proxy disconnected');
        if (activeProxySocket === ws) {
          activeProxySocket = null;
        }
      });
    });
  } catch (err) {
    console.error('Failed to start WebSocket server:', err);
  }
}

function sendToProxy(msg: ExtensionMessage) {
  if (activeProxySocket && activeProxySocket.readyState === WebSocket.OPEN) {
    activeProxySocket.send(JSON.stringify(msg));
  }
}

function handleProxyMessage(msg: ProxyMessage) {
  switch (msg.type) {
    case 'sync_state':
      // Update database baselines
      for (const [serverName, serverTools] of Object.entries(msg.baselines)) {
        for (const [toolName, baseline] of Object.entries(serverTools)) {
          db.setToolBaseline(serverName, toolName, baseline);
        }
      }
      // Sync to Webview UI
      syncStateToWebview();
      break;

    case 'log':
      db.addLog(msg.log);
      syncStateToWebview();
      break;

    case 'downstream_status':
      // Sync status log to Webview
      syncStateToWebview();
      break;

    case 'approve_request': {
      // Intercepted tool call. Show interactive notification alert
      const { id, serverName, toolName, reason } = msg;
      
      // Update UI first
      syncStateToWebview();

      // Show native VS Code dialog notification
      vscode.window.showWarningMessage(
        `[MCP Shield Alert] Tool '${serverName}__${toolName}' is blocked: ${reason}`,
        'Approve',
        'Deny'
      ).then((selection) => {
        if (selection === 'Approve') {
          respondToPendingRequest(id, true);
        } else {
          respondToPendingRequest(id, false);
        }
      });
      break;
    }
  }
}

function respondToPendingRequest(logId: string, approved: boolean) {
  // Update local log status
  const logs = db.getLogs();
  const logIndex = logs.findIndex(l => l.id === logId);
  if (logIndex !== -1) {
    logs[logIndex].status = approved ? 'allow' : 'block';
    if (!approved) {
      logs[logIndex].reason = 'Blocked by user decision.';
    }
    db.addLog(logs[logIndex]); // updates and saves
  }

  // Reply to proxy
  sendToProxy({
    type: 'approve_response',
    id: logId,
    approved
  });

  // Sync updated state to Webview
  syncStateToWebview();
}

function syncStateToWebview() {
  if (webviewPanel) {
    webviewPanel.webview.postMessage({
      type: 'sync',
      baselines: db.getBaselines(),
      logs: db.getLogs(),
      config: db.getConfig(),
      proxyConnected: !!activeProxySocket
    });
  }
}

// VS Code Webview View Provider
class GuardianWebviewProvider implements vscode.WebviewViewProvider {
  constructor(private readonly extensionUri: vscode.Uri) {}

  resolveWebviewView(
    webviewView: vscode.WebviewView,
    context: vscode.WebviewViewResolveContext<unknown>,
    token: vscode.CancellationToken
  ): void | Thenable<void> {
    webviewPanel = webviewView;

    webviewView.webview.options = {
      enableScripts: true,
      localResourceRoots: [this.extensionUri]
    };

    webviewView.webview.html = this.getHtmlContent(webviewView.webview);

    // Listen to messages from the UI
    webviewView.webview.onDidReceiveMessage((message) => {
      switch (message.type) {
        case 'request_sync':
          syncStateToWebview();
          break;
        case 'approve_request':
          respondToPendingRequest(message.id, true);
          break;
        case 'deny_request':
          respondToPendingRequest(message.id, false);
          break;
        case 'approve_drift':
          sendToProxy({
            type: 'approve_drift',
            serverName: message.serverName,
            toolName: message.toolName,
            newHash: message.newHash
          });
          break;
        case 'set_category':
          sendToProxy({
            type: 'set_category',
            serverName: message.serverName,
            toolName: message.toolName,
            category: message.category
          });
          break;
        case 'save_config':
          // Save to VS Code configuration so it persists
          const config = vscode.workspace.getConfiguration('mcp-guardian');
          config.update('servers', message.config.servers, vscode.ConfigurationTarget.Global);
          config.update('forbiddenTransitions', message.config.forbiddenTransitions, vscode.ConfigurationTarget.Global);
          config.update('geminiApiKey', message.config.geminiApiKey, vscode.ConfigurationTarget.Global);
          config.update('autoApproveSafe', message.config.autoApproveSafe, vscode.ConfigurationTarget.Global);
          break;
        case 'clear_logs':
          db.clearLogs();
          syncStateToWebview();
          break;
      }
    });

    // Handle view state changes
    webviewView.onDidChangeVisibility(() => {
      if (webviewView.visible) {
        syncStateToWebview();
      }
    });

    // Send initial sync
    setTimeout(syncStateToWebview, 500);
  }

  private getHtmlContent(webview: vscode.Webview): string {
    const htmlPath = path.join(this.extensionUri.fsPath, 'src', 'webview', 'sidebar.html');
    if (fs.existsSync(htmlPath)) {
      let content = fs.readFileSync(htmlPath, 'utf8');
      
      // Inject VS Code Webview CSP and standard vscode CSS/JS hooks if needed
      // (For now, our embedded sidebar will be clean and self-contained)
      return content;
    }
    return `<html><body><h3>Failed to load Dashboard UI at ${htmlPath}</h3></body></html>`;
  }
}
