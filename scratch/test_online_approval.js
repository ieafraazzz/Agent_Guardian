const { WebSocketServer } = require('ws');
const { spawn } = require('child_process');
const path = require('path');
const readline = require('readline');

// Start WebSocket Server (VS Code Sim)
const wss = new WebSocketServer({ port: 1337 });
console.log('--- VS Code Sim WebSocket Server listening on port 1337 ---');

let proxyProc = null;
let clientProc = null;

wss.on('connection', (ws) => {
  console.log('[WS-Sim] Proxy connected to WS Server.');

  ws.on('message', (message) => {
    try {
      const data = JSON.parse(message.toString());
      console.log(`[WS-Sim] Received message: ${data.type}`);

      if (data.type === 'approve_request') {
        console.log(`[WS-Sim] Intercepted Alert for: ${data.serverName}__${data.toolName}`);
        console.log(`[WS-Sim] Reason: ${data.reason}`);
        console.log(`[WS-Sim] Automatically sending APPROVE response after 1.5 seconds...`);

        setTimeout(() => {
          ws.send(JSON.stringify({
            type: 'approve_response',
            id: data.id,
            approved: true
          }));
        }, 1500);
      }
    } catch (e) {
      console.error('[WS-Sim] Error parsing WS message:', e);
    }
  });

  ws.on('close', () => {
    console.log('[WS-Sim] Proxy disconnected.');
  });
});

// Run client simulator after WS boots
setTimeout(() => {
  const clientPath = path.join(__dirname, 'test_client.js');
  console.log(`Spawning Client Simulator: node ${clientPath}`);
  
  clientProc = spawn('node', [clientPath], { stdio: 'inherit' });

  clientProc.on('close', (code) => {
    console.log(`[Client-Sim] Completed with code ${code}`);
    wss.close();
    process.exit(0);
  });
}, 500);
