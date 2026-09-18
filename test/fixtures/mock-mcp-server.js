const readline = require('node:readline');

const serverName = process.env.MOCK_SERVER_NAME || 'mock';
const mode = process.env.MOCK_SERVER_MODE || 'normal';
const reader = readline.createInterface({ input: process.stdin, terminal: false });

function respond(message) {
  process.stdout.write(`${JSON.stringify(message)}\n`);
}

reader.on('line', line => {
  if (!line.trim()) return;
  const message = JSON.parse(line);

  if (message.method === 'initialize') {
    respond({
      jsonrpc: '2.0',
      id: message.id,
      result: {
        protocolVersion: '2024-11-05',
        capabilities: { tools: {} },
        serverInfo: { name: serverName, version: '1.0.0' }
      }
    });
    return;
  }

  if (message.method === 'tools/list') {
    if (mode === 'silent-tools') return;
    const tools = [
      {
        name: 'echo',
        description: `Echo from ${serverName}`,
        inputSchema: {
          type: 'object',
          properties: { value: { type: 'string' } },
          required: ['value']
        }
      }
    ];
    if (serverName === 'alpha') {
      tools.push(
        {
          name: 'read_file',
          description: 'Read a local file',
          inputSchema: {
            type: 'object',
            properties: { path: { type: 'string' } },
            required: ['path']
          }
        },
        {
          name: 'send_email',
          description: 'Send an email message',
          inputSchema: {
            type: 'object',
            properties: {
              to: { type: 'string' },
              body: { type: 'string' }
            },
            required: ['to', 'body']
          }
        }
      );
    }
    respond({ jsonrpc: '2.0', id: message.id, result: { tools } });
    return;
  }

  if (message.method === 'tools/call') {
    if (mode === 'silent-calls') return;
    respond({
      jsonrpc: '2.0',
      id: message.id,
      result: {
        content: [{
          type: 'text',
          text: JSON.stringify({ serverName, tool: message.params.name, arguments: message.params.arguments })
        }]
      }
    });
  }
});
