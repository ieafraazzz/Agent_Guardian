const readline = require('readline');

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
  terminal: false
});

rl.on('line', (line) => {
  if (!line.trim()) return;
  try {
    const msg = JSON.parse(line);
    handleRequest(msg);
  } catch (e) {
    console.error('[Mock-Server] Error parsing message:', line, e);
  }
});

function writeResponse(msg) {
  process.stdout.write(JSON.stringify(msg) + '\n');
}

function handleRequest(msg) {
  if (msg.method === 'initialize') {
    writeResponse({
      jsonrpc: '2.0',
      id: msg.id,
      result: {
        protocolVersion: '2024-11-05',
        capabilities: {
          tools: {}
        },
        serverInfo: {
          name: 'mock-mcp-server',
          version: '1.0.0'
        }
      }
    });
    return;
  }

  if (msg.method === 'tools/list') {
    writeResponse({
      jsonrpc: '2.0',
      id: msg.id,
      result: {
        tools: [
          {
            name: 'get_invoice',
            description: 'Retrieve details and content of financial invoices.',
            inputSchema: {
              type: 'object',
              properties: {
                invoice_id: { type: 'string', description: 'The invoice ID' }
              },
              required: ['invoice_id']
            }
          },
          {
            name: 'read_file',
            description: 'Read the contents of a local file in the workspace.',
            inputSchema: {
              type: 'object',
              properties: {
                path: { type: 'string', description: 'File path to read' }
              },
              required: ['path']
        }
          },
          {
            name: 'send_email',
            description: 'Send an email communication to a specified recipient.',
            inputSchema: {
              type: 'object',
              properties: {
                to: { type: 'string', description: 'Recipient email address' },
                subject: { type: 'string', description: 'Subject of email' },
                body: { type: 'string', description: 'Body text of email' }
              },
              required: ['to', 'body']
            }
          }
        ]
      }
    });
    return;
  }

  if (msg.method === 'tools/call') {
    const name = msg.params.name;
    const args = msg.params.arguments || {};

    if (name === 'get_invoice') {
      writeResponse({
        jsonrpc: '2.0',
        id: msg.id,
        result: {
          content: [
            {
              type: 'text',
              text: `Invoice ${args.invoice_id} content: Total due $1,250.00. Billing address: Acme Corp.`
            }
          ]
        }
      });
      return;
    }

    if (name === 'read_file') {
      writeResponse({
        jsonrpc: '2.0',
        id: msg.id,
        result: {
          content: [
            {
              type: 'text',
              text: `File content for '${args.path}': CONFIDENTIAL API_KEY = "sk-live-9993332211"`
            }
          ]
        }
      });
      return;
    }

    if (name === 'send_email') {
      writeResponse({
        jsonrpc: '2.0',
        id: msg.id,
        result: {
          content: [
            {
              type: 'text',
              text: `Email successfully sent to ${args.to} with subject "${args.subject || 'No Subject'}".`
            }
          ]
        }
      });
      return;
    }

    writeResponse({
      jsonrpc: '2.0',
      id: msg.id,
      error: { code: -32601, message: `Tool ${name} not found` }
    });
  }
}
