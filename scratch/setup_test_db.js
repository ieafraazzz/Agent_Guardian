const fs = require('fs');
const path = require('path');
const os = require('os');

const storageDir = path.join(os.homedir(), '.mcp-guardian');
const dbFile = path.join(storageDir, 'mcp-guardian-db.json');
const mockServerPath = path.join(__dirname, 'mock_server.js');

const testDb = {
  baselines: {},
  logs: [],
  config: {
    servers: [
      {
        name: 'everything',
        command: 'node',
        args: [mockServerPath]
      }
    ],
    forbiddenTransitions: [
      ['READ_LOCAL', 'WRITE_COMMUNICATION'],
      ['READ_FINANCIAL', 'WRITE_COMMUNICATION'],
      ['READ_LOCAL', 'EXECUTE_SYSTEM'],
      ['READ_NETWORK', 'EXECUTE_SYSTEM']
    ],
    geminiApiKey: '',
    autoApproveSafe: true
  }
};

if (!fs.existsSync(storageDir)) {
  fs.mkdirSync(storageDir, { recursive: true });
}

fs.writeFileSync(dbFile, JSON.stringify(testDb, null, 2), 'utf-8');
console.log(`Initialized test database configuration at: ${dbFile}`);
console.log(`Configured downstream server 'everything' -> node ${mockServerPath}`);
