const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const test = require('node:test');

const {
  actionFingerprint,
  buildAuditExport,
  inferDestination,
  isTrustedDestination,
  parseAuditExport,
  resolveSessionPolicy,
  sanitizeForDisplay,
  serializeReport,
  verifyAuditExport
} = require('../dist/security.js');

function log(overrides = {}) {
  return {
    id: 'log-1',
    timestamp: '2026-01-01T00:00:00.000Z',
    serverName: 'mail',
    toolName: 'send_email',
    category: 'WRITE_COMMUNICATION',
    arguments: { to: 'professor@example.edu', api_key: 'top-secret-value' },
    status: 'block',
    reason: 'Destination requires approval',
    evidence: [{
      id: 'evidence-1', detectorId: 'policy', detectorVersion: '1', ruleId: 'R4',
      severity: 'high', confidence: 1, message: 'Untrusted destination', eventIds: ['event-1']
    }],
    ...overrides
  };
}

test('action approvals bind canonical arguments, session context, and evidence', () => {
  const first = {
    sessionId: 'session-1', intent: 'Send report', serverName: 'mail', toolName: 'send_email',
    capability: 'WRITE_COMMUNICATION', destination: 'professor@example.edu',
    arguments: { subject: 'Report', body: 'Attached' }, evidenceIds: ['b', 'a']
  };
  const reordered = {
    ...first,
    arguments: { body: 'Attached', subject: 'Report' }
  };
  assert.equal(actionFingerprint(first), actionFingerprint(reordered));
  assert.notEqual(actionFingerprint(first), actionFingerprint({ ...first, destination: 'attacker.example' }));
  assert.notEqual(actionFingerprint(first), actionFingerprint({ ...first, sessionId: 'session-2' }));
});

test('approval display sanitization removes controls, redacts credentials, and bounds structures', () => {
  const safe = sanitizeForDisplay({
    note: '\u202E<script>alert(1)</script>',
    authorization: 'Bearer abcdefghijklmnop',
    secret: 'api_key=top-secret-token',
    nested: {
      one: { two: { three: { four: { five: { six: { seven: 'hidden' } } } } } }
    }
  });
  const serialized = JSON.stringify(safe);
  assert.doesNotMatch(serialized, /\u202e/i);
  assert.doesNotMatch(serialized, /abcdefghijklmnop|top-secret-token/);
  assert.match(serialized, /REDACTED/);
  assert.match(serialized, /maximum depth/);
});

test('session policy accepts out-of-band defaults and scoped MCP metadata overrides', () => {
  const configured = {
    intent: 'Default intent',
    allowedCapabilities: ['READ_LOCAL'],
    trustedDestinations: ['@example.edu']
  };
  assert.equal(resolveSessionPolicy(undefined, configured).policy.intent, 'Default intent');
  const resolved = resolveSessionPolicy({ guardian: {
    sessionId: 'demo session!',
    intent: 'Send the report',
    allowedCapabilities: ['WRITE_COMMUNICATION'],
    trustedDestinations: ['professor@example.edu']
  } }, configured);
  assert.equal(resolved.sessionId, 'demosession');
  assert.deepEqual(resolved.policy.allowedCapabilities, ['WRITE_COMMUNICATION']);
  assert.equal(inferDestination({ to: 'professor@example.edu' }), 'professor@example.edu');
  assert.equal(isTrustedDestination('student@example.edu', ['@example.edu']), true);
  assert.equal(isTrustedDestination('attacker@example.com', ['@example.edu']), false);
});

test('JSON, JSONL, and SARIF reports redact secrets and detect audit-chain tampering', () => {
  const logs = [log(), log({ id: 'log-2', timestamp: '2026-01-01T00:00:01.000Z', status: 'allow' })];
  const records = buildAuditExport(logs);
  assert.equal(verifyAuditExport(records), true);
  assert.doesNotMatch(JSON.stringify(records), /top-secret-value/);
  const jsonl = serializeReport(logs, 'jsonl');
  assert.equal(verifyAuditExport(parseAuditExport(jsonl)), true);
  const json = serializeReport(logs, 'json');
  assert.equal(verifyAuditExport(parseAuditExport(json)), true);
  const sarif = JSON.parse(serializeReport(logs, 'sarif'));
  assert.equal(sarif.version, '2.1.0');
  assert.equal(sarif.runs[0].results[0].ruleId, 'R4');
  records[0].log.reason = 'tampered';
  assert.equal(verifyAuditExport(records), false);
});

test('reporting CLI returns distinct success, usage, and integrity exit codes', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'agent-guardian-cli-'));
  const reportPath = path.join(directory, 'audit.jsonl');
  const databasePath = path.join(directory, 'mcp-guardian-db.json');
  fs.writeFileSync(databasePath, JSON.stringify({ baselines: {}, logs: [log()], config: {
    servers: [], forbiddenTransitions: [], autoApproveSafe: true
  } }));
  const cli = path.join(__dirname, '..', 'dist', 'cli.js');
  const exported = spawnSync(process.execPath, [cli, 'report', 'export', '--format', 'jsonl', '--out', reportPath, '--storage', directory]);
  assert.equal(exported.status, 0, exported.stderr.toString());
  assert.equal(spawnSync(process.execPath, [cli, 'report', 'verify', '--input', reportPath]).status, 0);
  assert.equal(spawnSync(process.execPath, [cli, 'unknown']).status, 2);
  const records = parseAuditExport(fs.readFileSync(reportPath, 'utf8'));
  records[0].log.reason = 'tampered';
  fs.writeFileSync(reportPath, records.map(item => JSON.stringify(item)).join('\n'));
  assert.equal(spawnSync(process.execPath, [cli, 'report', 'verify', '--input', reportPath]).status, 3);
});
