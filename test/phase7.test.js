const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const test = require('node:test');
const { renderMarkdown } = require('../demo/report-generator.js');

const root = path.resolve(__dirname, '..');

test('distribution metadata includes all runtime artifacts', () => {
  const manifest = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
  assert.equal(manifest.bin['agent-guardian'], './dist/cli.js');
  assert.ok(manifest.files.includes('dist/'));
  assert.ok(manifest.files.includes('src/webview/sidebar.html'));
  assert.equal(manifest.scripts.demo.includes('demo/run-demo.js'), true);
});

test('CLI configures and safely displays a downstream server', () => {
  const storage = fs.mkdtempSync(path.join(os.tmpdir(), 'agent-guardian-phase7-'));
  const cli = path.join(root, 'dist', 'cli.js');
  const add = spawnSync(process.execPath, [cli, 'config', 'add-server', '--name', 'mock', '--command', 'node', '--args-json', '["server.js"]', '--storage', storage], { encoding: 'utf8' });
  assert.equal(add.status, 0, add.stderr);
  const show = spawnSync(process.execPath, [cli, 'config', 'show', '--storage', storage], { encoding: 'utf8' });
  assert.equal(show.status, 0, show.stderr);
  const config = JSON.parse(show.stdout);
  assert.deepEqual(config.servers.find(server => server.name === 'mock'), {
    name: 'mock', command: 'node', args: ['server.js']
  });
});

test('presentation demo is isolated and documents its assertions', () => {
  const runner = fs.readFileSync(path.join(root, 'demo', 'run-demo.js'), 'utf8');
  const guide = fs.readFileSync(path.join(root, 'demo', 'README.md'), 'utf8');
  assert.match(runner, /maliciousSideEffectPrevented/);
  assert.match(runner, /benignSideEffectCompleted/);
  assert.match(runner, /CrossSurfaceStore/);
  assert.match(guide, /presentation script for ma'am/i);
});

test('human-readable demo report explains prompt, threat, rule, decision, and side effects', () => {
  const report = {
    generatedAt: new Date().toISOString(), passed: true, traceIntegrity: true,
    assertions: {
      maliciousCredentialHeld: true, maliciousExternalSendHeld: true,
      maliciousSideEffectPrevented: true, benignSendAllowed: true,
      benignSideEffectCompleted: true
    },
    sideEffects: { approvedDeliveries: 1, attackerDeliveries: 0 },
    scenarios: [
      { id: 'malicious', userPrompt: 'Show total only', intent: 'Show total only', evidenceCount: 2, credentialDecision: 'ASK', credentialRules: ['R6'], sendDecision: 'ASK', sendRules: ['R6'], outcome: 'prevented' },
      { id: 'benign', userPrompt: 'Send to professor', intent: 'Send to professor', evidenceCount: 0, sendDecision: 'ALLOW', sendRules: [], outcome: 'completed' }
    ],
    traceRecords: [{
      sequence: 0,
      event: { sessionId: 'demo-malicious', timestamp: new Date().toISOString(), lane: 'browser', operation: 'submit_form', dataLabels: ['untrusted'], destination: 'http://127.0.0.1:1234/collect' },
      evidence: [{ id: 'e1', detectorId: 'browser.provenance', ruleId: 'R6', severity: 'high', message: 'Untrusted content influenced submit_form', metadata: { match: 'exact-fingerprint', samples: ['hidden instruction'] } }],
      decision: { outcome: 'ASK' }
    }]
  };
  const readable = renderMarkdown(report);
  for (const expected of ['User prompt', 'Hidden prompt injection', 'R6', 'ASK', 'Actual attacker deliveries', 'Scope and limitations']) {
    assert.match(readable, new RegExp(expected, 'i'));
  }
  assert.doesNotMatch(readable, /127\.0\.0\.1:1234/);
});

test('dashboard exposes intent, evidence, outcome, and trace integrity', () => {
  const dashboard = fs.readFileSync(path.join(root, 'src', 'webview', 'sidebar.html'), 'utf8');
  for (const label of ['Declared session intent', 'Ordered Interaction Timeline', 'Trace integrity', 'evidence-list']) {
    assert.ok(dashboard.includes(label), `missing dashboard element: ${label}`);
  }
});
