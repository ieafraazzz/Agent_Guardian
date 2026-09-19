const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const test = require('node:test');

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

test('dashboard exposes intent, evidence, outcome, and trace integrity', () => {
  const dashboard = fs.readFileSync(path.join(root, 'src', 'webview', 'sidebar.html'), 'utf8');
  for (const label of ['Declared session intent', 'Ordered Interaction Timeline', 'Trace integrity', 'evidence-list']) {
    assert.ok(dashboard.includes(label), `missing dashboard element: ${label}`);
  }
});
