const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const {
  EVALUATION_CONFIGURATIONS,
  EvaluationEngine,
  parseCorpus,
  runEvaluation,
  wilson
} = require('../dist/evaluation.js');

const root = path.join(__dirname, '..');
const corpusPath = path.join(root, 'evaluation', 'corpus.jsonl');
const policyPath = path.join(root, 'evaluation', 'frozen-policy-v1.json');

function temporaryDirectory(prefix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

test('evaluation corpus is unique, split, labelled, and covers required attack families', () => {
  const scenarios = parseCorpus(fs.readFileSync(corpusPath, 'utf8'));
  assert.equal(scenarios.length, 25);
  assert.equal(new Set(scenarios.map(item => item.id)).size, scenarios.length);
  assert.ok(scenarios.some(item => item.split === 'held_out'));
  assert.ok(scenarios.some(item => !item.malicious));
  for (const lane of ['mcp', 'browser', 'cross']) assert.ok(scenarios.some(item => item.lane === lane));
  const tags = new Set(scenarios.flatMap(item => item.tags));
  for (const required of [
    'metadata-poisoning', 'rug-pull', 'schema-poisoning', 'shadowing', 'arguments',
    'tool-result', 'hidden-text', 'credential', 'confused-deputy', 'cross-surface', 'override'
  ]) assert.ok(tags.has(required), `missing ${required}`);
});

test('full configuration matches every frozen expected outcome', () => {
  const scenarios = parseCorpus(fs.readFileSync(corpusPath, 'utf8'));
  const full = EVALUATION_CONFIGURATIONS.find(item => item.id === 'full');
  const engine = new EvaluationEngine(temporaryDirectory('guardian-eval-engine-'));
  const results = scenarios.map(item => engine.evaluate(item, full));
  assert.deepEqual(results.filter(item => item.outcome !== item.expectedOutcome).map(item => item.scenarioId), []);
  assert.deepEqual(results.filter(item => item.error).map(item => item.error), []);
});

test('ablation runner produces reproducible artifacts and meaningful layer effects', () => {
  const outputDirectory = temporaryDirectory('guardian-eval-output-');
  const run = runEvaluation({
    corpusPath,
    policyPath,
    outputDirectory,
    storagePath: temporaryDirectory('guardian-eval-store-'),
    repetitions: 1
  });
  assert.equal(run.configurations.length, 14);
  assert.match(run.corpusSha256, /^[a-f0-9]{64}$/);
  assert.match(run.policySha256, /^[a-f0-9]{64}$/);
  for (const name of ['evaluation.json', 'summary.md', 'results.csv']) {
    assert.equal(fs.existsSync(path.join(outputDirectory, name)), true);
  }
  const noGuardian = run.configurations.find(item => item.configuration.id === 'no_guardian');
  const full = run.configurations.find(item => item.configuration.id === 'full');
  assert.equal(noGuardian.metrics.attackSuccessRate.value, 1);
  assert.equal(full.metrics.recall.value, 1);
  assert.equal(full.metrics.precision.value, 1);
  assert.equal(full.metrics.benignCompletionRate.value, 1);
  assert.ok(full.metrics.attackSuccessRate.value > 0, 'simulated user override must remain visible');
  assert.ok(full.metrics.attackSuccessRate.value < noGuardian.metrics.attackSuccessRate.value);
  for (const layer of ['integrity', 'semantic', 'behavior', 'intent', 'provenance']) {
    const ablated = run.configurations.find(item => item.configuration.id === `full_minus_${layer}`);
    assert.ok(ablated.metrics.recall.value < full.metrics.recall.value, `${layer} ablation must reduce recall`);
    assert.ok(ablated.heldOutMetrics.recall.value < full.heldOutMetrics.recall.value, `${layer} held-out ablation must reduce recall`);
  }
});

test('Wilson intervals are bounded and include the measured proportion', () => {
  const interval = wilson(7, 10);
  assert.equal(interval.value, 0.7);
  assert.ok(interval.low >= 0 && interval.high <= 1);
  assert.ok(interval.low <= interval.value && interval.high >= interval.value);
  assert.deepEqual(wilson(0, 0), { value: 0, low: 0, high: 0, confidence: 0.95 });
});

test('corpus parser rejects duplicate ids and malformed JSONL', () => {
  const line = JSON.stringify({
    id: 'duplicate', title: 'duplicate', split: 'development', lane: 'mcp', kind: 'benign',
    malicious: false, tags: [], source: 'test', input: {}, expected: { fullOutcome: 'ALLOW' }
  });
  assert.throws(() => parseCorpus(`${line}\n${line}\n`), /duplicate/i);
  assert.throws(() => parseCorpus('{not-json}\n'), /Invalid corpus JSONL/i);
});
