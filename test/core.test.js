const assert = require('node:assert/strict');
const test = require('node:test');
const {
  CompletenessLedger,
  DetectorRegistry,
  HashChainedAuditTrail,
  PolicyEngine
} = require('../dist/core.js');

function session() {
  return {
    id: 'session-1',
    intent: 'Retrieve invoice 42 and summarize it',
    allowedCapabilities: ['financial.read'],
    trustedDestinations: [],
    startedAt: '2026-01-01T00:00:00.000Z',
    events: [],
    dataFlow: [],
    taint: []
  };
}

function event() {
  return {
    id: 'event-1',
    sessionId: 'session-1',
    timestamp: '2026-01-01T00:00:01.000Z',
    lane: 'mcp',
    kind: 'tool_call',
    operation: 'invoice__get_invoice',
    capability: 'financial.read',
    dataLabels: []
  };
}

function evidence(ruleId, message = 'test evidence', metadata) {
  return {
    id: `evidence-${ruleId}`,
    detectorId: 'test',
    detectorVersion: '1.0.0',
    ruleId,
    severity: 'high',
    confidence: 1,
    message,
    eventIds: ['event-1'],
    metadata
  };
}

test('detector registry rejects duplicate detector ids and records unsupported work', async () => {
  const registry = new DetectorRegistry();
  const detector = {
    id: 'safe-detector',
    version: '1.0.0',
    supports: () => false,
    analyze: () => ({ evidence: [] })
  };
  registry.register(detector);
  assert.throws(() => registry.register(detector), /already registered/);

  const result = await registry.run({ session: session(), event: event() });
  assert.equal(result.evidence.length, 0);
  assert.equal(result.ledger.summarize().outOfScope, 1);
  assert.equal(result.ledger.summarize().complete, true);
});

test('detector failures make the completeness verdict non-clean', async () => {
  const registry = new DetectorRegistry();
  registry.register({
    id: 'failing-detector',
    version: '1.0.0',
    supports: () => true,
    analyze: () => { throw new Error('scan timed out'); }
  });

  const result = await registry.run({ session: session(), event: event() });
  const summary = result.ledger.summarize();
  assert.equal(summary.complete, false);
  assert.equal(summary.failed, 1);
  assert.deepEqual(summary.reasons, ['scan timed out']);
});

test('completeness ledger distinguishes completed, partial, and out-of-scope work', () => {
  const ledger = new CompletenessLedger();
  ledger.record({ analyzerId: 'a', subject: 'one', outcome: 'completed', startedAt: 'a', finishedAt: 'b' });
  ledger.record({ analyzerId: 'b', subject: 'two', outcome: 'partial', startedAt: 'a', finishedAt: 'b', reason: 'size limit' });
  ledger.record({ analyzerId: 'c', subject: 'three', outcome: 'out_of_scope', startedAt: 'a', finishedAt: 'b' });
  assert.deepEqual(ledger.summarize(), {
    complete: false,
    total: 3,
    completed: 1,
    partial: 1,
    skipped: 0,
    failed: 0,
    outOfScope: 1,
    reasons: ['size limit']
  });
});

test('policy engine applies deterministic precedence and one-time approval expiry', () => {
  const engine = new PolicyEngine({ approvalTtlMs: 5_000 });
  assert.equal(engine.evaluate(session(), event(), []).outcome, 'ALLOW');

  const ask = engine.evaluate(session(), event(), [evidence('R3', 'Capability outside intent')]);
  assert.equal(ask.outcome, 'ASK');
  assert.ok(ask.expiresAt);

  const blocked = engine.evaluate(session(), event(), [evidence('R3'), evidence('R5', 'Credential followed by remote write')]);
  assert.equal(blocked.outcome, 'BLOCK');

  const credential = engine.evaluate(session(), event(), [evidence('R4', 'Credential egress', { dataLabel: 'credential' })]);
  assert.equal(credential.outcome, 'BLOCK');
});

test('R9 raises an ASK decision to BLOCK', () => {
  const decision = new PolicyEngine().evaluate(session(), event(), [
    evidence('R3', 'Capability outside intent'),
    evidence('R9', 'Confusable characters detected')
  ]);
  assert.equal(decision.outcome, 'BLOCK');
});

test('hash-chained audit detects payload and link tampering', () => {
  const inspection = {
    complete: true,
    total: 1,
    completed: 1,
    partial: 0,
    skipped: 0,
    failed: 0,
    outOfScope: 0,
    reasons: []
  };
  const trail = new HashChainedAuditTrail();
  const decision = new PolicyEngine().evaluate(session(), event(), []);
  trail.append({ event: event(), decision, inspection }, '2026-01-01T00:00:02.000Z');
  trail.append({ event: { ...event(), id: 'event-2' }, decision: { ...decision, id: 'decision-2', eventId: 'event-2' }, inspection }, '2026-01-01T00:00:03.000Z');
  assert.equal(trail.verify(), true);
  const jsonl = trail.toJSONL();
  const restored = HashChainedAuditTrail.parseJSONL(jsonl);
  assert.equal(restored.length, 2);
  assert.equal(HashChainedAuditTrail.verify(restored), true);

  const tampered = structuredClone(trail.list());
  tampered[0].payload.event.operation = 'attacker__send_email';
  assert.equal(HashChainedAuditTrail.verify(tampered), false);
});
