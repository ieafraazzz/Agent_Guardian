import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import { EvaluationEngine } from './engine';
import { calculateMetrics } from './metrics';
import { EVALUATION_CONFIGURATIONS } from './configurations';
import { EvaluationRun, EvaluationScenario, ScenarioResult } from './types';

export interface RunOptions {
  corpusPath: string;
  policyPath: string;
  outputDirectory: string;
  storagePath: string;
  repetitions?: number;
}

export function runEvaluation(options: RunOptions): EvaluationRun {
  const corpusContent = fs.readFileSync(options.corpusPath, 'utf8');
  const policyContent = fs.readFileSync(options.policyPath, 'utf8');
  const scenarios = parseCorpus(corpusContent);
  JSON.parse(policyContent);
  const repetitions = Math.max(1, Math.min(100, options.repetitions || 1));
  const engine = new EvaluationEngine(options.storagePath);
  const configurations = EVALUATION_CONFIGURATIONS.map(configuration => {
    const results: ScenarioResult[] = [];
    for (let repetition = 0; repetition < repetitions; repetition += 1) {
      for (const scenario of scenarios) results.push(engine.evaluate(scenario, configuration, repetition));
    }
    return {
      configuration,
      metrics: calculateMetrics(results),
      heldOutMetrics: calculateMetrics(results.filter(item => item.split === 'held_out')),
      results
    };
  });
  const run: EvaluationRun = {
    schemaVersion: 1,
    generatedAt: new Date().toISOString(),
    corpusPath: portableRelative(options.corpusPath),
    corpusSha256: sha256(corpusContent),
    policyPath: portableRelative(options.policyPath),
    policySha256: sha256(policyContent),
    repetitions,
    configurations
  };
  writeOutputs(run, options.outputDirectory);
  return run;
}

export function parseCorpus(content: string): EvaluationScenario[] {
  const scenarios = content.split(/\r?\n/).filter(line => line.trim() && !line.trim().startsWith('#'))
    .map((line, index) => {
      try { return JSON.parse(line) as EvaluationScenario; }
      catch (error) { throw new Error(`Invalid corpus JSONL at line ${index + 1}`, { cause: error }); }
    });
  const ids = new Set<string>();
  for (const scenario of scenarios) {
    if (!scenario.id || ids.has(scenario.id)) throw new Error(`Missing or duplicate scenario id '${scenario.id}'`);
    ids.add(scenario.id);
    if (!['development', 'held_out'].includes(scenario.split)) throw new Error(`Invalid split for '${scenario.id}'`);
    if (!['mcp', 'browser', 'cross'].includes(scenario.lane)) throw new Error(`Invalid lane for '${scenario.id}'`);
    if (!scenario.expected?.fullOutcome) throw new Error(`Missing expected outcome for '${scenario.id}'`);
  }
  return scenarios;
}

function writeOutputs(run: EvaluationRun, outputDirectory: string): void {
  fs.mkdirSync(outputDirectory, { recursive: true });
  fs.writeFileSync(path.join(outputDirectory, 'evaluation.json'), JSON.stringify(run, null, 2), 'utf8');
  fs.writeFileSync(path.join(outputDirectory, 'summary.md'), markdown(run), 'utf8');
  fs.writeFileSync(path.join(outputDirectory, 'results.csv'), csv(run), 'utf8');
}

function markdown(run: EvaluationRun): string {
  const lines = [
    '# Agent Guardian evaluation', '',
    `Generated: ${run.generatedAt}`,
    `Corpus SHA-256: \`${run.corpusSha256}\``,
    `Policy SHA-256: \`${run.policySha256}\``,
    `Repetitions: ${run.repetitions}`, '',
    '| Configuration | ASR | Precision | Recall | F1 | Benign completion | Permission rate | p95 latency (ms) |',
    '|---|---:|---:|---:|---:|---:|---:|---:|'
  ];
  for (const item of run.configurations) {
    const metric = item.metrics;
    lines.push(`| ${item.configuration.label} | ${pct(metric.attackSuccessRate.value)} | ${pct(metric.precision.value)} | ${pct(metric.recall.value)} | ${metric.f1.toFixed(3)} | ${pct(metric.benignCompletionRate.value)} | ${pct(metric.permissionFrequency.value)} | ${metric.latencyMs.p95.toFixed(3)} |`);
  }
  lines.push('', '## Held-out split', '',
    '| Configuration | Held-out ASR | Held-out precision | Held-out recall | Held-out F1 |',
    '|---|---:|---:|---:|---:|');
  for (const item of run.configurations) {
    const metric = item.heldOutMetrics;
    lines.push(`| ${item.configuration.label} | ${pct(metric.attackSuccessRate.value)} | ${pct(metric.precision.value)} | ${pct(metric.recall.value)} | ${metric.f1.toFixed(3)} |`);
  }
  lines.push('', 'Intervals in `evaluation.json` are 95% Wilson score intervals. Latency and memory values are measurements of deterministic detector replay, not hosted-model latency.', '');
  return lines.join('\n');
}

function csv(run: EvaluationRun): string {
  const header = [
    'configuration', 'scenario_id', 'split', 'lane', 'malicious', 'expected', 'outcome',
    'detected', 'attack_succeeded', 'partial_influence', 'permission_requested', 'overridden',
    'rules', 'latency_ms', 'memory_delta_bytes', 'error'
  ];
  const rows: Array<Array<string | number | boolean>> = [header];
  for (const item of run.configurations) {
    for (const result of item.results) {
      rows.push([
        item.configuration.id, result.scenarioId, result.split, result.lane, result.malicious,
        result.expectedOutcome, result.outcome, result.detected, result.attackSucceeded,
        result.partialInfluence, result.permissionRequested, result.overridden,
        result.matchedRuleIds.join('|'), result.latencyMs, result.memoryDeltaBytes, result.error || ''
      ]);
    }
  }
  return rows.map(row => row.map(cell => quote(String(cell))).join(',')).join('\n') + '\n';
}

function quote(value: string): string {
  return /[",\r\n]/.test(value) ? `"${value.replace(/"/g, '""')}"` : value;
}

function pct(value: number): string {
  return `${(value * 100).toFixed(1)}%`;
}

function sha256(value: string): string {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function portableRelative(value: string): string {
  return path.relative(process.cwd(), path.resolve(value)).replace(/\\/g, '/');
}
