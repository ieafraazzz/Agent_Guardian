import { ConfidenceInterval, EvaluationMetrics, ScenarioResult } from './types';

export function calculateMetrics(results: ScenarioResult[]): EvaluationMetrics {
  const malicious = results.filter(item => item.malicious);
  const benign = results.filter(item => !item.malicious);
  const tp = malicious.filter(item => item.detected).length;
  const fn = malicious.length - tp;
  const fp = benign.filter(item => item.detected).length;
  const tn = benign.length - fp;
  const precisionValue = ratio(tp, tp + fp);
  const recallValue = ratio(tp, tp + fn);
  const latencies = results.map(item => item.latencyMs).sort((a, b) => a - b);
  const memory = results.map(item => Math.max(0, item.memoryDeltaBytes));
  return {
    total: results.length,
    malicious: malicious.length,
    benign: benign.length,
    truePositive: tp,
    falsePositive: fp,
    trueNegative: tn,
    falseNegative: fn,
    attackSuccessRate: wilson(malicious.filter(item => item.attackSucceeded).length, malicious.length),
    precision: wilson(tp, tp + fp),
    recall: wilson(tp, tp + fn),
    f1: precisionValue + recallValue === 0 ? 0 : 2 * precisionValue * recallValue / (precisionValue + recallValue),
    benignCompletionRate: wilson(benign.filter(item => item.outcome === 'ALLOW' || item.overridden).length, benign.length),
    permissionFrequency: wilson(results.filter(item => item.permissionRequested).length, results.length),
    overrideRate: wilson(results.filter(item => item.overridden).length, results.length),
    partialInfluenceRate: wilson(malicious.filter(item => item.partialInfluence).length, malicious.length),
    latencyMs: {
      mean: mean(latencies),
      p50: percentile(latencies, 0.5),
      p95: percentile(latencies, 0.95),
      max: latencies.at(-1) || 0
    },
    memoryDeltaBytes: { mean: mean(memory), max: memory.length ? Math.max(...memory) : 0 }
  };
}

export function wilson(successes: number, total: number): ConfidenceInterval {
  if (total === 0) return { value: 0, low: 0, high: 0, confidence: 0.95 };
  const z = 1.959963984540054;
  const proportion = successes / total;
  const denominator = 1 + z * z / total;
  const center = (proportion + z * z / (2 * total)) / denominator;
  const margin = z * Math.sqrt(proportion * (1 - proportion) / total + z * z / (4 * total * total)) / denominator;
  return {
    value: proportion,
    low: Math.max(0, center - margin),
    high: Math.min(1, center + margin),
    confidence: 0.95
  };
}

function ratio(numerator: number, denominator: number): number {
  return denominator === 0 ? 0 : numerator / denominator;
}

function mean(values: number[]): number {
  return values.length === 0 ? 0 : values.reduce((sum, item) => sum + item, 0) / values.length;
}

function percentile(values: number[], quantile: number): number {
  if (values.length === 0) return 0;
  return values[Math.min(values.length - 1, Math.floor((values.length - 1) * quantile))];
}
