import { DecisionOutcome, Evidence } from '../core/types';

export type EvaluationLayer = 'integrity' | 'semantic' | 'behavior' | 'intent' | 'provenance';
export type ScenarioLane = 'mcp' | 'browser' | 'cross';
export type ScenarioKind =
  | 'text'
  | 'tool_drift'
  | 'unknown_tool'
  | 'behavior_chain'
  | 'intent_scope'
  | 'data_flow'
  | 'browser_action'
  | 'cross_surface'
  | 'benign';

export interface EvaluationScenario {
  id: string;
  title: string;
  split: 'development' | 'held_out';
  lane: ScenarioLane;
  kind: ScenarioKind;
  malicious: boolean;
  tags: string[];
  source: string;
  input: Record<string, unknown>;
  expected: {
    fullOutcome: DecisionOutcome;
    attackerGoal?: string;
    partialInfluence?: boolean;
  };
}

export interface EvaluationConfiguration {
  id: string;
  label: string;
  layers: Record<EvaluationLayer, boolean>;
  lanes: { mcp: boolean; browser: boolean };
}

export interface ScenarioResult {
  scenarioId: string;
  configurationId: string;
  split: EvaluationScenario['split'];
  lane: ScenarioLane;
  malicious: boolean;
  expectedOutcome: DecisionOutcome;
  outcome: DecisionOutcome;
  detected: boolean;
  attackSucceeded: boolean;
  partialInfluence: boolean;
  permissionRequested: boolean;
  overridden: boolean;
  matchedRuleIds: string[];
  evidence: Evidence[];
  latencyMs: number;
  memoryDeltaBytes: number;
  error?: string;
}

export interface ConfidenceInterval {
  value: number;
  low: number;
  high: number;
  confidence: 0.95;
}

export interface EvaluationMetrics {
  total: number;
  malicious: number;
  benign: number;
  truePositive: number;
  falsePositive: number;
  trueNegative: number;
  falseNegative: number;
  attackSuccessRate: ConfidenceInterval;
  precision: ConfidenceInterval;
  recall: ConfidenceInterval;
  f1: number;
  benignCompletionRate: ConfidenceInterval;
  permissionFrequency: ConfidenceInterval;
  overrideRate: ConfidenceInterval;
  partialInfluenceRate: ConfidenceInterval;
  latencyMs: { mean: number; p50: number; p95: number; max: number };
  memoryDeltaBytes: { mean: number; max: number };
}

export interface EvaluationRun {
  schemaVersion: 1;
  generatedAt: string;
  corpusPath: string;
  corpusSha256: string;
  policyPath: string;
  policySha256: string;
  repetitions: number;
  configurations: Array<{
    configuration: EvaluationConfiguration;
    metrics: EvaluationMetrics;
    heldOutMetrics: EvaluationMetrics;
    results: ScenarioResult[];
  }>;
}
