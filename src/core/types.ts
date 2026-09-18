export type GuardianLane = 'mcp' | 'browser' | 'system';

export type DataLabel =
  | 'trusted'
  | 'untrusted'
  | 'sensitive'
  | 'credential'
  | 'financial'
  | 'personal'
  | 'unknown';

export type EvidenceSeverity = 'info' | 'low' | 'medium' | 'high' | 'critical';

export type DecisionOutcome = 'ALLOW' | 'ASK' | 'BLOCK';

export interface SecurityEvent {
  id: string;
  sessionId: string;
  timestamp: string;
  lane: GuardianLane;
  kind: string;
  operation: string;
  capability?: string;
  source?: string;
  destination?: string;
  dataLabels: DataLabel[];
  input?: unknown;
  output?: unknown;
  metadata?: Record<string, unknown>;
}

export interface DataFlowEdge {
  id: string;
  sessionId: string;
  sourceEventId: string;
  targetEventId: string;
  labels: DataLabel[];
  match: 'exact-fingerprint' | 'coarse-session-taint';
  fingerprint?: string;
  createdAt: string;
}

export interface GuardianSession {
  id: string;
  intent: string;
  allowedCapabilities: string[];
  trustedDestinations: string[];
  startedAt: string;
  endedAt?: string;
  events: SecurityEvent[];
  dataFlow: DataFlowEdge[];
  taint: DataLabel[];
  metadata?: Record<string, unknown>;
}

export interface Evidence {
  id: string;
  detectorId: string;
  detectorVersion: string;
  ruleId?: string;
  severity: EvidenceSeverity;
  confidence: number;
  message: string;
  eventIds: string[];
  provenance?: {
    lane: GuardianLane;
    source?: string;
    path?: string;
  };
  metadata?: Record<string, unknown>;
}

export interface Decision {
  id: string;
  sessionId: string;
  eventId: string;
  outcome: DecisionOutcome;
  policyId: string;
  matchedRuleIds: string[];
  evidence: Evidence[];
  explanation: string;
  createdAt: string;
  latencyMs: number;
  expiresAt?: string;
  userResponse?: 'approve_once' | 'deny' | 'expired';
}

export type LedgerOutcome = 'completed' | 'partial' | 'skipped' | 'failed' | 'out_of_scope';

export interface InspectionLedgerEntry {
  id: string;
  analyzerId: string;
  subject: string;
  outcome: LedgerOutcome;
  startedAt: string;
  finishedAt: string;
  reason?: string;
  limits?: Record<string, number>;
  observed?: Record<string, number>;
}

export interface InspectionSummary {
  complete: boolean;
  total: number;
  completed: number;
  partial: number;
  skipped: number;
  failed: number;
  outOfScope: number;
  reasons: string[];
}

export interface DetectorContext {
  event: SecurityEvent;
  session: GuardianSession;
}

export interface DetectorResult {
  evidence: Evidence[];
  inspectedSubjects?: string[];
}

export interface Detector {
  readonly id: string;
  readonly version: string;
  supports(event: SecurityEvent): boolean;
  analyze(context: DetectorContext): DetectorResult | Promise<DetectorResult>;
}

export interface PolicyOptions {
  strictUnknownTools?: boolean;
  approvalTtlMs?: number;
}

export interface AuditPayload {
  event: SecurityEvent;
  decision: Decision;
  inspection: InspectionSummary;
}

export interface HashChainedAuditRecord {
  sequence: number;
  timestamp: string;
  previousHash: string;
  payload: AuditPayload;
  hash: string;
}
