import * as crypto from 'crypto';
import { DataLabel } from '../core/types';

export interface SessionDataFlowState {
  fingerprints: Map<string, Set<DataLabel>>;
  taint: Set<DataLabel>;
}

export interface DataFlowMatch {
  exact: boolean;
  labels: DataLabel[];
}

const CREDENTIAL_PATTERNS = [
  /\b(?:api[_-]?key|access[_-]?token|secret|password|passwd)\s*[:=]\s*["']?[^\s"']{6,}/i,
  /\bsk-(?:live|test|proj)?[-_a-z0-9]{12,}\b/i,
  /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/i
];
const PERSONAL_PATTERN = /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/i;
const FINANCIAL_PATTERN = /\b(?:invoice|account|routing|iban|card)\b|\b\d{4}[- ]\d{4}[- ]\d{4}[- ]\d{4}\b/i;

export function createDataFlowState(): SessionDataFlowState {
  return { fingerprints: new Map(), taint: new Set() };
}

export function recordOutput(
  state: SessionDataFlowState,
  value: unknown,
  inheritedLabels: DataLabel[] = []
): DataLabel[] {
  const strings = extractStrings(value);
  const labels = new Set<DataLabel>(inheritedLabels);
  for (const text of strings) for (const label of classifyText(text)) labels.add(label);
  if (labels.size === 0) labels.add('unknown');
  for (const label of labels) if (label !== 'unknown') state.taint.add(label);
  for (const text of strings) {
    if (text.trim().length < 4) continue;
    state.fingerprints.set(fingerprint(text), new Set(labels));
  }
  return Array.from(labels);
}

export function matchInput(state: SessionDataFlowState, value: unknown): DataFlowMatch {
  const labels = new Set<DataLabel>();
  let exact = false;
  for (const text of extractStrings(value)) {
    const matched = state.fingerprints.get(fingerprint(text));
    if (!matched) continue;
    exact = true;
    for (const label of matched) labels.add(label);
  }
  return { exact, labels: Array.from(labels) };
}

export function coarseTaint(state: SessionDataFlowState): DataLabel[] {
  return Array.from(state.taint);
}

export function classifyText(text: string): DataLabel[] {
  const labels = new Set<DataLabel>();
  if (CREDENTIAL_PATTERNS.some(pattern => pattern.test(text))) {
    labels.add('credential');
    labels.add('sensitive');
  }
  if (PERSONAL_PATTERN.test(text)) {
    labels.add('personal');
    labels.add('sensitive');
  }
  if (FINANCIAL_PATTERN.test(text)) {
    labels.add('financial');
    labels.add('sensitive');
  }
  return Array.from(labels);
}

function extractStrings(value: unknown): string[] {
  const strings: string[] = [];
  const pending = [value];
  const seen = new Set<object>();
  while (pending.length > 0 && strings.length < 2_000) {
    const current = pending.pop();
    if (typeof current === 'string') {
      strings.push(current.normalize('NFKC'));
    } else if (current && typeof current === 'object' && !seen.has(current)) {
      seen.add(current);
      pending.push(...(Array.isArray(current) ? current : Object.values(current as Record<string, unknown>)));
    }
  }
  return strings;
}

function fingerprint(text: string): string {
  return crypto.createHash('sha256').update(text.normalize('NFKC').trim()).digest('hex');
}
