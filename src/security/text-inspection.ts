import * as crypto from 'crypto';
import { Evidence, EvidenceSeverity } from '../core/types';

export interface TextView {
  original: string;
  normalized: string;
  zeroWidthCount: number;
  bidiControlCount: number;
  confusableCount: number;
  changedByNormalization: boolean;
}

export interface StructuredInspection {
  evidence: Evidence[];
  stringsInspected: number;
  truncated: boolean;
}

const ZERO_WIDTH = /[\u200B-\u200F\u2060\uFEFF]/g;
const BIDI_CONTROLS = /[\u202A-\u202E\u2066-\u2069]/g;
const CONFUSABLES: Record<string, string> = {
  '\u0430': 'a', '\u0435': 'e', '\u043E': 'o', '\u0440': 'p', '\u0441': 'c', '\u0445': 'x',
  '\u0456': 'i', '\u04CF': 'l', '\u0501': 'd', '\u051B': 'q',
  '\u0391': 'A', '\u0392': 'B', '\u0395': 'E', '\u0397': 'H', '\u0399': 'I', '\u039A': 'K',
  '\u039C': 'M', '\u039D': 'N', '\u039F': 'O', '\u03A1': 'P', '\u03A4': 'T', '\u03A7': 'X',
  '\u03BF': 'o', '\u03C1': 'p', '\u03BD': 'v'
};
const CONFUSABLE_PATTERN = new RegExp(`[${Object.keys(CONFUSABLES).join('')}]`, 'g');

const INJECTION_PATTERNS: Array<{ id: string; severity: EvidenceSeverity; pattern: RegExp; message: string }> = [
  { id: 'PI_IGNORE', severity: 'high', pattern: /\bignore\s+(?:previous|above|all|system)\s+(?:instructions|directives|prompts|commands|rules)\b/i, message: 'Instruction attempts to override prior guidance' },
  { id: 'PI_SECRET_SIDE_EFFECT', severity: 'critical', pattern: /\b(?:secretly|silently)\s+(?:send|email|exfiltrate|upload|post|write|save)\b/i, message: 'Instruction requests a concealed side effect' },
  { id: 'PI_USER_DECEPTION', severity: 'high', pattern: /\bdo\s+not\s+(?:tell|inform|notify)\s+the\s+user\b/i, message: 'Instruction attempts to hide behavior from the user' },
  { id: 'PI_SYSTEM_OVERRIDE', severity: 'high', pattern: /\b(?:system\s+override|hidden\s+instruction|disobey\s+the\s+user)\b/i, message: 'Instruction claims unauthorized control priority' },
  { id: 'PI_EXFILTRATION', severity: 'critical', pattern: /\b(?:exfiltrate|steal|leak)\b.{0,80}\b(?:secret|credential|token|password|key|file|data)\b/i, message: 'Instruction describes sensitive-data exfiltration' },
  { id: 'PI_ACTIVE_MARKUP', severity: 'high', pattern: /<\/?script\b|style\s*=\s*['"][^'"]*(?:display\s*:\s*none|opacity\s*:\s*0)/i, message: 'Active or hidden markup may carry an injection' }
];

export function createTextView(text: string): TextView {
  const zeroWidthCount = (text.match(ZERO_WIDTH) || []).length;
  const bidiControlCount = (text.match(BIDI_CONTROLS) || []).length;
  const confusableCount = (text.match(CONFUSABLE_PATTERN) || []).length;
  const normalized = text
    .normalize('NFKC')
    .replace(ZERO_WIDTH, '')
    .replace(BIDI_CONTROLS, '')
    .replace(CONFUSABLE_PATTERN, character => CONFUSABLES[character] || character);
  return {
    original: text,
    normalized,
    zeroWidthCount,
    bidiControlCount,
    confusableCount,
    changedByNormalization: normalized !== text
  };
}

export function inspectStructuredText(
  value: unknown,
  detectorId: string,
  eventId: string,
  maxStrings = 2_000
): StructuredInspection {
  const evidence: Evidence[] = [];
  const pending: Array<{ value: unknown; path: string }> = [{ value, path: '$' }];
  let stringsInspected = 0;
  let truncated = false;

  while (pending.length > 0) {
    const current = pending.pop()!;
    if (typeof current.value === 'string') {
      if (stringsInspected >= maxStrings) {
        truncated = true;
        continue;
      }
      stringsInspected += 1;
      evidence.push(...inspectOneText(current.value, current.path, detectorId, eventId));
      continue;
    }
    if (Array.isArray(current.value)) {
      current.value.forEach((item, index) => pending.push({ value: item, path: `${current.path}[${index}]` }));
      continue;
    }
    if (current.value && typeof current.value === 'object') {
      for (const [key, item] of Object.entries(current.value as Record<string, unknown>)) {
        pending.push({ value: item, path: `${current.path}.${key}` });
        pending.push({ value: key, path: `${current.path}::<key>` });
      }
    }
  }

  return { evidence: deduplicateEvidence(evidence), stringsInspected, truncated };
}

function inspectOneText(text: string, path: string, detectorId: string, eventId: string): Evidence[] {
  const view = createTextView(text);
  const findings: Evidence[] = [];
  if (view.zeroWidthCount > 0 || view.bidiControlCount > 0 || view.confusableCount > 0) {
    findings.push(evidence(detectorId, 'UNICODE_OBFUSCATION', 'R9', 'high', 0.95,
      `Unicode obfuscation detected at ${path}`, eventId, path, {
        zeroWidthCount: view.zeroWidthCount,
        bidiControlCount: view.bidiControlCount,
        confusableCount: view.confusableCount
      }));
  }
  for (const rule of INJECTION_PATTERNS) {
    if (rule.pattern.test(view.normalized)) {
      findings.push(evidence(detectorId, rule.id, undefined, rule.severity, 0.9,
        `${rule.message} at ${path}`, eventId, path));
    }
  }
  return findings;
}

function evidence(
  detectorId: string,
  code: string,
  ruleId: string | undefined,
  severity: EvidenceSeverity,
  confidence: number,
  message: string,
  eventId: string,
  path: string,
  metadata?: Record<string, unknown>
): Evidence {
  return {
    id: crypto.createHash('sha256').update(`${detectorId}\0${code}\0${eventId}\0${path}\0${message}`).digest('hex'),
    detectorId,
    detectorVersion: '1.0.0',
    ruleId,
    severity,
    confidence,
    message,
    eventIds: [eventId],
    provenance: { lane: 'mcp', path },
    metadata: { code, path, ...(metadata || {}) }
  };
}

function deduplicateEvidence(findings: Evidence[]): Evidence[] {
  return Array.from(new Map(findings.map(finding => [finding.id, finding])).values());
}
