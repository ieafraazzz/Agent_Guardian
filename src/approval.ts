import * as crypto from 'crypto';
import { canonicalize } from './core/audit-chain';
import { ApprovalRequestView, AuditLog, SessionPolicy } from './types';

const CONTROL_CHARACTERS = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F\u202A-\u202E\u2066-\u2069]/g;
const CREDENTIALS = /\b(api[_-]?key|access[_-]?token|authorization|password|passwd|secret)\b(\s*[:=]\s*)([^\s,;}\]]+)/gi;
const BEARER = /\bBearer\s+[A-Za-z0-9._~+/=-]{8,}/gi;
const SENSITIVE_KEY = /^(?:api[_-]?key|access[_-]?token|authorization|password|passwd|secret|private[_-]?key)$/i;

export interface ExactAction {
  sessionId: string;
  intent: string;
  serverName: string;
  toolName: string;
  capability: string;
  destination?: string;
  arguments: unknown;
  evidenceIds: string[];
}

export function actionFingerprint(action: ExactAction): string {
  return crypto.createHash('sha256')
    .update(JSON.stringify(canonicalize(action)))
    .digest('hex');
}

export function sanitizeDisplayText(value: unknown, maximum = 500): string {
  const text = String(value ?? '')
    .normalize('NFKC')
    .replace(CONTROL_CHARACTERS, '')
    .replace(CREDENTIALS, (_match, name: string, separator: string) => `${name}${separator}[REDACTED]`)
    .replace(BEARER, 'Bearer [REDACTED]');
  return text.length <= maximum ? text : `${text.slice(0, maximum)}…[truncated]`;
}

export function sanitizeForDisplay(value: unknown, maximumDepth = 6, maximumEntries = 100): unknown {
  let entries = 0;
  const visit = (current: unknown, depth: number): unknown => {
    if (typeof current === 'string') return sanitizeDisplayText(current);
    if (current === null || typeof current !== 'object') return current;
    if (depth >= maximumDepth) return '[truncated: maximum depth]';
    if (Array.isArray(current)) {
      return current.slice(0, maximumEntries).map(item => visit(item, depth + 1));
    }
    const output: Record<string, unknown> = {};
    for (const [key, item] of Object.entries(current as Record<string, unknown>)) {
      if (entries >= maximumEntries) {
        output['[truncated]'] = 'maximum entries reached';
        break;
      }
      entries += 1;
      output[sanitizeDisplayText(key, 100)] = SENSITIVE_KEY.test(key)
        ? '[REDACTED]'
        : visit(item, depth + 1);
    }
    return output;
  };
  return visit(value, 0);
}

export function resolveSessionPolicy(meta: unknown, configured?: SessionPolicy): { sessionId: string; policy: SessionPolicy } {
  const fallback: SessionPolicy = configured || { intent: '', allowedCapabilities: [], trustedDestinations: [] };
  const guardian = meta && typeof meta === 'object'
    ? (meta as Record<string, unknown>).guardian
    : undefined;
  const source = guardian && typeof guardian === 'object' ? guardian as Record<string, unknown> : {};
  return {
    sessionId: cleanIdentifier(source.sessionId, 'default'),
    policy: {
      intent: sanitizeDisplayText(typeof source.intent === 'string' ? source.intent : fallback.intent, 500),
      allowedCapabilities: cleanStringArray(source.allowedCapabilities, fallback.allowedCapabilities),
      trustedDestinations: cleanStringArray(source.trustedDestinations, fallback.trustedDestinations)
    }
  };
}

export function inferDestination(argumentsValue: unknown): string | undefined {
  if (!argumentsValue || typeof argumentsValue !== 'object') return undefined;
  const record = argumentsValue as Record<string, unknown>;
  for (const key of ['destination', 'to', 'recipient', 'url', 'uri', 'host']) {
    if (typeof record[key] === 'string' && record[key].trim()) return sanitizeDisplayText(record[key], 300);
  }
  return undefined;
}

export function isTrustedDestination(destination: string, trusted: string[]): boolean {
  const normalized = destination.trim().toLowerCase();
  return trusted.some(item => {
    const candidate = item.trim().toLowerCase();
    if (!candidate) return false;
    if (normalized === candidate) return true;
    if (normalized.includes('@') && candidate.startsWith('@')) return normalized.endsWith(candidate);
    try {
      return new URL(normalized).origin === new URL(candidate).origin;
    } catch {
      return false;
    }
  });
}

export function createApprovalView(
  log: AuditLog,
  policy: SessionPolicy,
  requestedAt: string,
  expiresAt: string
): ApprovalRequestView {
  const exact: ExactAction = {
    sessionId: log.sessionId || 'default',
    intent: policy.intent,
    serverName: log.serverName,
    toolName: log.toolName,
    capability: log.category,
    destination: log.destination,
    arguments: log.arguments,
    evidenceIds: (log.evidence || []).map(item => item.id).sort()
  };
  return {
    id: log.id,
    actionFingerprint: actionFingerprint(exact),
    requestedAt,
    expiresAt,
    sessionId: exact.sessionId,
    intent: sanitizeDisplayText(policy.intent || 'No explicit intent supplied', 500),
    serverName: sanitizeDisplayText(log.serverName, 100),
    toolName: sanitizeDisplayText(log.toolName, 100),
    capability: sanitizeDisplayText(log.category, 100),
    destination: log.destination ? sanitizeDisplayText(log.destination, 300) : undefined,
    reason: sanitizeDisplayText(log.reason || 'Manual confirmation required', 1_000),
    arguments: sanitizeForDisplay(log.arguments),
    evidence: (log.evidence || []).slice(0, 20).map(item => ({
      id: item.id,
      ruleId: item.ruleId,
      severity: item.severity,
      message: sanitizeDisplayText(item.message, 500)
    }))
  };
}

function cleanIdentifier(value: unknown, fallback: string): string {
  if (typeof value !== 'string') return fallback;
  const cleaned = value.normalize('NFKC').replace(/[^A-Za-z0-9._:-]/g, '').slice(0, 128);
  return cleaned || fallback;
}

function cleanStringArray(value: unknown, fallback: string[]): string[] {
  const source = Array.isArray(value) ? value : fallback;
  return source.filter(item => typeof item === 'string').slice(0, 100).map(item => sanitizeDisplayText(item, 300));
}
