import * as crypto from 'crypto';
import { canonicalize } from './core/audit-chain';
import { sanitizeForDisplay } from './approval';
import { AuditLog } from './types';

export type ReportFormat = 'json' | 'jsonl' | 'sarif';

export interface AuditExportRecord {
  sequence: number;
  timestamp: string;
  previousHash: string;
  log: AuditLog;
  hash: string;
}

const GENESIS_HASH = '0'.repeat(64);

export function buildAuditExport(logs: AuditLog[]): AuditExportRecord[] {
  const ordered = [...logs].sort((left, right) =>
    left.timestamp.localeCompare(right.timestamp) || left.id.localeCompare(right.id)
  );
  const records: AuditExportRecord[] = [];
  for (const [sequence, log] of ordered.entries()) {
    const previousHash = sequence === 0 ? GENESIS_HASH : records[sequence - 1].hash;
    const safeLog = { ...log, arguments: sanitizeForDisplay(log.arguments) } as AuditLog;
    const unsigned = { sequence, timestamp: log.timestamp, previousHash, log: safeLog };
    records.push({ ...unsigned, hash: hash(unsigned) });
  }
  return records;
}

export function verifyAuditExport(records: AuditExportRecord[]): boolean {
  for (let index = 0; index < records.length; index += 1) {
    const record = records[index];
    const expectedPrevious = index === 0 ? GENESIS_HASH : records[index - 1].hash;
    if (record.sequence !== index || record.previousHash !== expectedPrevious) return false;
    const { hash: actual, ...unsigned } = record;
    if (actual !== hash(unsigned)) return false;
  }
  return true;
}

export function serializeReport(logs: AuditLog[], format: ReportFormat): string {
  const records = buildAuditExport(logs);
  if (format === 'jsonl') return records.map(record => JSON.stringify(record)).join('\n') + (records.length ? '\n' : '');
  if (format === 'sarif') return JSON.stringify(toSarif(records), null, 2);
  return JSON.stringify({ version: 1, generatedAt: new Date().toISOString(), records }, null, 2);
}

export function parseAuditExport(content: string): AuditExportRecord[] {
  const trimmed = content.trim();
  if (!trimmed) return [];
  try {
    const parsed = JSON.parse(trimmed);
    if (Array.isArray(parsed.records)) return parsed.records;
    if (typeof parsed.sequence === 'number' && typeof parsed.hash === 'string') return [parsed];
  } catch {
    // Multiple JSONL records are intentionally not one valid JSON document.
  }
  return trimmed.split(/\r?\n/).filter(Boolean).map(line => JSON.parse(line));
}

function toSarif(records: AuditExportRecord[]): unknown {
  const rules = new Map<string, { id: string; shortDescription: { text: string } }>();
  const results: unknown[] = [];
  for (const record of records) {
    for (const finding of record.log.evidence || []) {
      const ruleId = finding.ruleId || finding.detectorId;
      rules.set(ruleId, { id: ruleId, shortDescription: { text: sanitizeText(finding.message) } });
      results.push({
        ruleId,
        level: finding.severity === 'critical' || finding.severity === 'high' ? 'error'
          : finding.severity === 'medium' ? 'warning' : 'note',
        message: { text: sanitizeText(finding.message) },
        properties: {
          auditSequence: record.sequence,
          serverName: record.log.serverName,
          toolName: record.log.toolName,
          decision: record.log.status,
          evidenceId: finding.id
        }
      });
    }
  }
  return {
    version: '2.1.0',
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    runs: [{ tool: { driver: { name: 'Agent Guardian', rules: Array.from(rules.values()) } }, results }]
  };
}

function hash(value: unknown): string {
  return crypto.createHash('sha256').update(JSON.stringify(canonicalize(value))).digest('hex');
}

function sanitizeText(value: unknown): string {
  return String(sanitizeForDisplay(value));
}
