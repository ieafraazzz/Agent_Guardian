import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import { canonicalize } from '../core/audit-chain';
import { DataLabel, Decision, Evidence, SecurityEvent } from '../core/types';

export interface CrossSurfaceRecord {
  sequence: number;
  previousHash: string;
  event: SecurityEvent;
  evidence: Evidence[];
  fingerprints: string[];
  decision?: Decision;
  hash: string;
}

export interface BrowserInfluence {
  influenced: boolean;
  exact: boolean;
  labels: DataLabel[];
  sourceEventIds: string[];
  evidence: Evidence[];
}

export class CrossSurfaceStore {
  private readonly filePath: string;

  constructor(storagePath: string) {
    fs.mkdirSync(storagePath, { recursive: true });
    this.filePath = path.join(storagePath, 'cross-surface-events.jsonl');
  }

  append(record: Omit<CrossSurfaceRecord, 'sequence' | 'previousHash' | 'hash'>): CrossSurfaceRecord {
    const records = this.readAndVerify();
    const sequence = records.length;
    const previousHash = sequence === 0 ? '0'.repeat(64) : records[sequence - 1].hash;
    const unsigned = { sequence, previousHash, ...record };
    const sealed = { ...unsigned, hash: hashRecord(unsigned) };
    fs.appendFileSync(this.filePath, `${JSON.stringify(sealed)}\n`, 'utf8');
    return sealed;
  }

  list(sessionId?: string, maximum = 1_000): CrossSurfaceRecord[] {
    try {
      return this.readAndVerify()
        .filter(record => !sessionId || record.event.sessionId === sessionId)
        .slice(-maximum);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') return [];
      throw error;
    }
  }

  private readAndVerify(): CrossSurfaceRecord[] {
    if (!fs.existsSync(this.filePath)) return [];
    const lines = fs.readFileSync(this.filePath, 'utf8').split(/\r?\n/).filter(Boolean);
    const records = lines.map((line, index) => {
      try { return JSON.parse(line) as CrossSurfaceRecord; }
      catch { throw new Error(`Cross-surface trace is invalid at line ${index + 1}`); }
    });
    for (let index = 0; index < records.length; index += 1) {
      const record = records[index];
      const expectedPrevious = index === 0 ? '0'.repeat(64) : records[index - 1].hash;
      const { hash, ...unsigned } = record;
      if (record.sequence !== index || record.previousHash !== expectedPrevious || hash !== hashRecord(unsigned)) {
        throw new Error(`Cross-surface trace integrity failed at sequence ${index}`);
      }
    }
    return records;
  }

  matchBrowserInfluence(sessionId: string, value: unknown, maximumAgeMs = 5 * 60_000): BrowserInfluence {
    const cutoff = Date.now() - maximumAgeMs;
    const records = this.list(sessionId).filter(record =>
      record.event.lane === 'browser' &&
      record.event.kind === 'observation' &&
      Date.parse(record.event.timestamp) >= cutoff
    );
    const inputFingerprints = new Set(extractStrings(value).map(fingerprint));
    const exactRecords = records.filter(record => record.fingerprints.some(item => inputFingerprints.has(item)));
    const untrusted = records.filter(record => record.event.dataLabels.includes('untrusted'));
    const sources = exactRecords.length > 0 ? exactRecords : untrusted;
    return {
      influenced: sources.length > 0,
      exact: exactRecords.length > 0,
      labels: Array.from(new Set(sources.flatMap(record => record.event.dataLabels))),
      sourceEventIds: sources.map(record => record.event.id),
      evidence: sources.flatMap(record => record.evidence)
    };
  }
}

export function fingerprintsFor(value: unknown): string[] {
  return Array.from(new Set(extractStrings(value)
    .filter(text => text.trim().length >= 4)
    .map(fingerprint)));
}

function extractStrings(value: unknown): string[] {
  const output: string[] = [];
  const pending = [value];
  const seen = new Set<object>();
  while (pending.length > 0 && output.length < 2_000) {
    const current = pending.pop();
    if (typeof current === 'string') output.push(current.normalize('NFKC').trim());
    else if (current && typeof current === 'object' && !seen.has(current)) {
      seen.add(current);
      pending.push(...(Array.isArray(current) ? current : Object.values(current as Record<string, unknown>)));
    }
  }
  return output;
}

function fingerprint(value: string): string {
  return crypto.createHash('sha256').update(value.normalize('NFKC').trim()).digest('hex');
}

function hashRecord(value: unknown): string {
  return crypto.createHash('sha256').update(JSON.stringify(canonicalize(value))).digest('hex');
}
