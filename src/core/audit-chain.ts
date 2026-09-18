import * as crypto from 'crypto';
import { AuditPayload, HashChainedAuditRecord } from './types';

const GENESIS_HASH = '0'.repeat(64);

export class HashChainedAuditTrail {
  private readonly records: HashChainedAuditRecord[] = [];

  append(payload: AuditPayload, timestamp = new Date().toISOString()): HashChainedAuditRecord {
    const sequence = this.records.length;
    const previousHash = sequence === 0 ? GENESIS_HASH : this.records[sequence - 1].hash;
    const unsigned = { sequence, timestamp, previousHash, payload };
    const record: HashChainedAuditRecord = {
      ...unsigned,
      hash: hashCanonical(unsigned)
    };
    this.records.push(record);
    return structuredClone(record);
  }

  list(): readonly HashChainedAuditRecord[] {
    return structuredClone(this.records);
  }

  verify(): boolean {
    return HashChainedAuditTrail.verify(this.records);
  }

  toJSONL(): string {
    return this.records.map(record => JSON.stringify(record)).join('\n') + (this.records.length > 0 ? '\n' : '');
  }

  static parseJSONL(content: string): HashChainedAuditRecord[] {
    return content
      .split(/\r?\n/)
      .filter(line => line.trim().length > 0)
      .map((line, index) => {
        try {
          return JSON.parse(line) as HashChainedAuditRecord;
        } catch (error) {
          throw new Error(`Invalid audit JSONL at line ${index + 1}`, { cause: error });
        }
      });
  }

  static verify(records: readonly HashChainedAuditRecord[]): boolean {
    for (let index = 0; index < records.length; index += 1) {
      const record = records[index];
      const expectedPrevious = index === 0 ? GENESIS_HASH : records[index - 1].hash;
      if (record.sequence !== index || record.previousHash !== expectedPrevious) return false;
      const { hash, ...unsigned } = record;
      if (hash !== hashCanonical(unsigned)) return false;
    }
    return true;
  }
}

export function canonicalize(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value && typeof value === 'object') {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>)
        .sort(([left], [right]) => left.localeCompare(right))
        .map(([key, item]) => [key, canonicalize(item)])
    );
  }
  return value;
}

function hashCanonical(value: unknown): string {
  return crypto.createHash('sha256').update(JSON.stringify(canonicalize(value))).digest('hex');
}
