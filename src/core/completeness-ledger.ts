import * as crypto from 'crypto';
import { InspectionLedgerEntry, InspectionSummary, LedgerOutcome } from './types';

const INCOMPLETE_OUTCOMES = new Set<LedgerOutcome>(['partial', 'skipped', 'failed']);

export class CompletenessLedger {
  private readonly entries: InspectionLedgerEntry[] = [];

  record(entry: Omit<InspectionLedgerEntry, 'id'> & { id?: string }): InspectionLedgerEntry {
    const normalized: InspectionLedgerEntry = {
      ...entry,
      id: entry.id ?? crypto.randomUUID()
    };
    this.entries.push(normalized);
    return normalized;
  }

  list(): readonly InspectionLedgerEntry[] {
    return this.entries.map(entry => ({ ...entry }));
  }

  summarize(): InspectionSummary {
    const count = (outcome: LedgerOutcome) => this.entries.filter(entry => entry.outcome === outcome).length;
    const reasons = Array.from(
      new Set(
        this.entries
          .filter(entry => INCOMPLETE_OUTCOMES.has(entry.outcome))
          .map(entry => entry.reason)
          .filter((reason): reason is string => Boolean(reason))
      )
    );

    return {
      complete: this.entries.length > 0 && !this.entries.some(entry => INCOMPLETE_OUTCOMES.has(entry.outcome)),
      total: this.entries.length,
      completed: count('completed'),
      partial: count('partial'),
      skipped: count('skipped'),
      failed: count('failed'),
      outOfScope: count('out_of_scope'),
      reasons
    };
  }
}
