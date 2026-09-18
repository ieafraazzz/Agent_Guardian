import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import { Evidence } from '../core/types';

export interface AcceptedRiskEntry {
  fingerprint: string;
  reason: string;
  acceptedAt: string;
  expiresAt?: string;
}

export class AcceptedRiskStore {
  private readonly filePath: string;
  private entries: AcceptedRiskEntry[];

  constructor(storagePath: string) {
    this.filePath = path.join(storagePath, 'accepted-risks.json');
    this.entries = this.load();
  }

  isAccepted(evidence: Evidence): boolean {
    const fingerprint = evidenceFingerprint(evidence);
    const now = Date.now();
    return this.entries.some(entry =>
      entry.fingerprint === fingerprint &&
      entry.reason.trim().length > 0 &&
      (!entry.expiresAt || Date.parse(entry.expiresAt) > now)
    );
  }

  add(evidence: Evidence, reason: string, expiresAt?: string): AcceptedRiskEntry {
    if (!reason.trim()) throw new Error('Accepted-risk reason must not be empty');
    const entry = {
      fingerprint: evidenceFingerprint(evidence),
      reason: reason.trim(),
      acceptedAt: new Date().toISOString(),
      ...(expiresAt ? { expiresAt } : {})
    };
    this.entries = [entry, ...this.entries.filter(item => item.fingerprint !== entry.fingerprint)];
    fs.mkdirSync(path.dirname(this.filePath), { recursive: true });
    fs.writeFileSync(this.filePath, JSON.stringify({ version: 1, entries: this.entries }, null, 2));
    return entry;
  }

  private load(): AcceptedRiskEntry[] {
    try {
      const parsed = JSON.parse(fs.readFileSync(this.filePath, 'utf8'));
      return Array.isArray(parsed.entries) ? parsed.entries : [];
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT') {
        console.error('[MCP-Guardian] Failed to load accepted risks:', error);
      }
      return [];
    }
  }
}

export function evidenceFingerprint(evidence: Evidence): string {
  const identity = JSON.stringify({
    detectorId: evidence.detectorId,
    detectorVersion: evidence.detectorVersion,
    ruleId: evidence.ruleId,
    message: evidence.message,
    provenance: evidence.provenance,
    metadata: evidence.metadata
  });
  return crypto.createHash('sha256').update(identity).digest('hex');
}
