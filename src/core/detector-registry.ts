import * as crypto from 'crypto';
import { CompletenessLedger } from './completeness-ledger';
import { Detector, DetectorContext, Evidence } from './types';

export interface DetectorRun {
  evidence: Evidence[];
  ledger: CompletenessLedger;
}

export class DetectorRegistry {
  private readonly detectors = new Map<string, Detector>();

  register(detector: Detector): void {
    if (!detector.id.trim()) {
      throw new Error('Detector id must not be empty');
    }
    if (this.detectors.has(detector.id)) {
      throw new Error(`Detector '${detector.id}' is already registered`);
    }
    this.detectors.set(detector.id, detector);
  }

  list(): readonly Detector[] {
    return Array.from(this.detectors.values());
  }

  async run(context: DetectorContext): Promise<DetectorRun> {
    const ledger = new CompletenessLedger();
    const evidence: Evidence[] = [];

    for (const detector of this.detectors.values()) {
      const startedAt = new Date().toISOString();
      if (!detector.supports(context.event)) {
        ledger.record({
          analyzerId: detector.id,
          subject: context.event.id,
          outcome: 'out_of_scope',
          startedAt,
          finishedAt: new Date().toISOString(),
          reason: 'Detector does not support this event type'
        });
        continue;
      }

      try {
        const result = await detector.analyze(context);
        evidence.push(...result.evidence.map(item => normalizeEvidence(item, detector)));
        ledger.record({
          analyzerId: detector.id,
          subject: context.event.id,
          outcome: 'completed',
          startedAt,
          finishedAt: new Date().toISOString()
        });
      } catch (error) {
        ledger.record({
          analyzerId: detector.id,
          subject: context.event.id,
          outcome: 'failed',
          startedAt,
          finishedAt: new Date().toISOString(),
          reason: error instanceof Error ? error.message : 'Unknown detector failure'
        });
      }
    }

    return { evidence, ledger };
  }
}

function normalizeEvidence(evidence: Evidence, detector: Detector): Evidence {
  if (evidence.confidence < 0 || evidence.confidence > 1) {
    throw new Error(`Detector '${detector.id}' emitted confidence outside 0..1`);
  }
  return {
    ...evidence,
    id: evidence.id || crypto.randomUUID(),
    detectorId: detector.id,
    detectorVersion: detector.version
  };
}
