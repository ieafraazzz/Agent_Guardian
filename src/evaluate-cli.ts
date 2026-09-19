import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { runEvaluation } from './evaluation/runner';
import { runLiveSubset } from './evaluation/live-subset';

async function main(): Promise<number> {
  const args = process.argv.slice(2);
  const root = process.cwd();
  const corpusPath = path.resolve(option(args, '--corpus') || path.join(root, 'evaluation', 'corpus.jsonl'));
  const policyPath = path.resolve(option(args, '--policy') || path.join(root, 'evaluation', 'frozen-policy-v1.json'));
  const outputDirectory = path.resolve(option(args, '--out') || path.join(root, 'evaluation', 'results', 'latest'));
  const repetitions = Number(option(args, '--repetitions') || '1');
  const liveRepetitions = Number(option(args, '--live-repetitions') || '3');
  const storagePath = fs.mkdtempSync(path.join(os.tmpdir(), 'agent-guardian-evaluation-'));
  const run = runEvaluation({ corpusPath, policyPath, outputDirectory, storagePath, repetitions });
  const live = await runLiveSubset(outputDirectory, Math.max(1, Math.min(20, liveRepetitions)));
  const full = run.configurations.find(item => item.configuration.id === 'full');
  if (!full) throw new Error('Full configuration result is missing');
  const mismatches = full.results.filter(item => item.outcome !== item.expectedOutcome || item.error);
  process.stdout.write(`Evaluated ${full.results.length} full-configuration scenario runs across ${run.configurations.length} configurations.\n`);
  process.stdout.write(`Results: ${path.join(outputDirectory, 'summary.md')}\n`);
  process.stdout.write(`Live Chromium subset: ${live.maliciousHeld}/${live.repetitions} attacks held, ${live.benignAllowed}/${live.repetitions} benign runs allowed.\n`);
  if (mismatches.length > 0) {
    process.stderr.write(`Full configuration mismatched ${mismatches.length} expected outcomes: ${mismatches.map(item => item.scenarioId).join(', ')}\n`);
    return 3;
  }
  return 0;
}

function option(args: string[], name: string): string | undefined {
  const index = args.indexOf(name);
  return index >= 0 ? args[index + 1] : undefined;
}

void main().then(code => { process.exitCode = code; }).catch(error => {
  process.stderr.write(`Agent Guardian evaluation failed: ${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 4;
});
