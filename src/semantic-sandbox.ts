import * as path from 'path';
import { spawn } from 'child_process';

export interface SemanticScanResult {
  suspicious: boolean;
  reason?: string;
  complete: boolean;
  llmUsed: boolean;
}

export function scanSemanticSandboxed(
  toolName: string,
  content: string,
  apiKey: string,
  timeoutMs = 4_000
): Promise<SemanticScanResult> {
  if (!apiKey) return Promise.resolve({ suspicious: false, complete: true, llmUsed: false });
  const workerPath = path.join(__dirname, 'semantic-worker.js');
  return new Promise(resolve => {
    const child = spawn(process.execPath, [workerPath], {
      stdio: ['pipe', 'pipe', 'ignore'],
      shell: false,
      windowsHide: true,
      env: {
        PATH: process.env.PATH || '',
        SystemRoot: process.env.SystemRoot || '',
        WINDIR: process.env.WINDIR || ''
      }
    });
    let output = '';
    let settled = false;
    const finish = (result: SemanticScanResult) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (child.exitCode === null) child.kill();
      resolve(result);
    };
    const timer = setTimeout(() => finish({
      suspicious: false,
      reason: 'Semantic scan timed out',
      complete: false,
      llmUsed: true
    }), timeoutMs);
    child.stdout.on('data', chunk => {
      output += chunk.toString();
      if (output.length > 64_000) finish({
        suspicious: false,
        reason: 'Semantic worker output exceeded limit',
        complete: false,
        llmUsed: true
      });
    });
    child.once('error', error => finish({
      suspicious: false,
      reason: `Semantic worker failed: ${error.message}`,
      complete: false,
      llmUsed: true
    }));
    child.once('close', code => {
      if (settled) return;
      try {
        const parsed = JSON.parse(output.trim());
        finish({
          suspicious: Boolean(parsed.suspicious),
          reason: typeof parsed.reason === 'string' ? parsed.reason : undefined,
          complete: code === 0 && parsed.complete !== false,
          llmUsed: true
        });
      } catch {
        finish({
          suspicious: false,
          reason: 'Semantic worker returned invalid structured output',
          complete: false,
          llmUsed: true
        });
      }
    });
    child.stdin.end(JSON.stringify({ toolName, content, apiKey }));
  });
}
