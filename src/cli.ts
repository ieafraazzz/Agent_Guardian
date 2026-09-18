import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { GuardianDb } from './db';
import { parseAuditExport, ReportFormat, serializeReport, verifyAuditExport } from './reporting';

export const EXIT_OK = 0;
export const EXIT_USAGE = 2;
export const EXIT_INTEGRITY = 3;
export const EXIT_IO = 4;

function main(args = process.argv.slice(2)): number {
  try {
    if (args.includes('--help') || args.length === 0) {
      process.stdout.write(help());
      return EXIT_OK;
    }
    const [command, operation] = args;
    if (command !== 'report') return usage(`Unknown command '${command}'`);
    if (operation === 'export') return exportReport(args.slice(2));
    if (operation === 'verify') return verifyReport(args.slice(2));
    return usage(`Unknown report operation '${operation || ''}'`);
  } catch (error) {
    process.stderr.write(`Agent Guardian: ${error instanceof Error ? error.message : String(error)}\n`);
    return EXIT_IO;
  }
}

function exportReport(args: string[]): number {
  const format = option(args, '--format') as ReportFormat | undefined;
  const output = option(args, '--out');
  const storage = option(args, '--storage') || process.env.MCP_GUARDIAN_STORAGE_PATH || path.join(os.homedir(), '.mcp-guardian');
  if (!format || !['json', 'jsonl', 'sarif'].includes(format)) return usage('Use --format json, jsonl, or sarif');
  if (!output) return usage('Missing --out path');
  const database = new GuardianDb(path.resolve(storage));
  fs.writeFileSync(path.resolve(output), serializeReport(database.getLogs(), format), 'utf8');
  process.stdout.write(`Exported ${database.getLogs().length} audit entries to ${path.resolve(output)}\n`);
  return EXIT_OK;
}

function verifyReport(args: string[]): number {
  const input = option(args, '--input');
  if (!input) return usage('Missing --input path');
  const records = parseAuditExport(fs.readFileSync(path.resolve(input), 'utf8'));
  if (!verifyAuditExport(records)) {
    process.stderr.write('Audit integrity verification failed\n');
    return EXIT_INTEGRITY;
  }
  process.stdout.write(`Audit integrity verified (${records.length} records)\n`);
  return EXIT_OK;
}

function option(args: string[], name: string): string | undefined {
  const index = args.indexOf(name);
  return index >= 0 ? args[index + 1] : undefined;
}

function usage(message: string): number {
  process.stderr.write(`${message}\n\n${help()}`);
  return EXIT_USAGE;
}

function help(): string {
  return [
    'Agent Guardian reporting CLI',
    '',
    '  agent-guardian report export --format json|jsonl|sarif --out <file> [--storage <directory>]',
    '  agent-guardian report verify --input <json-or-jsonl-file>',
    '',
    `Exit codes: ${EXIT_OK}=success, ${EXIT_USAGE}=usage, ${EXIT_INTEGRITY}=integrity failure, ${EXIT_IO}=I/O failure`,
    ''
  ].join('\n');
}

process.exitCode = main();
