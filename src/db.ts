import * as fs from 'fs';
import * as path from 'path';
import { ToolBaseline, AuditLog, GuardianConfig } from './types';

export class GuardianDb {
  private filePath: string;
  private data: {
    baselines: Record<string, Record<string, ToolBaseline>>; // serverName -> toolName -> Baseline
    logs: AuditLog[];
    config: GuardianConfig;
  };

  constructor(storagePath: string) {
    this.filePath = path.join(storagePath, 'mcp-guardian-db.json');
    this.ensureDirectoryExists(storagePath);
    this.data = this.load();
  }

  private ensureDirectoryExists(dir: string) {
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
  }

  private load(): typeof this.data {
    const defaultConfig = {
      servers: [
        {
          name: 'everything',
          command: 'npx',
          args: ['-y', '@modelcontextprotocol/server-everything']
        }
      ],
      forbiddenTransitions: [
        ['READ_LOCAL', 'WRITE_COMMUNICATION'],
        ['READ_FINANCIAL', 'WRITE_COMMUNICATION'],
        ['READ_LOCAL', 'EXECUTE_SYSTEM'],
        ['READ_NETWORK', 'EXECUTE_SYSTEM']
      ] as [string, string][],
      geminiApiKey: '',
      autoApproveSafe: true
    };

    if (fs.existsSync(this.filePath)) {
      try {
        const raw = fs.readFileSync(this.filePath, 'utf-8');
        const parsed = JSON.parse(raw);
        return {
          baselines: parsed.baselines || {},
          logs: parsed.logs || [],
          config: parsed.config || defaultConfig
        };
      } catch (e) {
        console.error('Failed to parse database, using defaults', e);
      }
    }

    const initial = {
      baselines: {},
      logs: [],
      config: defaultConfig
    };
    this.save(initial);
    return initial;
  }

  private save(dataToSave = this.data) {
    try {
      fs.writeFileSync(this.filePath, JSON.stringify(dataToSave, null, 2), 'utf-8');
    } catch (e) {
      console.error('Failed to write database file', e);
    }
  }

  // Configurations
  getConfig(): GuardianConfig {
    return this.data.config;
  }

  updateConfig(config: Partial<GuardianConfig>) {
    this.data.config = { ...this.data.config, ...config };
    this.save();
  }

  // Baselines
  getBaselines(): Record<string, Record<string, ToolBaseline>> {
    return this.data.baselines;
  }

  getToolBaseline(serverName: string, toolName: string): ToolBaseline | undefined {
    return this.data.baselines[serverName]?.[toolName];
  }

  setToolBaseline(serverName: string, toolName: string, baseline: ToolBaseline) {
    if (!this.data.baselines[serverName]) {
      this.data.baselines[serverName] = {};
    }
    this.data.baselines[serverName][toolName] = baseline;
    this.save();
  }

  approveDrift(serverName: string, toolName: string, newHash: string) {
    const baseline = this.getToolBaseline(serverName, toolName);
    if (baseline) {
      baseline.hash = newHash;
      baseline.approved = true;
      baseline.lastSeen = new Date().toISOString();
      this.save();
    }
  }

  setToolCategory(serverName: string, toolName: string, category: string) {
    const baseline = this.getToolBaseline(serverName, toolName);
    if (baseline) {
      baseline.category = category;
      this.save();
    }
  }

  // Logs
  getLogs(): AuditLog[] {
    return this.data.logs;
  }

  addLog(log: AuditLog) {
    const existingIndex = this.data.logs.findIndex(existing => existing.id === log.id);
    if (existingIndex >= 0) {
      this.data.logs[existingIndex] = { ...this.data.logs[existingIndex], ...log };
    } else {
      this.data.logs.unshift(log);
    }
    // Limit to last 500 logs to prevent memory bloat
    if (this.data.logs.length > 500) {
      this.data.logs.pop();
    }
    this.save();
  }

  clearLogs() {
    this.data.logs = [];
    this.save();
  }

  // Full raw state for sync
  getRawState() {
    return this.data;
  }
}
