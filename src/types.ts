export interface DownstreamServerConfig {
  name: string;
  command: string;
  args?: string[];
  env?: Record<string, string>;
}

export interface ResourceLimits {
  maxMessageBytes: number;
  maxNestingDepth: number;
  requestTimeoutMs: number;
  approvalTimeoutMs: number;
}

export interface ToolBaseline {
  name: string;
  description: string;
  inputSchema: any;
  hash: string;
  category: string;
  approved: boolean;
  firstSeen: string;
  lastSeen: string;
}

export interface AuditLog {
  id: string;
  timestamp: string;
  serverName: string;
  toolName: string;
  category: string;
  arguments: any;
  status: 'allow' | 'block' | 'pending';
  reason?: string;
  drift?: boolean;
  promptInjection?: boolean;
  isCategoryTransitionViolation?: boolean;
  sessionId?: string;
}

export interface GuardianConfig {
  servers: DownstreamServerConfig[];
  forbiddenTransitions: [string, string][];
  geminiApiKey?: string;
  autoApproveSafe: boolean;
  resourceLimits?: Partial<ResourceLimits>;
}

// WebSocket Message Types
export type ExtensionMessage =
  | { type: 'approve_response'; id: string; approved: boolean }
  | { type: 'update_config'; config: GuardianConfig }
  | { type: 'approve_drift'; serverName: string; toolName: string; newHash: string }
  | { type: 'set_category'; serverName: string; toolName: string; category: string }
  | { type: 'request_state' };

export type ProxyMessage =
  | { type: 'proxy_started'; pid: number; port: number }
  | { type: 'downstream_status'; serverName: string; status: 'connected' | 'disconnected' | 'error'; error?: string }
  | { type: 'log'; log: AuditLog }
  | { type: 'approve_request'; id: string; serverName: string; toolName: string; arguments: any; reason: string; driftDetails?: { oldHash?: string; newHash: string } }
  | { type: 'sync_state'; baselines: Record<string, Record<string, ToolBaseline>>; logs: AuditLog[]; config: GuardianConfig };
