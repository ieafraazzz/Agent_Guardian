import * as crypto from 'crypto';
import { canonicalize } from '../core/audit-chain';
import { SchemaDifference, ToolDefinitionSnapshot } from '../types';

const VOLATILE_KEYS = new Set(['lastUpdated', 'updatedAt', 'generatedAt', 'requestId', 'sessionId']);

export function snapshotTool(tool: any): ToolDefinitionSnapshot {
  return canonicalize({
    name: String(tool?.name || ''),
    ...(tool?.title === undefined ? {} : { title: tool.title }),
    description: String(tool?.description || ''),
    inputSchema: tool?.inputSchema || {},
    ...(tool?.outputSchema === undefined ? {} : { outputSchema: tool.outputSchema }),
    ...(tool?.annotations === undefined ? {} : { annotations: tool.annotations }),
    ...(tool?._meta === undefined ? {} : { metadata: removeVolatile(tool._meta) })
  }) as ToolDefinitionSnapshot;
}

export function fingerprintTool(snapshot: ToolDefinitionSnapshot): string {
  return crypto.createHash('sha256').update(JSON.stringify(canonicalize(snapshot))).digest('hex');
}

export function diffToolDefinitions(
  trusted: ToolDefinitionSnapshot,
  observed: ToolDefinitionSnapshot,
  maxEntries = 100
): { differences: SchemaDifference[]; truncated: boolean } {
  const differences: SchemaDifference[] = [];
  const pending: Array<{ before: unknown; after: unknown; path: string }> = [
    { before: trusted, after: observed, path: '$' }
  ];
  let truncated = false;

  while (pending.length > 0) {
    if (differences.length >= maxEntries) {
      truncated = true;
      break;
    }
    const current = pending.pop()!;
    if (Object.is(current.before, current.after)) continue;
    if (!isObject(current.before) || !isObject(current.after) || Array.isArray(current.before) !== Array.isArray(current.after)) {
      differences.push({ path: current.path, kind: 'changed', before: current.before, after: current.after });
      continue;
    }
    const beforeObject = current.before as Record<string, unknown>;
    const afterObject = current.after as Record<string, unknown>;
    const keys = new Set([...Object.keys(beforeObject), ...Object.keys(afterObject)]);
    for (const key of Array.from(keys).sort().reverse()) {
      const childPath = Array.isArray(current.before) ? `${current.path}[${key}]` : `${current.path}.${key}`;
      if (!(key in beforeObject)) differences.push({ path: childPath, kind: 'added', after: afterObject[key] });
      else if (!(key in afterObject)) differences.push({ path: childPath, kind: 'removed', before: beforeObject[key] });
      else pending.push({ before: beforeObject[key], after: afterObject[key], path: childPath });
      if (differences.length >= maxEntries) break;
    }
  }
  return { differences, truncated };
}

function removeVolatile(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(removeVolatile);
  if (!isObject(value)) return value;
  return Object.fromEntries(
    Object.entries(value)
      .filter(([key]) => !VOLATILE_KEYS.has(key))
      .map(([key, item]) => [key, removeVolatile(item)])
  );
}

function isObject(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === 'object';
}
