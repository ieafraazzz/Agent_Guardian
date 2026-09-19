import { EvaluationConfiguration, EvaluationLayer } from './types';

const all = layerState(true);
const none = layerState(false);

export const EVALUATION_CONFIGURATIONS: EvaluationConfiguration[] = [
  { id: 'no_guardian', label: 'No Guardian', layers: none, lanes: { mcp: true, browser: true } },
  ...(['integrity', 'semantic', 'behavior', 'intent', 'provenance'] as EvaluationLayer[]).map(layer => ({
    id: `${layer}_only`,
    label: `${capitalize(layer)} only`,
    layers: { ...none, [layer]: true },
    lanes: { mcp: true, browser: true }
  })),
  { id: 'full', label: 'Full Guardian', layers: all, lanes: { mcp: true, browser: true } },
  ...(['integrity', 'semantic', 'behavior', 'intent', 'provenance'] as EvaluationLayer[]).map(layer => ({
    id: `full_minus_${layer}`,
    label: `Full minus ${capitalize(layer)}`,
    layers: { ...all, [layer]: false },
    lanes: { mcp: true, browser: true }
  })),
  { id: 'mcp_only', label: 'MCP lane only', layers: all, lanes: { mcp: true, browser: false } },
  { id: 'browser_only', label: 'Browser lane only', layers: all, lanes: { mcp: false, browser: true } }
];

function layerState(value: boolean): Record<EvaluationLayer, boolean> {
  return { integrity: value, semantic: value, behavior: value, intent: value, provenance: value };
}

function capitalize(value: string): string {
  return value.charAt(0).toUpperCase() + value.slice(1);
}
