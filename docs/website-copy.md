# Website alignment copy

Use this wording when the deployed project site is updated. It deliberately matches the implemented scope and Phase 6 evidence.

## Hero

**A runtime policy wall for agent interactions with MCP tools and a controlled browser.**

Agent Guardian combines user intent, tool integrity, content provenance, data-flow evidence, and pre-action gates to produce explainable `ALLOW`, `ASK`, or `BLOCK` decisions before supported external side effects.

## What is implemented

- MCP stdio proxy with multi-server routing, bounded processing, schema fingerprints, drift detection, recursive injection scanning, and exact/coarse data-flow tracking.
- Controlled Playwright/Chromium browser with hidden-content comparison, provenance, destination checks, and pre-action gates.
- Cross-surface Browser-to-MCP rules for untrusted content influencing communication or system execution.
- Exact, expiring, one-time approvals plus JSON, JSONL, and SARIF audit exports.
- VS Code dashboard for intent, evidence, ordered interaction timeline, pending permissions, outcomes, and trace-integrity status.
- Reproducible 25-case research corpus with ablation configurations and a smaller live Chromium subset.

## Measured result

On the repository's frozen 25-case synthetic corpus, the full configuration recorded 100% precision, 100% recall, and 100% benign completion. Its reported 5.3% attack-success rate comes from the evaluation's explicit simulated user-override case. The repeated live Chromium subset held all three malicious actions and allowed all three benign twins.

These are prototype benchmark results, not proof of universal security or performance on every agent, model, MCP server, or novel attack.

## Scope boundary

Agent Guardian protects interactions that are actually routed through its MCP proxy or controlled browser harness. It does not automatically inspect a provider's private built-in tools, ordinary browser activity, direct network paths that bypass Guardian, vulnerabilities inside an allowed service, or every future attack technique.

## Calls to action

- **Run the five-minute demo:** `npm run demo:headed`
- **Reproduce the evaluation:** `npm run evaluate`
- **Install locally:** build and install the generated npm tarball
- **Read the threat model:** `docs/threat-model.md`

Avoid claims such as “detects every threat,” “guards all AI activity,” or “zero attack success.”
