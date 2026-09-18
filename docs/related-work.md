# Related Work and Claim Boundary

This document fixes the project's novelty claim before implementation and evaluation. It should be updated when the team adds or removes a comparison system.

## Established work

- **Indirect prompt injection (Greshake et al.)** establishes that instructions embedded in retrieved data can redirect an LLM-integrated application and its API calls.
- **CaMeL** separates trusted control flow from untrusted data and tracks dependencies to prevent unintended actions and exfiltration.
- **MCPTox** evaluates tool poisoning on real MCP servers and identifies single-turn evaluation and manually constructed attacks as limitations.
- **MCPXKIT** supplies an offensive taxonomy with 31 MCP attack methods across four categories.
- **MCPGuard** surveys MCP threat classes and scanning/runtime defense approaches; it must not be described as a complete implemented runtime product without further evidence.
- **WASP** evaluates realistic end-to-end browser-agent attacks and distinguishes partial influence from completed attacker goals.
- **WebSentinel** detects and localizes suspicious webpage segments using contextual inconsistency.
- **WARD** is a large trained browser prompt-injection guard and represents classifier-based defense, not the same systems contribution as Guardian.
- **ceLLMate** gates browser side effects outside the agent at the HTTP layer.
- **Untrusted Content Masking** separates trusted and untrusted DOM regions and optionally hides unsafe content from the planning agent.

## Closest overlapping systems

- **mcp-scan / Invariant Gateway** performs static and runtime MCP scanning, hashing, prompt-injection checks, toxic-flow analysis, tool-call/result guardrails, PII/secret detection, and sequence restrictions.
- **Runtime Policy Enforcement for MCP-Based LLM Agents** evaluates a tool-call Policy Enforcement Point with cross-step integrity/sensitivity labels and a SHA-256 hash-chained audit trail. This substantially overlaps MCP-only policy, taint, and audit claims.
- **mcp-policy-gateway** reports a labelled corpus containing attacks and benign near-misses and should be treated as a benchmark/product comparison after its source and licence are inspected.
- **NVIDIA SkillSpector** is a pre-install static scanner. Guardian borrows its uniform finding discipline, inspection completeness, resource bounds, Unicode handling, and accepted-risk concepts, but Guardian's runtime enforcement and cross-surface trace serve a different purpose.

## Claim we will make

Agent Guardian investigates whether correlating browser and MCP events in one ordered runtime trace, then gating privileged actions using explicit user intent plus content provenance, improves detection over individual integrity, semantic, behavior, intent, or provenance layers.

## Claims we will not make

- First MCP security proxy or firewall.
- First prompt-injection detector.
- First rug-pull or tool-shadowing detector.
- First MCP data-flow or cross-step policy engine.
- Guaranteed prevention of all prompt injection.
- Production-ready browser protection.

## Evidence required for the contribution

- Benign and malicious twin tasks differing by intent and provenance.
- Cross-surface attacks that cannot be decided from one isolated event.
- Held-out attack cases not written to fit Guardian's rules.
- Full-system, single-layer, and leave-one-layer-out results.
- False-positive, benign-completion, approval-frequency, latency, and completeness results.
- Exact versions, settings, repetitions, and confidence intervals for live-agent experiments.

The rule table must be frozen before held-out evaluation, and results on team-authored and external attacks must be reported separately.
