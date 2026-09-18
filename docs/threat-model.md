# Agent Guardian Threat Model

## Security objective

Agent Guardian mediates every protected MCP and controlled-browser action before its side effect occurs. It uses explicit user intent, capability policy, content provenance, tool integrity, and ordered session history to produce an explainable `ALLOW`, `ASK`, or `BLOCK` decision.

The project does not attempt to make the underlying language model trustworthy. It limits what an untrusted or mistaken model can cause the surrounding tools and browser to execute.

## Protected assets

- Credentials, tokens, private files, personal data, and financial information.
- Integrity of MCP tool definitions, prompts, resources, arguments, and results.
- Authenticated browser sessions and state-changing browser actions.
- The user's stated intent, allowed capabilities, and trusted destinations.
- Accuracy and integrity of audit records and approval decisions.

## Trust boundaries

- Direct user intent and explicit approvals are trusted only for the exact session/action to which they apply.
- MCP server metadata, resources, tool results, and external webpage content are untrusted.
- The language model and its generated arguments are not a policy authority.
- The Guardian core is trusted to mediate protected actions; downstream servers and webpages are not.
- Semantic classifiers are untrusted advisers. Their output is evidence, never authorization.
- Text displayed in an approval interface remains attacker controlled until sanitized.

## Attacker capabilities

The attacker may:

- Publish or compromise an MCP server before onboarding.
- Change a previously approved tool definition (rug pull).
- Poison descriptions, nested schemas, defaults, enums, prompts, resources, arguments, or results.
- Supply hidden, confusable, zero-width, encoded, or paraphrased instructions.
- Control webpage text, hidden DOM regions, forms, links, frames, or cross-origin destinations.
- Cause a sequence of individually legitimate operations that becomes harmful in combination.
- Learn public Guardian rules and adapt attacks using previous outcomes.
- Target detectors, semantic models, audit explanations, and the approval interface.
- Transform or summarize sensitive information to evade exact value matching.

The attacker is not assumed able to modify Guardian's installed code, directly forge a user's approval, or compromise the operating system. Audit-chain integrity detects offline record modification but does not prevent deletion of the entire log by an OS-level attacker.

## Required security properties

1. **Complete mediation:** protected side effects pass through the policy engine.
2. **Denial non-execution:** `ASK` and `BLOCK` actions are not forwarded before authorization.
3. **Exact approval scope:** one approval authorizes only the matching pending action.
4. **Fail-closed risk handling:** missing/expired approval, incomplete critical inspection, or policy failure cannot silently authorize a risky action.
5. **Session isolation:** intent, taint, history, and approvals cannot leak between sessions.
6. **Definition integrity:** observed MCP definitions are compared with an explicitly approved baseline.
7. **Provenance retention:** untrusted sources remain identifiable when they influence later actions.
8. **Honest completeness:** partial, skipped, failed, or truncated inspection is never labelled clean.
9. **Tamper evidence:** every decision is linked into a verifiable hash-chained audit trail.

## In-scope attacks

- MCP tool poisoning, rug pulls, shadowing, and schema poisoning.
- Malicious arguments, resources, prompts, and tool outputs.
- Indirect browser prompt injection and invisible/obfuscated content.
- Sensitive-data exfiltration and confused-deputy behavior.
- Cross-tool, multi-turn, delayed, browser-to-MCP, and MCP-to-browser chains.
- Privilege escalation outside explicit intent or trusted destinations.
- Resource-exhaustion attempts against scanner inputs.

## Out of scope for the first research prototype

- A compromised operating system, Guardian installation, or IDE process.
- Atomic control inside a malicious downstream server after an allowed request.
- General harmful text generation that causes no protected side effect.
- Perfect semantic understanding or guaranteed detection of every paraphrase.
- Production protection of arbitrary personal browser sessions; the browser lane uses controlled Playwright/Chromium.
- Multi-agent delegation graphs and remote policy administration.

## Residual risks

- Coarse taint may generate false positives; exact fingerprints may miss transformed data.
- A user may approve a harmful action despite a correct warning.
- Incorrect intent or capability configuration can over-authorize a session.
- Rules may have coverage gaps against novel destinations or capabilities.
- Hash chaining reveals record modification but cannot recover a deleted log without external anchoring.

These limitations must be measured or disclosed rather than hidden behind a single risk score.
