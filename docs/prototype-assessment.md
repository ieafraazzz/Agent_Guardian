# Existing Prototype Assessment

This assessment records the starting condition of Afraaz's prototype so later refactoring preserves its intent and credits the existing foundation.

## Foundation retained

- VS Code extension and WebSocket approval channel.
- stdio MCP proxy and downstream server configuration.
- Tool aggregation and server-name prefixing.
- SHA-256 hashing of normalized tool definitions.
- Heuristic and optional Gemini semantic scanning.
- Capability-category assignment and forbidden-transition checks.
- JSON persistence, dashboard, audit display, mock server, and demonstration clients.

## Verified implementation risks

1. Downstream processes use `shell: true`, which increases command-injection exposure and breaks quoted Windows paths.
2. The multi-server `tools/list` callback is deleted after the first response, preventing reliable aggregation.
3. Client IDs are encoded into colon-separated downstream IDs, so arbitrary string IDs are not preserved safely.
4. Schema drift is logged during discovery but does not set the stored baseline to an enforceable unapproved state.
5. First-seen tool definitions are trusted automatically without an onboarding decision.
6. The call graph is one global list rather than per-session state.
7. Behavior considers only the immediately previous category and has no user-intent representation.
8. Prompt evidence overwrites one reason string rather than accumulating structured findings.
9. Tool results are returned without security or sensitive-data inspection.
10. Approval requests have no expiry and may hang beyond the client's timeout.
11. Audit state changes insert duplicate records instead of updating one decision lifecycle.
12. Tests are manual scripts, use timing, and write shared state under the user's home directory.
13. The current webview interpolates tool-controlled values into HTML and requires sanitization before it can safely display evidence.

## Refactoring constraint

Phase 1 adds an isolated security core without changing MCP behavior. Phase 2 will place the existing transport behind stable request maps and tests. Existing detector behavior will be migrated into the registry during Phase 3, after transport correctness is established.
