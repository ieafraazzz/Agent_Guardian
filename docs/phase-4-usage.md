# Phase 4: approvals, session policy, and reports

## Session context

Set default intent, allowed capabilities, and trusted destinations in the VS Code settings:

- `mcp-guardian.sessionIntent`
- `mcp-guardian.allowedCapabilities`
- `mcp-guardian.trustedDestinations`

An MCP client may narrow or override that context for one call through `_meta`:

```json
{
  "name": "mail__send_email",
  "arguments": {
    "to": "professor@example.edu",
    "body": "Project report"
  },
  "_meta": {
    "guardian": {
      "sessionId": "mini-project-demo",
      "intent": "Send the project report to our professor",
      "allowedCapabilities": ["READ_LOCAL", "WRITE_COMMUNICATION"],
      "trustedDestinations": ["professor@example.edu"]
    }
  }
}
```

Empty configured capability and destination lists mean that no explicit constraint was supplied; they do not silently create an allow list. When a list is supplied, an out-of-policy capability or destination produces an `ASK` decision. Existing hard-block rules cannot be overridden through approval.

## Approval properties

Every approval is bound to the canonical fingerprint of the session, intent, server, tool, capability, destination, arguments, and evidence IDs. It is valid for one pending request only and expires before the client request timeout. Replayed IDs, mismatched fingerprints, late replies, offline approval UI, and unanswered requests fail closed.

The extension receives a display-only copy with credentials redacted, control characters removed, and size/depth bounds applied. The original arguments are sent to the downstream tool only after a valid approval.

## Exporting reports

Use the VS Code Command Palette commands:

- `MCP Guardian: Export Audit as JSON`
- `MCP Guardian: Export Audit as JSONL`
- `MCP Guardian: Export Audit as SARIF`

Or use the reporting CLI:

```text
agent-guardian report export --format jsonl --out audit.jsonl
agent-guardian report export --format sarif --out audit.sarif
agent-guardian report verify --input audit.jsonl
```

Pass `--storage <directory>` to export a non-default Guardian database. Exported JSON and JSONL records form a SHA-256 hash chain, and sensitive argument values are redacted before hashing.

CLI exit codes:

| Code | Meaning |
|---:|---|
| 0 | Success |
| 2 | Invalid command or arguments |
| 3 | Audit integrity verification failed |
| 4 | File, parsing, or other I/O failure |
