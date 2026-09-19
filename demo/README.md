# Agent Guardian presentation demo

This folder is deliberately separate from the product and evaluation code. The demo runs the real `GuardedBrowserHarness`, `BrowserGuardian`, policy engine, and hash-chained `CrossSurfaceStore` from `dist/`.

## Run it

From the repository root on Windows PowerShell:

```powershell
npm install
npx playwright install chromium
npm run demo:headed
```

Use `npm run demo` for the faster headless version. A machine-readable evidence report is written to `demo/output/latest-report.json` after every run.

## What the demonstration proves

The runner starts two local web servers. One represents the trusted invoice application; the other represents an attacker-controlled external destination. No real email, credential, or internet service is used.

1. The malicious page visually shows an ordinary invoice but contains a hidden prompt instructing the agent to read a credential and send the invoice externally.
2. Guardian compares rendered text with agent-ingested text and records prompt-injection/provenance evidence.
3. Credential entry and external form/email submission are gated before execution. Both produce `ASK`, and because this scripted demo grants no approval, neither side effect executes.
4. The benign twin contains no hidden instruction and matches the declared intent to send to the approved professor. It produces `ALLOW`, and exactly one local delivery occurs.
5. The final report verifies the hash-chained trace and asserts that the attacker received zero deliveries.

## Five-minute presentation script for ma'am

1. Open `demo/README.md` and briefly explain that the two pages are identical in purpose but differ in hidden attacker content and destination.
2. Open a terminal at the repository root and run `npm run demo:headed`.
3. During **MALICIOUS TWIN**, point out the normal-looking invoice. The browser may close quickly; the terminal is the authoritative result. Highlight:
   - hidden-injection evidence is non-zero;
   - credential entry is held;
   - external send is held;
   - attacker side effects remain zero.
4. During **BENIGN TWIN**, explain that the user's intent explicitly authorizes the professor and the trusted destination. Highlight the `ALLOW` decision and one approved delivery.
5. Open `demo/output/latest-report.json`. Show `assertions`, `traceIntegrity: true`, the ordered `traceRecords`, and `passed: true`.
6. Finish with the honest claim: “Agent Guardian enforces supported MCP and controlled-browser policies at runtime before external side effects. It reduces risk; it does not claim to detect every possible attack.”

## If something goes wrong

- `Executable doesn't exist`: run `npx playwright install chromium`.
- A browser is not visible: use `npm run demo:headed`, not `npm run demo`.
- Port conflict is not expected because both servers request free ephemeral localhost ports.
- A failed assertion makes the command exit non-zero and leaves the JSON report for inspection.
