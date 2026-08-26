# MCP Guardian — VS Code Extension & MCP Firewall

MCP Guardian is a security gateway and monitoring extension for VS Code designed to defend AI agents (in clients like Cursor, Windsurf, or Claude Desktop) against **Model Context Protocol (MCP) tool poisoning** and **malicious prompt injections**. It acts as a single trust boundary, intercepting execution flows before they reach downstream servers.

---

## 🛡️ Core Defense Layers

### Layer 1: Cryptographic Fingerprinting & Drift Detector
*   Computes and stores SHA-256 hashes of all tool schemas (name, description, input parameters) on first connect.
*   On subsequent sessions, it compares hashes and instantly flags silent tool description changes (protecting against **Day-15 Rug Pulls**).

### Layer 2: Heuristic & Semantic Prompt Injection Scanner
*   Scans tool descriptions and argument payloads for imperative instructions designed to hijack LLM reasoning (e.g. *"ignore previous instructions"* or *"secretly email file content"*).
*   Supports optional **Gemini API-powered semantic scans** for advanced classification.

### Layer 3: Cross-Category Call Graph & Anomaly Detector
*   Categorizes tools based on capabilities (e.g., `READ_LOCAL`, `WRITE_COMMUNICATION`, `EXECUTE_SYSTEM`).
*   Monitors execution sequences and detects dangerous transitions (e.g., reading a confidential local file and immediately trying to send an email without user intent).

### Interactive Approval Gateway
*   Whenever a threat or forbidden transition is flagged, the proxy pauses execution and alerts the VS Code Extension.
*   The extension triggers a native VS Code approval notification and highlights the sidebar. The user can inspect the exact arguments and approve or block the execution in real-time.

---

## 📂 Project Structure

```
├── assets/
│   └── shield.svg                # Activity Bar icon
├── dist/                         # Compiled JavaScript output
│   ├── extension.js              # VS Code extension host bundle
│   └── proxy.js                  # Standalone stdio MCP proxy server
├── scratch/                      # Verification and test suites
│   ├── mock_server.js            # Mock downstream MCP server
│   ├── test_client.js            # Client simulator
│   ├── setup_test_db.js          # DB test initializer
│   └── test_online_approval.js   # Interactive approval test
├── src/                          # TypeScript source files
│   ├── webview/
│   │   └── sidebar.html          # Glassmorphic Sidebar Dashboard UI
│   ├── db.ts                     # Local database loader/writer
│   ├── detector.ts               # Layers 1, 2, and 3 security logic
│   ├── extension.ts              # Extension lifecycle & WS server
│   ├── proxy.ts                  # JSON-RPC proxy process
│   └── types.ts                  # Shared TypeScript interfaces
├── esbuild.js                    # High-speed bundler configuration
├── tsconfig.json                 # TypeScript compiler configuration
└── package.json                  # Extension manifest
```

---

## 🚀 Setup & Integration

### 1. Build the Extension
Ensure you have Node.js installed, then run:
```bash
npm install
npm run build
```

### 2. Configure Your AI Client
Configure your AI assistant to talk to the MCP Guardian proxy instead of connecting directly to downstream servers:

#### For Cursor (`project.json` or Global settings)
Add an MCP server pointing to the built proxy:
```json
{
  "mcpServers": {
    "mcp-guardian": {
      "command": "node",
      "args": [
        "c:/Users/ieafr/OneDrive/Desktop/MyGithub/miniproject-sem-5/dist/proxy.js"
      ]
    }
  }
}
```

#### For Claude Desktop (`claude_desktop_config.json`)
Add the following to your configuration file (typically in `%APPDATA%\Claude\claude_desktop_config.json`):
```json
{
  "mcpServers": {
    "mcp-guardian": {
      "command": "node",
      "args": [
        "c:/Users/ieafr/OneDrive/Desktop/MyGithub/miniproject-sem-5/dist/proxy.js"
      ]
    }
  }
}
```

---

## 🧪 Verification & Testing

The project includes pre-configured testing scripts that demonstrate the security layers in action.

### Run the Test Suite
1.  **Configure test environment**: Run the helper script to setup mock servers in the database:
    ```bash
    node scratch/setup_test_db.js
    ```
2.  **Test offline fail-closed action**:
    ```bash
    node scratch/test_client.js
    ```
    *This simulates a client requesting `read_file` followed by `send_email`. Because the extension is offline, the proxy blocks the exfiltration attempt automatically.*
3.  **Test online interactive approval**:
    ```bash
    node scratch/test_online_approval.js
    ```
    *This runs a mock WebSocket server on port 1337. When the `send_email` request is intercepted, it alerts the server, which responds with an approval, allowing the tool to execute.*
