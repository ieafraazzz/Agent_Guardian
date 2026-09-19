# Phase 7 installation and client setup

Agent Guardian has two cooperating parts:

- the **npm CLI/proxy**, which must be the MCP process launched by the AI client;
- the optional **VS Code extension**, which supplies configuration, live evidence, and exact one-time approval UI.

Only MCP servers routed through the proxy are protected. The controlled Browser Guardian is a separate Playwright harness; Agent Guardian does not silently intercept a user's ordinary browser or private tools built into an AI provider.

## 1. Install from this repository

Requirements: Node.js 20 or later and npm.

```powershell
npm install
npm run build
npm run pack:check
npm pack
npm install --global .\mcp-guardian-1.0.0.tgz
agent-guardian --help
```

Until the package is published to the npm registry, the generated `.tgz` is the reproducible local installation artifact. Do not run `npm publish` without the repository owner's approval and an agreed package name/publisher.

## 2. Configure the real downstream MCP server

This example routes the official-style “everything” test server behind Guardian:

```powershell
agent-guardian config add-server --name everything --command npx --args-json '["-y","@modelcontextprotocol/server-everything"]'
agent-guardian config show
```

Replace the name, command, and argument array with the MCP server you actually want to protect. On Windows PowerShell, single quotes around the JSON array prevent PowerShell from consuming its double quotes.

Guardian stores local configuration and audit data under `%USERPROFILE%\.mcp-guardian` by default. Set `MCP_GUARDIAN_STORAGE_PATH` on both the proxy and extension-side workflow only when an isolated store is required.

## 3. Configure an MCP client

The examples assume the package was installed globally, so `agent-guardian` is on `PATH`.

### VS Code

Create `.vscode/mcp.json` in the workspace:

```json
{
  "servers": {
    "agent-guardian": {
      "type": "stdio",
      "command": "agent-guardian",
      "args": ["proxy"]
    }
  }
}
```

Run **MCP: List Servers**, start `agent-guardian`, and inspect its output if startup fails. Current VS Code MCP configuration is documented at <https://code.visualstudio.com/docs/agent-customization/mcp-servers>.

### Cursor

Create `.cursor/mcp.json` in the project or `~/.cursor/mcp.json` globally:

```json
{
  "mcpServers": {
    "agent-guardian": {
      "command": "agent-guardian",
      "args": ["proxy"]
    }
  }
}
```

Cursor's current locations and schema are documented at <https://docs.cursor.com/context/model-context-protocol>.

### Claude Desktop

On Windows, edit `%APPDATA%\Claude\claude_desktop_config.json` and restart Claude Desktop:

```json
{
  "mcpServers": {
    "agent-guardian": {
      "command": "agent-guardian",
      "args": ["proxy"]
    }
  }
}
```

Anthropic's current local-server installation guidance is at <https://support.anthropic.com/en/articles/10949351-getting-started-with-local-mcp-servers-on-claude-desktop>.

### Windsurf

Edit `~/.codeium/windsurf/mcp_config.json`:

```json
{
  "mcpServers": {
    "agent-guardian": {
      "command": "agent-guardian",
      "args": ["proxy"]
    }
  }
}
```

VS Code's current discovery reference also records this Windsurf configuration location: <https://code.visualstudio.com/docs/agents/reference/mcp-configuration#_automatic-mcp-server-discovery>.

### Generic stdio MCP client

Configure the executable `agent-guardian` with one argument, `proxy`. Guardian speaks newline-delimited JSON-RPC over standard input/output and starts the configured downstream servers itself. Do not configure the same downstream server directly alongside Guardian, because the agent could then bypass the proxy.

## 4. Install or debug the VS Code extension

For development:

1. Open this repository in VS Code.
2. Run `npm install` and `npm run compile`.
3. Press `F5` and choose **Extension Development Host**.
4. In the new window, select the shield icon labelled **MCP Guardian**.
5. Configure `mcp-guardian.sessionIntent`, `allowedCapabilities`, `trustedDestinations`, and `servers` in Settings.
6. Start the MCP server from the client's MCP configuration. The dashboard should change from **SHIELD IDLE** to **SHIELD ACTIVE**.

To create a VSIX for team installation:

```powershell
npx --yes @vscode/vsce package
code --install-extension .\mcp-guardian-1.0.0.vsix
```

The extension and proxy communicate on localhost port `1337` by default. `ASK` decisions fail closed if no approval UI connects before the configured timeout. `ALLOW` and deterministic `BLOCK` decisions still work without the extension.

## 5. Verify the installation

```powershell
npm test
npm run demo
npm run evaluate
```

- `npm test` validates the security/runtime behavior.
- `npm run demo` runs the malicious and benign presentation twins.
- `npm run evaluate` reproduces the Phase 6 corpus and ablations.

For the narrated classroom flow, use [`../demo/README.md`](../demo/README.md).

## Troubleshooting

- **Client cannot find `agent-guardian`:** use the absolute path to `dist/cli.js` with `node`, or reinstall the tarball globally.
- **No downstream tools appear:** run `agent-guardian config show` and inspect the MCP client output log.
- **Approval immediately fails or expires:** start the VS Code extension dashboard before the client invokes the tool.
- **Dashboard stays idle:** ensure only one extension instance owns port `1337`, and that `MCP_GUARDIAN_WS_DISABLED` is not set to `1`.
- **Browser demo lacks Chromium:** run `npx playwright install chromium`.
