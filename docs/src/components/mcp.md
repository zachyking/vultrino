# MCP Server

The Model Context Protocol (MCP) server allows AI agents to make authenticated API requests without accessing the actual credentials.

## Overview

MCP is a protocol for AI assistants to interact with external tools and services. Vultrino's MCP server provides tools for:
- Listing available credentials (by alias only)
- Making authenticated HTTP requests
- Managing credentials (with proper permissions)

```
┌──────────────────┐     ┌──────────────────┐     ┌──────────────────┐
│   AI Agent       │────▶│   Vultrino MCP   │────▶│   External       │
│   (Claude, etc.) │     │   Server         │     │   APIs           │
└──────────────────┘     └──────────────────┘     └──────────────────┘
        │                        │
        │  "Use github-api       │  Credential never
        │   to fetch user"       │  exposed to agent
        │                        │
```

## Starting the MCP Server

```bash
export VULTRINO_PASSWORD="your-password"
vultrino mcp
```

The MCP server uses stdio transport, communicating via stdin/stdout.

## API Key Authentication

AI agents authenticate by calling the `authenticate` tool with their API key:

```json
{
  "tool": "authenticate",
  "arguments": {
    "api_key": "vk_your_api_key_here"
  }
}
```

**Authentication flow:**
1. Admin creates API key: `vultrino key create ai-agent --role executor`
2. MCP server starts with storage password
3. AI agent calls `authenticate` tool with its API key
4. Server validates key and scopes subsequent requests to the key's role

**Without authentication:** Full access (for local development). In production, always have agents authenticate first.

## Configuring AI Clients

### Claude Desktop

Add to `~/Library/Application Support/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "vultrino": {
      "command": "/path/to/vultrino",
      "args": ["mcp"],
      "env": {
        "VULTRINO_PASSWORD": "your-password"
      }
    }
  }
}
```

### Claude Code (CLI)

Add to your MCP configuration:

```json
{
  "mcpServers": {
    "vultrino": {
      "command": "vultrino",
      "args": ["mcp"],
      "env": {
        "VULTRINO_PASSWORD": "your-password"
      }
    }
  }
}
```

**Important:** For scoped access, the AI agent should call the `authenticate` tool with its API key as the first action. Without authentication, the agent has full access to all credentials.

### Generic MCP Client

```javascript
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

const transport = new StdioClientTransport({
  command: "vultrino",
  args: ["mcp"],
  env: {
    VULTRINO_PASSWORD: process.env.VULTRINO_PASSWORD
  }
});

const client = new Client({
  name: "my-ai-app",
  version: "1.0.0"
});

await client.connect(transport);

// Authenticate with API key for scoped access
await client.callTool("authenticate", {
  api_key: process.env.VULTRINO_API_KEY
});
```

## Available Tools

### `list_credentials`

List all available credential aliases.

**Input:** None

**Output:**
```json
{
  "credentials": [
    {
      "alias": "github-api",
      "type": "api_key",
      "description": "GitHub personal access token"
    },
    {
      "alias": "stripe-api",
      "type": "api_key",
      "description": "Stripe API key"
    }
  ]
}
```

**Example prompt:**
> "What credentials are available?"

### `http_request`

Make an authenticated HTTP request.

**Input:**
```json
{
  "credential": "github-api",
  "method": "GET",
  "url": "https://api.github.com/user",
  "headers": {
    "Accept": "application/json"
  },
  "body": null
}
```

**Output:**
```json
{
  "status": 200,
  "headers": {
    "content-type": "application/json"
  },
  "body": "{\"login\": \"username\", ...}"
}
```

**Example prompts:**
> "Use github-api to get my user profile"
> "Make a POST request to Stripe to create a customer using stripe-api"

### `add_credential`

Add a new credential (requires write permission).

**Input:**
```json
{
  "alias": "new-api",
  "type": "api_key",
  "key": "secret-key-value",
  "description": "Optional description"
}
```

**Output:**
```json
{
  "success": true,
  "id": "550e8400-e29b-41d4-a716-446655440000"
}
```

### `delete_credential`

Delete a credential (requires delete permission).

**Input:**
```json
{
  "alias": "old-api"
}
```

**Output:**
```json
{
  "success": true
}
```

## Security Model

### Credential Isolation

The MCP server **never** exposes actual credential values to the AI agent. The agent only sees:
- Credential aliases
- Credential types
- Descriptions

### Permission Checks

If RBAC is enabled, the MCP server checks:
1. API key validity (from session or configuration)
2. Role permissions (read, execute, write, delete)
3. Credential scope restrictions

### Audit Trail

All MCP tool calls are logged:
```
2024-01-15T10:30:00Z MCP http_request credential=github-api url=https://api.github.com/user
```

## Tool Descriptions

The MCP server provides rich tool descriptions to help AI agents understand capabilities:

```json
{
  "name": "http_request",
  "description": "Make an authenticated HTTP request using a stored credential. The credential's actual value is never exposed - only the alias is needed.",
  "inputSchema": {
    "type": "object",
    "properties": {
      "credential": {
        "type": "string",
        "description": "Alias of the credential to use for authentication"
      },
      "method": {
        "type": "string",
        "enum": ["GET", "POST", "PUT", "PATCH", "DELETE"],
        "description": "HTTP method"
      },
      "url": {
        "type": "string",
        "description": "Target URL"
      },
      "headers": {
        "type": "object",
        "description": "Additional headers to include"
      },
      "body": {
        "type": "string",
        "description": "Request body (for POST, PUT, PATCH)"
      }
    },
    "required": ["credential", "method", "url"]
  }
}
```

## Example Conversations

### Listing and Using Credentials

**User:** "What API credentials do I have available?"

**AI Agent:** *calls list_credentials tool*

**AI Agent:** "You have the following credentials available:
- `github-api` - GitHub personal access token
- `stripe-api` - Stripe API key"

**User:** "Get my GitHub profile"

**AI Agent:** *calls http_request with credential=github-api*

**AI Agent:** "Your GitHub profile shows you're logged in as 'username' with 50 public repos..."

### Making Authenticated Requests

**User:** "Create a new Stripe customer with email test@example.com"

**AI Agent:** *calls http_request tool*
```json
{
  "credential": "stripe-api",
  "method": "POST",
  "url": "https://api.stripe.com/v1/customers",
  "headers": {
    "Content-Type": "application/x-www-form-urlencoded"
  },
  "body": "email=test@example.com"
}
```

**AI Agent:** "I've created a new Stripe customer. The customer ID is cus_xxx..."

## Troubleshooting

### MCP server not starting

- Verify `VULTRINO_PASSWORD` is set
- Check credentials file exists (`vultrino list` should work)
- Look for error messages in stderr

### Tool not found

- Ensure you're using the latest Vultrino version
- Verify MCP server started successfully
- Check client configuration

### Permission denied

- Verify the API key (if RBAC enabled) has execute permission
- Check credential scope restrictions
- Review audit logs for denial reasons

### Connection timeout

- MCP uses stdio transport; ensure no other process is consuming stdin
- Check that Vultrino binary path is correct
- Verify environment variables are passed correctly

## Best Practices

### For AI Developers

1. **Don't ask for credentials** — Always use aliases, never actual secrets
2. **Use descriptive aliases** — Help the AI understand what each credential is for
3. **Set up RBAC** — Create restricted roles for AI agent access
4. **Review audit logs** — Monitor what requests agents are making

### For System Administrators

1. **Use short-lived credentials** — Rotate frequently
2. **Scope credentials narrowly** — Each credential should do one thing
3. **Enable audit logging** — Track all credential usage
4. **Review agent behavior** — Periodically check what the AI is doing
