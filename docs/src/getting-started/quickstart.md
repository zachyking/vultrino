# Quick Start

This guide will get you up and running with Vultrino in under 5 minutes.

## 1. Initialize Vultrino

First, initialize the configuration and set up your admin account:

```bash
vultrino init
```

You'll be prompted to:
1. Set a **storage password** (encrypts your credentials at rest)
2. Create an **admin username** for the web UI
3. Set an **admin password** for the web UI

> **Tip:** Set the `VULTRINO_PASSWORD` environment variable to avoid password prompts:
> ```bash
> export VULTRINO_PASSWORD="your-secure-password"
> ```

## 2. Add Your First Credential

Add an API key credential:

```bash
vultrino add --alias github-api --key ghp_your_github_token
```

Add a Basic Auth credential:

```bash
vultrino add --alias my-service --type basic_auth --username admin --password secret123
```

## 3. List Your Credentials

```bash
vultrino list
```

Output:
```
ALIAS                TYPE            ID                                   DESCRIPTION
github-api           api_key         a1b2c3d4-...                        -
my-service           basic_auth      e5f6g7h8-...                        -
```

## 4. Make an Authenticated Request

Use the `request` command to make API calls with your stored credentials:

```bash
vultrino request github-api https://api.github.com/user
```

The credential is automatically injected — you never need to expose the actual token.

## 5. Start the Web UI

Launch the admin dashboard:

```bash
vultrino web
```

Open http://127.0.0.1:7879 and log in with your admin credentials.

## 6. Create an API Key for AI Agents

Before AI agents can use Vultrino, create a scoped API key:

```bash
vultrino key create my-agent --role executor
```

Output:
```
API key created successfully!

Key: vk_abc123...

*** SAVE THIS KEY - IT WILL NOT BE SHOWN AGAIN ***

Name:    my-agent
Role:    executor
Expires: Never
```

> **Important:** Save this key securely. It provides scoped access to your credentials.

## 7. Start the Server

Start the web server (required for CLI with API key and web UI):

```bash
vultrino web
```

This starts:
- Web UI at http://127.0.0.1:7879
- JSON API for CLI and external apps

## 8. Use CLI with API Key (No Password)

Once the server is running, use CLI commands with just the API key:

```bash
# List credentials (no VULTRINO_PASSWORD needed!)
vultrino --key vk_abc123... request github-api https://api.github.com/user
```

## 9. Use with MCP (AI Agents)

Start the MCP server:

```bash
vultrino mcp
```

AI agents use your API key in every tool call:

```json
{
  "tool": "http_request",
  "arguments": {
    "api_key": "vk_abc123...",
    "credential": "github-api",
    "method": "GET",
    "url": "https://api.github.com/user"
  }
}
```

See [Using with AI Agents](../guides/ai-agents.md) for detailed setup.

## Common Commands

| Command | Description |
|---------|-------------|
| `vultrino init` | Initialize configuration and admin account |
| `vultrino add --alias NAME --key TOKEN` | Add an API key credential |
| `vultrino list` | List all credentials |
| `vultrino remove <alias>` | Remove a credential |
| `vultrino request <alias> <url>` | Make authenticated request (needs password) |
| `vultrino --key KEY request <alias> <url>` | Make request with API key (no password) |
| `vultrino web` | Start web UI and API server |
| `vultrino mcp` | Start MCP server for AI agents |
| `vultrino key create NAME --role ROLE` | Create API key |
| `vultrino key list` | List API keys |
| `vultrino key revoke NAME` | Revoke an API key |
| `vultrino role list` | List available roles |

## Next Steps

- [Configuration](./configuration.md) — Customize Vultrino settings
- [Managing Credentials](../guides/credentials.md) — Advanced credential management
- [Roles & API Keys](../guides/rbac.md) — Set up access control
- [Using with AI Agents](../guides/ai-agents.md) — MCP integration guide
