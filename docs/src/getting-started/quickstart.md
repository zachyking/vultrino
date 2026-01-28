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

## 6. Use with AI Agents (MCP)

Start the MCP server for LLM integration:

```bash
vultrino serve --mcp
```

Configure your AI agent (Claude, etc.) to use Vultrino as an MCP server. See [Using with AI Agents](../guides/ai-agents.md) for detailed setup instructions.

## Common Commands

| Command | Description |
|---------|-------------|
| `vultrino init` | Initialize configuration |
| `vultrino add` | Add a credential |
| `vultrino list` | List all credentials |
| `vultrino remove <alias>` | Remove a credential |
| `vultrino request <alias> <url>` | Make authenticated request |
| `vultrino web` | Start web UI |
| `vultrino serve --mcp` | Start MCP server |
| `vultrino role list` | List roles |
| `vultrino key create` | Create API key |

## Next Steps

- [Configuration](./configuration.md) — Customize Vultrino settings
- [Managing Credentials](../guides/credentials.md) — Advanced credential management
- [Roles & API Keys](../guides/rbac.md) — Set up access control
- [Using with AI Agents](../guides/ai-agents.md) — MCP integration guide
