# Vultrino Examples

This folder contains example scripts and configurations for using Vultrino.

## Examples

| File | Description |
|------|-------------|
| `basic-usage.sh` | Basic CLI setup with API keys |
| `python-client.py` | Python HTTP API client |
| `mcp-claude-config.json` | MCP configuration for Claude Desktop |
| `multi-agent-setup.sh` | Multiple agents with different scopes |
| `curl-examples.sh` | HTTP API examples using curl |

## Quick Start

```bash
# 1. Initialize Vultrino
vultrino init

# 2. Add a credential
vultrino add --alias github-api --key ghp_your_token

# 3. Start the web server
vultrino web &

# 4. Create an API key for your application
vultrino key create my-app --role executor
# Save the vk_xxx key!

# 5. Use the API key (no password required)
vultrino --key vk_xxx request github-api https://api.github.com/user
```

## Authentication Modes

### Direct Mode (with password)
```bash
export VULTRINO_PASSWORD="your-storage-password"
vultrino request github-api https://api.github.com/user
```

### API Key Mode (passwordless, requires running server)
```bash
vultrino web &  # Start server first
vultrino --key vk_xxx request github-api https://api.github.com/user
```

### HTTP API
```bash
curl -H "Authorization: Bearer vk_xxx" \
     http://localhost:7879/api/v1/credentials
```

### MCP (for AI agents)
Every tool call includes the API key:
```json
{
  "tool": "http_request",
  "arguments": {
    "api_key": "vk_xxx",
    "credential": "github-api",
    "method": "GET",
    "url": "https://api.github.com/user"
  }
}
```
