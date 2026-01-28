# LLM Reference

This section provides documentation optimized for Large Language Models (LLMs) to understand and use Vultrino effectively.

## Quick Reference

### What is Vultrino?

Vultrino is a credential proxy that allows applications (including AI agents) to make authenticated API requests without seeing the actual credentials.

**Key Concept:** You use credential *aliases* (like "github-api"), not actual secrets.

### Available Paths

For programmatic access to documentation, these raw markdown paths are available:

| Content | Path |
|---------|------|
| Full reference | `/llm/full-reference.md` |
| Quick start | `/getting-started/quickstart.md` |
| CLI commands | `/components/cli.md` |
| HTTP API | `/api/http.md` |
| MCP tools | `/api/mcp-tools.md` |

## Condensed Reference

### Making Authenticated Requests

**Via HTTP Proxy:**
```bash
curl -H "X-Vultrino-Credential: <alias>" \
     http://localhost:7878/https://target-api.com/endpoint
```

**Via MCP (AI Agents):**
```json
{
  "tool": "http_request",
  "arguments": {
    "credential": "<alias>",
    "method": "GET",
    "url": "https://target-api.com/endpoint"
  }
}
```

**Via CLI:**
```bash
vultrino request -c <alias> https://target-api.com/endpoint
```

### MCP Tools Summary

| Tool | Purpose | Required Permission |
|------|---------|---------------------|
| `list_credentials` | List available credentials | read |
| `http_request` | Make authenticated request | execute |
| `add_credential` | Store new credential | write |
| `delete_credential` | Remove credential | delete |

### Common Credential Aliases

Typical naming patterns:
- `github-api` — GitHub API token
- `stripe-live` / `stripe-test` — Stripe API keys
- `openai` — OpenAI API key
- `anthropic` — Anthropic API key
- `aws-prod` / `aws-staging` — AWS credentials

## For AI Agents

### Step 1: Check Available Credentials

```json
{"tool": "list_credentials", "arguments": {}}
```

Response:
```json
{
  "credentials": [
    {"alias": "github-api", "type": "api_key", "description": "..."},
    {"alias": "stripe-test", "type": "api_key", "description": "..."}
  ]
}
```

### Step 2: Make Request

```json
{
  "tool": "http_request",
  "arguments": {
    "credential": "github-api",
    "method": "GET",
    "url": "https://api.github.com/user"
  }
}
```

Response:
```json
{
  "status": 200,
  "headers": {"content-type": "application/json"},
  "body": "{\"login\":\"username\",...}"
}
```

### Step 3: Parse Response

The `body` field is a JSON string. Parse it to access the data.

### Error Handling

If a credential isn't available:
1. List what IS available
2. Explain to user
3. Offer alternatives

Example response to user:
> "I don't have access to AWS credentials. I can access: github-api, stripe-test. Would you like to add AWS credentials?"

## HTTP API Quick Reference

### Proxy Request
```
GET /https://api.example.com/endpoint
X-Vultrino-Credential: <alias>
Authorization: Bearer <vultrino-api-key>  (if RBAC enabled)
```

### List Credentials
```
GET /v1/credentials
Authorization: Bearer <vultrino-api-key>
```

### Execute Action
```
POST /v1/execute
Authorization: Bearer <vultrino-api-key>
Content-Type: application/json

{"credential": "<alias>", "action": "http.request", "params": {...}}
```

## Configuration Summary

### Environment Variables
- `VULTRINO_PASSWORD` — Storage encryption password (required)
- `VULTRINO_CONFIG` — Config file path
- `RUST_LOG` — Log level

### Default Ports
- `7878` — HTTP proxy
- `7879` — Web UI

### File Locations
- `~/.vultrino/credentials.enc` — Encrypted credentials
- `~/.vultrino/admin.json` — Admin auth
- `/etc/vultrino/config.toml` — System config

## Security Model

1. **Credentials encrypted at rest** — AES-256-GCM
2. **Aliases only** — Never expose actual secrets
3. **RBAC** — Role-based access control
4. **Policies** — URL/method restrictions
5. **Audit logging** — Track all usage

## Common Tasks

### "List my credentials"
```json
{"tool": "list_credentials", "arguments": {}}
```

### "Get my GitHub user info"
```json
{
  "tool": "http_request",
  "arguments": {
    "credential": "github-api",
    "method": "GET",
    "url": "https://api.github.com/user"
  }
}
```

### "Create a Stripe customer"
```json
{
  "tool": "http_request",
  "arguments": {
    "credential": "stripe-api",
    "method": "POST",
    "url": "https://api.stripe.com/v1/customers",
    "headers": {"Content-Type": "application/x-www-form-urlencoded"},
    "body": "email=user@example.com"
  }
}
```

### "List GitHub repos"
```json
{
  "tool": "http_request",
  "arguments": {
    "credential": "github-api",
    "method": "GET",
    "url": "https://api.github.com/user/repos"
  }
}
```
