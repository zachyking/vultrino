# Vultrino Complete LLM Reference

This document contains everything an LLM needs to know to use Vultrino effectively.

---

## What is Vultrino?

Vultrino is a credential proxy for the AI era. It allows AI agents and applications to make authenticated API requests without ever seeing the actual credentials.

**Core Concept:** You reference credentials by *alias* (e.g., "github-api"), and Vultrino automatically injects the real credential into your request.

---

## MCP Tools

### list_credentials

Lists all credentials you have access to.

**Input:** None required

**Output:**
```json
{
  "credentials": [
    {
      "alias": "github-api",
      "type": "api_key",
      "description": "GitHub personal access token"
    }
  ]
}
```

**Permission Required:** read

---

### http_request

Makes an authenticated HTTP request.

**Input:**
```json
{
  "credential": "string (required) - credential alias",
  "method": "string (required) - GET|POST|PUT|PATCH|DELETE",
  "url": "string (required) - target URL",
  "headers": "object (optional) - additional headers",
  "body": "string (optional) - request body"
}
```

**Output:**
```json
{
  "status": 200,
  "headers": {"content-type": "application/json"},
  "body": "string - response body"
}
```

**Permission Required:** execute

**Example:**
```json
{
  "credential": "github-api",
  "method": "GET",
  "url": "https://api.github.com/user"
}
```

---

### add_credential

Stores a new credential.

**Input:**
```json
{
  "alias": "string (required) - unique name",
  "type": "string (required) - api_key|basic_auth",
  "key": "string (for api_key) - the secret value",
  "username": "string (for basic_auth)",
  "password": "string (for basic_auth)",
  "description": "string (optional)"
}
```

**Output:**
```json
{
  "success": true,
  "id": "uuid",
  "alias": "string"
}
```

**Permission Required:** write

---

### delete_credential

Removes a credential.

**Input:**
```json
{
  "alias": "string (required)"
}
```

**Output:**
```json
{
  "success": true
}
```

**Permission Required:** delete

---

## HTTP API Endpoints

### Proxy Request

```
{METHOD} /{target_url}
Headers:
  X-Vultrino-Credential: {alias}
  Authorization: Bearer {api_key} (if RBAC enabled)
```

### List Credentials

```
GET /v1/credentials
Authorization: Bearer {api_key}
```

### Get Credential

```
GET /v1/credentials/{alias}
Authorization: Bearer {api_key}
```

### Create Credential

```
POST /v1/credentials
Authorization: Bearer {api_key}
Content-Type: application/json

{
  "alias": "string",
  "type": "api_key|basic_auth",
  "data": { ... },
  "description": "string"
}
```

### Delete Credential

```
DELETE /v1/credentials/{alias}
Authorization: Bearer {api_key}
```

### Execute Action

```
POST /v1/execute
Authorization: Bearer {api_key}
Content-Type: application/json

{
  "credential": "alias",
  "action": "http.request",
  "params": {
    "method": "GET",
    "url": "https://...",
    "headers": {},
    "body": null
  }
}
```

---

## CLI Commands

```bash
# Initialize
vultrino init

# Add credential
vultrino add --alias NAME --key SECRET

# List credentials
vultrino list

# Make request
vultrino request -c ALIAS URL

# Start proxy
vultrino serve

# Start web UI
vultrino web

# Start MCP server
vultrino serve --mcp

# Manage roles
vultrino role create NAME --permissions read,execute
vultrino role list
vultrino role delete NAME

# Manage API keys
vultrino key create NAME --role ROLE
vultrino key list
vultrino key revoke KEY_PREFIX
```

---

## Credential Types

### api_key
- For API tokens, bearer tokens
- Injected as: `Authorization: Bearer {key}`

### basic_auth
- For username/password
- Injected as: `Authorization: Basic {base64(user:pass)}`

### oauth2
- For OAuth2 with refresh tokens
- Handles token refresh automatically

---

## Permissions

| Permission | Description |
|------------|-------------|
| read | List credentials (metadata only) |
| write | Create new credentials |
| update | Modify existing credentials |
| delete | Remove credentials |
| execute | Use credentials for requests |

---

## Error Codes

| Code | Meaning |
|------|---------|
| missing_credential | X-Vultrino-Credential header required |
| unauthorized | Invalid or expired API key |
| forbidden | Permission denied |
| not_found | Credential not found |
| policy_denied | Request blocked by policy |
| upstream_error | Target server error |

---

## Common Patterns

### List then use

```
1. list_credentials → see what's available
2. http_request → use the appropriate credential
```

### Handle missing credentials

When a credential isn't available:
1. List available credentials
2. Tell user what's available
3. Suggest adding the needed credential

### Parse response body

The `body` field in http_request response is always a string.
Parse it according to the content-type:
- `application/json` → JSON.parse()
- `text/plain` → use directly
- `text/html` → use directly

---

## Security Notes

1. **Never ask for actual secrets** - only use aliases
2. **Credentials are never returned** - only metadata
3. **All requests are logged** - audit trail exists
4. **Policies may restrict access** - some URLs/methods may be blocked
5. **Scopes limit visibility** - you may not see all credentials

---

## Environment

| Variable | Purpose |
|----------|---------|
| VULTRINO_PASSWORD | Decryption password (required) |
| VULTRINO_CONFIG | Config file path |
| RUST_LOG | Log level |

| Port | Service |
|------|---------|
| 7878 | HTTP Proxy |
| 7879 | Web UI |

---

## Quick Examples

**Get GitHub user:**
```json
{"tool": "http_request", "arguments": {"credential": "github-api", "method": "GET", "url": "https://api.github.com/user"}}
```

**Create Stripe customer:**
```json
{"tool": "http_request", "arguments": {"credential": "stripe-api", "method": "POST", "url": "https://api.stripe.com/v1/customers", "headers": {"Content-Type": "application/x-www-form-urlencoded"}, "body": "email=test@example.com"}}
```

**List repos:**
```json
{"tool": "http_request", "arguments": {"credential": "github-api", "method": "GET", "url": "https://api.github.com/user/repos"}}
```

**Post to Slack:**
```json
{"tool": "http_request", "arguments": {"credential": "slack-webhook", "method": "POST", "url": "https://hooks.slack.com/services/xxx", "headers": {"Content-Type": "application/json"}, "body": "{\"text\":\"Hello!\"}"}}
```
