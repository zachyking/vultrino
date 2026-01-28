# HTTP Proxy

The Vultrino HTTP Proxy automatically injects credentials into outgoing HTTP requests, allowing applications to make authenticated API calls without knowing the actual secrets.

## Overview

The proxy:
- Accepts HTTP requests with a credential alias header
- Looks up the credential from encrypted storage
- Injects appropriate authentication (API key, Bearer token, Basic auth)
- Forwards the request to the target URL
- Returns the response to the client

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│   Client     │────▶│   Vultrino   │────▶│   Target     │
│   (no creds) │     │   Proxy      │     │   API        │
└──────────────┘     └──────────────┘     └──────────────┘
                     Injects auth header
```

## Starting the Proxy

```bash
export VULTRINO_PASSWORD="your-password"
vultrino serve
# Proxy listening on http://127.0.0.1:7878
```

Custom bind address:
```bash
vultrino serve --bind 0.0.0.0:8080
```

## Making Requests

### Using X-Vultrino-Credential Header

The simplest method — specify the credential alias in a header:

```bash
curl -H "X-Vultrino-Credential: github-api" \
     http://localhost:7878/https://api.github.com/user
```

The proxy will:
1. Extract the credential alias from `X-Vultrino-Credential`
2. Look up the credential in storage
3. Strip the header
4. Add the appropriate auth header (e.g., `Authorization: Bearer ghp_xxx`)
5. Forward to `https://api.github.com/user`

### With API Key Authentication

When using RBAC, include your Vultrino API key:

```bash
curl -H "Authorization: Bearer vk_your_api_key" \
     -H "X-Vultrino-Credential: github-api" \
     http://localhost:7878/https://api.github.com/user
```

## URL Formats

### Full URL in Path

```
http://localhost:7878/https://api.github.com/user
http://localhost:7878/https://api.stripe.com/v1/charges
```

### Standard HTTP Proxy

Configure your HTTP client to use Vultrino as a proxy:

```bash
export HTTP_PROXY=http://localhost:7878
export HTTPS_PROXY=http://localhost:7878

curl -H "X-Vultrino-Credential: github-api" \
     https://api.github.com/user
```

## Authentication Injection

Vultrino automatically formats authentication based on credential type:

### API Key

For `api_key` credentials, injects as Bearer token:

```
Authorization: Bearer <key>
```

### Basic Auth

For `basic_auth` credentials, injects Base64-encoded credentials:

```
Authorization: Basic <base64(username:password)>
```

### Custom Header

Some APIs expect the key in a custom header. Configure in the credential metadata:

```bash
vultrino add --alias custom-api --key xxx \
  --metadata '{"header_name": "X-API-Key"}'
```

Results in:
```
X-API-Key: xxx
```

## Request Flow

1. **Receive Request**
   - Parse target URL from path or proxy request
   - Extract `X-Vultrino-Credential` header
   - Extract `Authorization` header (if RBAC enabled)

2. **Authenticate**
   - Validate API key (if provided)
   - Check role permissions
   - Verify credential scope access

3. **Policy Check**
   - Evaluate policies for the credential
   - Check URL patterns, methods, rate limits
   - Deny if any policy fails

4. **Credential Injection**
   - Decrypt credential from storage
   - Format appropriate auth header
   - Remove Vultrino-specific headers

5. **Forward Request**
   - Send to target URL
   - Stream response back to client
   - Log audit entry

## Configuration

```toml
[server]
bind = "127.0.0.1:7878"
mode = "local"              # "local" or "server"
timeout = 30                # Request timeout in seconds
max_body_size = 10485760    # 10MB max request body

[proxy]
strip_headers = [           # Headers to remove before forwarding
  "X-Vultrino-Credential",
  "X-Vultrino-Policy",
]
inject_headers = {          # Headers to add to all requests
  "X-Forwarded-By" = "vultrino"
}
```

## Error Responses

### 400 Bad Request

Missing credential header:
```json
{
  "error": "missing_credential",
  "message": "X-Vultrino-Credential header is required"
}
```

### 401 Unauthorized

Invalid or expired API key:
```json
{
  "error": "unauthorized",
  "message": "Invalid or expired API key"
}
```

### 403 Forbidden

Permission denied by RBAC or policy:
```json
{
  "error": "forbidden",
  "message": "Permission denied for credential 'github-api'"
}
```

### 404 Not Found

Credential not found:
```json
{
  "error": "not_found",
  "message": "Credential 'unknown-api' not found"
}
```

### 502 Bad Gateway

Target server error:
```json
{
  "error": "upstream_error",
  "message": "Failed to connect to target server"
}
```

## Language Examples

### curl

```bash
curl -H "X-Vultrino-Credential: github-api" \
     http://localhost:7878/https://api.github.com/user
```

### Python

```python
import requests

response = requests.get(
    "http://localhost:7878/https://api.github.com/user",
    headers={"X-Vultrino-Credential": "github-api"}
)
print(response.json())
```

### JavaScript (Node.js)

```javascript
const response = await fetch(
  "http://localhost:7878/https://api.github.com/user",
  {
    headers: {
      "X-Vultrino-Credential": "github-api"
    }
  }
);
const data = await response.json();
```

### Go

```go
req, _ := http.NewRequest("GET",
    "http://localhost:7878/https://api.github.com/user", nil)
req.Header.Set("X-Vultrino-Credential", "github-api")

client := &http.Client{}
resp, _ := client.Do(req)
```

### Rust

```rust
let client = reqwest::Client::new();
let response = client
    .get("http://localhost:7878/https://api.github.com/user")
    .header("X-Vultrino-Credential", "github-api")
    .send()
    .await?;
```

## Performance

### Connection Pooling

The proxy maintains connection pools to frequently accessed backends, reducing latency for repeated requests.

### Streaming

Large responses are streamed directly to the client without buffering the entire body in memory.

### Caching

The proxy does not cache responses. Implement caching in your application or use a dedicated cache layer.

## Security

### Network Binding

Always bind to localhost in production. Use a reverse proxy (nginx, Caddy) for external access.

### TLS

The proxy can make requests to HTTPS endpoints. For production, also put the proxy itself behind TLS.

### Audit Logging

All requests are logged with:
- Timestamp
- Credential alias used
- Target URL
- HTTP method
- Source IP
- Response status

Audit logs never include actual credential values.
