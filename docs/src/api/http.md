# HTTP API Reference

Complete reference for Vultrino's HTTP API endpoints.

## Base URL

Default: `http://127.0.0.1:7878`

## Authentication

### API Key Authentication

Include the Vultrino API key in the Authorization header:

```
Authorization: Bearer vk_your_api_key_here
```

### No Authentication (Local Mode)

In local mode without RBAC, no authentication is required.

---

## Proxy Endpoints

### Execute Proxied Request

Proxy a request through Vultrino with automatic credential injection.

**URL Format:**
```
{method} /{target_url}
```

**Headers:**
| Header | Required | Description |
|--------|----------|-------------|
| `X-Vultrino-Credential` | Yes | Alias of credential to use |
| `Authorization` | Depends | API key (if RBAC enabled) |
| `*` | No | All other headers passed to target |

**Example:**
```http
GET /https://api.github.com/user HTTP/1.1
Host: localhost:7878
X-Vultrino-Credential: github-api
Accept: application/json
```

**Response:**
Returns the response from the target server, including:
- Status code
- Headers
- Body

**Error Responses:**

| Status | Code | Description |
|--------|------|-------------|
| 400 | `missing_credential` | X-Vultrino-Credential header not provided |
| 401 | `unauthorized` | Invalid or expired API key |
| 403 | `forbidden` | Permission denied by RBAC or policy |
| 404 | `not_found` | Credential alias not found |
| 502 | `upstream_error` | Failed to connect to target server |

---

## Execute API

### POST /v1/execute

Execute an action with a credential. More flexible than direct proxy.

**Request:**
```http
POST /v1/execute HTTP/1.1
Host: localhost:7878
Authorization: Bearer vk_xxx
Content-Type: application/json

{
  "credential": "github-api",
  "action": "http.request",
  "params": {
    "method": "GET",
    "url": "https://api.github.com/user",
    "headers": {
      "Accept": "application/json"
    },
    "body": null
  }
}
```

**Request Fields:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `credential` | string | Yes | Credential alias |
| `action` | string | Yes | Action to perform |
| `params` | object | Yes | Action-specific parameters |

**Actions:**

| Action | Description |
|--------|-------------|
| `http.request` | Make an HTTP request |
| `crypto.sign` | Sign data (future) |

**HTTP Request Params:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `method` | string | Yes | HTTP method |
| `url` | string | Yes | Target URL |
| `headers` | object | No | Additional headers |
| `body` | string | No | Request body |

**Response:**
```json
{
  "status": 200,
  "headers": {
    "content-type": "application/json",
    "x-ratelimit-remaining": "4999"
  },
  "body": "{\"login\":\"username\",...}"
}
```

---

## Credential Management API

### GET /v1/credentials

List all credentials (metadata only, no secrets).

**Request:**
```http
GET /v1/credentials HTTP/1.1
Host: localhost:7878
Authorization: Bearer vk_xxx
```

**Response:**
```json
{
  "credentials": [
    {
      "id": "550e8400-e29b-41d4-a716-446655440000",
      "alias": "github-api",
      "type": "api_key",
      "description": "GitHub personal access token",
      "created_at": "2024-01-15T10:30:00Z",
      "updated_at": "2024-01-15T10:30:00Z"
    },
    {
      "id": "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
      "alias": "stripe-api",
      "type": "api_key",
      "description": null,
      "created_at": "2024-01-16T14:20:00Z",
      "updated_at": "2024-01-16T14:20:00Z"
    }
  ]
}
```

**Required Permission:** `read`

---

### GET /v1/credentials/{alias}

Get details about a specific credential.

**Request:**
```http
GET /v1/credentials/github-api HTTP/1.1
Host: localhost:7878
Authorization: Bearer vk_xxx
```

**Response:**
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "alias": "github-api",
  "type": "api_key",
  "description": "GitHub personal access token",
  "metadata": {},
  "created_at": "2024-01-15T10:30:00Z",
  "updated_at": "2024-01-15T10:30:00Z"
}
```

**Required Permission:** `read`

**Error Responses:**
| Status | Code | Description |
|--------|------|-------------|
| 404 | `not_found` | Credential not found |

---

### POST /v1/credentials

Create a new credential.

**Request:**
```http
POST /v1/credentials HTTP/1.1
Host: localhost:7878
Authorization: Bearer vk_xxx
Content-Type: application/json

{
  "alias": "new-api-key",
  "type": "api_key",
  "data": {
    "key": "secret_key_value"
  },
  "description": "Description of this credential",
  "metadata": {
    "team": "backend"
  }
}
```

**Request Fields:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `alias` | string | Yes | Unique human-readable name |
| `type` | string | Yes | Credential type |
| `data` | object | Yes | Credential data (type-specific) |
| `description` | string | No | Optional description |
| `metadata` | object | No | Custom metadata |

**Credential Types and Data:**

**api_key:**
```json
{
  "type": "api_key",
  "data": {
    "key": "your_api_key"
  }
}
```

**basic_auth:**
```json
{
  "type": "basic_auth",
  "data": {
    "username": "user",
    "password": "pass"
  }
}
```

**oauth2:**
```json
{
  "type": "oauth2",
  "data": {
    "client_id": "xxx",
    "client_secret": "xxx",
    "refresh_token": "xxx",
    "access_token": "xxx",
    "expires_at": "2024-02-15T10:30:00Z"
  }
}
```

**Response:**
```json
{
  "id": "7c9e6679-7425-40de-944b-e07fc1f90ae7",
  "alias": "new-api-key"
}
```

**Required Permission:** `write`

**Error Responses:**
| Status | Code | Description |
|--------|------|-------------|
| 400 | `invalid_request` | Invalid request body |
| 409 | `conflict` | Alias already exists |

---

### DELETE /v1/credentials/{alias}

Delete a credential.

**Request:**
```http
DELETE /v1/credentials/old-api HTTP/1.1
Host: localhost:7878
Authorization: Bearer vk_xxx
```

**Response:**
```json
{
  "success": true
}
```

**Required Permission:** `delete`

**Error Responses:**
| Status | Code | Description |
|--------|------|-------------|
| 404 | `not_found` | Credential not found |

---

## Role Management API

### GET /v1/roles

List all roles.

**Request:**
```http
GET /v1/roles HTTP/1.1
Host: localhost:7878
Authorization: Bearer vk_xxx
```

**Response:**
```json
{
  "roles": [
    {
      "id": "role-123",
      "name": "executor",
      "description": "Can execute requests",
      "permissions": ["read", "execute"],
      "credential_scopes": [],
      "created_at": "2024-01-15T10:30:00Z"
    }
  ]
}
```

---

### POST /v1/roles

Create a new role.

**Request:**
```http
POST /v1/roles HTTP/1.1
Host: localhost:7878
Authorization: Bearer vk_xxx
Content-Type: application/json

{
  "name": "github-reader",
  "description": "Read-only GitHub access",
  "permissions": ["read", "execute"],
  "credential_scopes": ["github-*"]
}
```

**Response:**
```json
{
  "id": "role-456",
  "name": "github-reader"
}
```

---

### DELETE /v1/roles/{name}

Delete a role.

**Request:**
```http
DELETE /v1/roles/old-role HTTP/1.1
Host: localhost:7878
Authorization: Bearer vk_xxx
```

**Response:**
```json
{
  "success": true
}
```

---

## API Key Management

### GET /v1/keys

List all API keys (shows prefix only, not full key).

**Request:**
```http
GET /v1/keys HTTP/1.1
Host: localhost:7878
Authorization: Bearer vk_xxx
```

**Response:**
```json
{
  "keys": [
    {
      "id": "key-123",
      "name": "my-app",
      "key_prefix": "vk_a1b2c3d4",
      "role_id": "role-123",
      "expires_at": null,
      "last_used_at": "2024-01-16T14:20:00Z",
      "created_at": "2024-01-15T10:30:00Z"
    }
  ]
}
```

---

### POST /v1/keys

Create a new API key.

**Request:**
```http
POST /v1/keys HTTP/1.1
Host: localhost:7878
Authorization: Bearer vk_xxx
Content-Type: application/json

{
  "name": "new-app-key",
  "role_id": "role-123",
  "expires_at": "2024-12-31T23:59:59Z"
}
```

**Response:**
```json
{
  "id": "key-456",
  "key": "vk_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6",
  "name": "new-app-key"
}
```

> **Note:** The full key is only returned once at creation. Store it securely.

---

### DELETE /v1/keys/{id}

Revoke an API key.

**Request:**
```http
DELETE /v1/keys/key-123 HTTP/1.1
Host: localhost:7878
Authorization: Bearer vk_xxx
```

**Response:**
```json
{
  "success": true
}
```

---

## Health Check

### GET /health

Check if the server is running.

**Request:**
```http
GET /health HTTP/1.1
Host: localhost:7878
```

**Response:**
```json
{
  "status": "ok",
  "version": "0.1.0"
}
```

No authentication required.

---

## Error Response Format

All errors follow this format:

```json
{
  "error": "error_code",
  "message": "Human-readable error message",
  "details": {}
}
```

### Common Error Codes

| Code | HTTP Status | Description |
|------|-------------|-------------|
| `invalid_request` | 400 | Malformed request body or parameters |
| `missing_credential` | 400 | X-Vultrino-Credential header missing |
| `unauthorized` | 401 | Invalid or expired API key |
| `forbidden` | 403 | Permission denied |
| `not_found` | 404 | Resource not found |
| `conflict` | 409 | Resource already exists |
| `rate_limited` | 429 | Too many requests |
| `internal_error` | 500 | Server error |
| `upstream_error` | 502 | Target server error |

---

## Rate Limits

Default rate limits (configurable):

| Endpoint | Limit |
|----------|-------|
| Proxy requests | 1000/minute |
| Credential management | 100/minute |
| Authentication | 10 failed/minute |

Rate limit headers:
```
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 999
X-RateLimit-Reset: 1705330800
```
