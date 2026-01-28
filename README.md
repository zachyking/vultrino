# Vultrino

**A credential proxy for the AI era** — enabling AI agents to use credentials without seeing them.

## What is Vultrino?

Vultrino is a secure credential proxy that allows AI agents, LLMs, and automated systems to make authenticated API requests without ever exposing the actual credentials. Instead of giving your AI agent direct access to API keys, you give it access to Vultrino, which injects the authentication on behalf of the agent.

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   AI Agent      │────▶│    Vultrino     │────▶│   External API  │
│   (Claude, etc) │     │   (injects auth)│     │   (GitHub, etc) │
└─────────────────┘     └─────────────────┘     └─────────────────┘
        │                       │
        │ "Use github-api       │ Authorization: Bearer ghp_xxx...
        │  credential"          │
        ▼                       ▼
   Never sees the key     Handles authentication
```

## Features

- **Credential Isolation** — AI agents never see actual API keys or secrets
- **Role-Based Access Control** — Fine-grained permissions for different applications
- **Multiple Credential Types** — API keys, Basic Auth, Bearer tokens, and extensible via plugins
- **Plugin System** — Extend with custom credential types and actions via WASM plugins
- **MCP Integration** — Native Model Context Protocol support for LLM tools
- **Web UI** — Clean admin interface for managing credentials, roles, and API keys
- **Encrypted Storage** — AES-256-GCM encryption with Argon2 key derivation
- **Policy Engine** — URL patterns, method restrictions, rate limiting
- **Audit Logging** — Track all credential usage

## Installation

### From Source

```bash
# Clone the repository
git clone https://github.com/zachyking/vultrino.git
cd vultrino

# Build release binary
cargo build --release

# Install to path (optional)
cp target/release/vultrino ~/.local/bin/
```

### Requirements

- Rust 1.75+
- OpenSSL development libraries

## Quick Start

### 1. Initialize Storage

```bash
# Set your encryption password
export VULTRINO_PASSWORD="your-secure-password"

# Add your first credential
vultrino add --alias github-api --key ghp_your_token_here
```

### 2. Make Authenticated Requests

```bash
# Make a request using the credential
vultrino request github-api https://api.github.com/user
```

### 3. Start the Web UI

```bash
# Start the admin interface
vultrino web

# Open http://127.0.0.1:7879 in your browser
```

### 4. Use with AI Agents (MCP)

```bash
# Start MCP server for LLM integration
vultrino serve --mcp
```

## Usage

### CLI Commands

```bash
# Credential Management
vultrino add --alias <name> --key <api-key>    # Add API key credential
vultrino add --alias <name> --basic            # Add basic auth (interactive)
vultrino list                                   # List all credentials
vultrino remove <alias>                         # Remove a credential

# Making Requests
vultrino request <alias> <url>                  # GET request
vultrino request <alias> <url> -X POST -d '{}'  # POST with body

# Plugin Actions
vultrino action <credential> <plugin.action>    # Execute plugin action
vultrino action my-pgp pgp-signing.sign_cleartext -p '{"data":"Hello"}'

# Plugin Management
vultrino plugin install <path-or-url>           # Install a plugin
vultrino plugin list                            # List installed plugins
vultrino plugin info <name>                     # Show plugin details
vultrino plugin remove <name>                   # Remove a plugin

# Server Modes
vultrino web                                    # Start web UI
vultrino serve --mcp                            # Start MCP server
```

### Web UI

The web interface provides:

- **Dashboard** — Overview of credentials and recent activity
- **Credentials** — Add, edit, and remove credentials
- **API Keys** — Manage access keys for external applications
- **Roles** — Configure role-based access control
- **Audit Log** — View credential usage history

### MCP Integration

Vultrino provides native MCP (Model Context Protocol) support for AI agent integration:

```bash
# Start MCP server
vultrino serve --mcp
```

Available MCP tools:
- `http_request` — Make authenticated HTTP requests
- `list_credentials` — List available credentials
- Plugin tools (e.g., `pgp_sign`, `pgp_verify`)

## Plugin System

Vultrino supports WASM plugins for extending functionality with custom credential types and actions.

### Installing Plugins

```bash
# From local path
vultrino plugin install ./plugins/pgp-signing

# From git URL
vultrino plugin install https://github.com/user/vultrino-plugin-example
```

### Example: PGP Signing Plugin

The included PGP signing plugin adds:

**Credential Type:** `pgp_key`
- Private key (PEM/ASCII-armored)
- Optional passphrase

**Actions:**
- `sign` — Create detached signature
- `sign_cleartext` — Create cleartext signed message
- `verify` — Verify a signature
- `get_public_key` — Extract public key

```bash
# Install the plugin
vultrino plugin install ./plugins/pgp-signing

# Add a PGP credential via web UI or create via plugin

# Sign a message
vultrino action my-pgp pgp-signing.sign_cleartext -p '{"data":"Hello, World!"}'
```

### Developing Plugins

Plugins are WASM modules with a `plugin.toml` manifest:

```toml
[plugin]
name = "my-plugin"
version = "1.0.0"
description = "My custom plugin"
format = "wasm"
wasm_module = "plugin.wasm"

[[credential_types]]
name = "my_credential"
display_name = "My Credential Type"

[[credential_types.fields]]
name = "secret_field"
label = "Secret Field"
type = "password"
required = true
secret = true

[[actions]]
name = "my_action"
description = "Does something useful"

[[mcp_tools]]
name = "my_tool"
description = "MCP tool for AI agents"
action = "my_action"
```

Build with:
```bash
cargo build --release --target wasm32-wasip1
```

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `VULTRINO_PASSWORD` | Storage encryption password | Required |
| `VULTRINO_DATA_DIR` | Data directory path | `~/.vultrino` or platform default |

### Storage Location

- **macOS**: `~/Library/Application Support/vultrino/`
- **Linux**: `~/.local/share/vultrino/`
- **Windows**: `%APPDATA%\vultrino\`

## Security

### Encryption

- Credentials encrypted with AES-256-GCM
- Key derived using Argon2id
- Each credential has unique nonce

### Best Practices

1. Use a strong `VULTRINO_PASSWORD`
2. Restrict file permissions on data directory
3. Use role-based access control for multi-user setups
4. Enable audit logging in production
5. Review plugin code before installation

## Architecture

```
src/
├── auth/       # Authentication & authorization
├── config/     # Configuration management
├── crypto/     # Encryption & key derivation
├── mcp/        # Model Context Protocol server
├── plugins/    # Plugin system & WASM runtime
├── policy/     # Policy engine & rate limiting
├── router/     # Credential routing
├── server/     # HTTP proxy server
├── storage/    # Encrypted storage backend
└── web/        # Web UI (Axum + Askama)
```

## Documentation

Full documentation available in the `docs/` directory:

- [Getting Started](docs/src/getting-started/)
- [API Reference](docs/src/api/)
- [Plugin Development](docs/src/plugins/)
- [Deployment Guide](docs/src/deployment/)

## License

MIT License - see [LICENSE](LICENSE) for details.

## Contributing

Contributions welcome! Please read the contributing guidelines before submitting PRs.
