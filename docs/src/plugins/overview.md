# Plugin System

Vultrino's plugin system enables extending functionality with new credential types, actions, and MCP tools. Plugins are distributed as WebAssembly (WASM) modules that run in a sandboxed environment.

## Architecture

```
PluginRegistry
      │
      ├── HttpPlugin (built-in)
      │
      └── WasmPlugin (from installed plugins)
              │
              ├── PluginManifest (parsed from plugin.toml)
              │
              └── WasmRuntime (wasmtime)
```

## What Plugins Can Do

- **Define new credential types** — Store custom data like PGP keys, SSH certificates, or OAuth tokens
- **Provide custom actions** — Execute plugin-specific operations like signing or encryption
- **Register MCP tools** — Expose new tools to AI agents via the MCP protocol

## Plugin Directory Structure

Plugins are installed to `~/.vultrino/plugins/`:

```
~/.vultrino/
├── credentials.enc
└── plugins/
    └── pgp-signing/
        ├── plugin.toml      # Manifest
        ├── plugin.wasm      # WASM module
        └── .installed.json  # Installation metadata
```

## Plugin Manifest

Each plugin requires a `plugin.toml` manifest:

```toml
[plugin]
name = "pgp-signing"
version = "1.0.0"
description = "PGP/GPG signing and verification"
author = "Your Name"
format = "wasm"
wasm_module = "pgp_signing.wasm"

[[credential_types]]
name = "pgp_key"
display_name = "PGP/GPG Key"

[[credential_types.fields]]
name = "private_key"
label = "Private Key"
type = "textarea"
required = true
secret = true

[[actions]]
name = "sign"
description = "Sign data with PGP"

[[mcp_tools]]
name = "pgp_sign"
action = "sign"
description = "Sign data with PGP"
```

## Available Plugins

| Plugin | Description | Credential Types |
|--------|-------------|------------------|
| [PGP Signing](./pgp.md) | PGP/GPG signing and verification | `pgp_key` |

## Next Steps

- [Installing Plugins](./installing.md) — How to install and manage plugins
- [Developing Plugins](./developing.md) — Create your own plugins
- [PGP Plugin](./pgp.md) — Use the PGP signing plugin
