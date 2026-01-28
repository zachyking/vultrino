# PGP Signing Plugin

The PGP signing plugin enables Vultrino to store PGP private keys and perform cryptographic signing operations.

## Installation

```bash
vultrino plugin install https://github.com/vultrino/plugin-pgp
```

Or build from source:

```bash
cd plugins/pgp-signing
cargo build --release --target wasm32-wasip1
vultrino plugin install ./plugins/pgp-signing
```

## Credential Type: pgp_key

Store a PGP private key in Vultrino.

### Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `private_key` | textarea | Yes | ASCII-armored PGP private key |
| `passphrase` | password | No | Passphrase to unlock the key |
| `key_id` | text | No | Specific key ID to use |

### Adding via CLI

```bash
vultrino add --alias my-pgp-key --type plugin:pgp-signing:pgp_key
# You will be prompted for the private key and passphrase
```

### Adding via Web UI

1. Navigate to Credentials > Add Credential
2. Select "PGP/GPG Key (pgp-signing)" from the dropdown
3. Paste your ASCII-armored private key
4. Enter passphrase if the key is encrypted
5. Click "Add Credential"

## Available Actions

### sign

Create a signature for arbitrary data. Returns a base64-encoded signature.

**Parameters:**
- `data` (string, required) — Data to sign
- `armor` (boolean, optional) — Output armored format (default: true)

### sign_cleartext

Create a PGP cleartext signed message. The message text is visible, with the signature appended.

**Parameters:**
- `message` (string, required) — Message to sign

**Example output:**
```
-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA256

Your message here
-----BEGIN PGP SIGNATURE-----

iQIzBAEBCAAdFiEE...
-----END PGP SIGNATURE-----
```

### verify

Verify a cleartext signed message.

**Parameters:**
- `data` (string, required) — Original data that was signed
- `signature` (string, required) — The cleartext signed message

**Returns:** `"true"` or `"false"`

### get_public_key

Extract the public key from the stored private key.

**Parameters:**
- `armor` (boolean, optional) — Output armored format (default: true)

## MCP Tools

When running with MCP enabled, these tools are available:

| Tool | Description |
|------|-------------|
| `pgp_sign` | Sign data and return the signature |
| `pgp_sign_cleartext` | Create a cleartext signed message |
| `pgp_verify` | Verify a signature |
| `pgp_get_public_key` | Get the public key |

### Example MCP Usage

```json
{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "name": "pgp_sign_cleartext",
    "arguments": {
      "credential": "my-pgp-key",
      "message": "I agree to these terms."
    }
  }
}
```

## Use Cases

### Git Commit Signing

Use with AI agents to sign commits:

```bash
# Configure git to use Vultrino for signing
git config --global gpg.program vultrino-gpg-wrapper
```

### Document Signing

Create verifiable signatures on documents:

```bash
vultrino request my-pgp-key --action sign_cleartext \
  --param message="I approve this document"
```

### Key Management

Securely store team PGP keys without exposing private key material:

1. Store the private key in Vultrino
2. Create API keys for team members
3. Team members can request signatures without accessing the key

## Security Considerations

- Private keys are encrypted at rest using AES-256-GCM
- Keys are only decrypted in memory during signing operations
- The WASM sandbox isolates plugin execution
- Audit logs track all signing operations
