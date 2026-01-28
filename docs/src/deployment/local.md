# Local Development

The simplest way to run Vultrino — perfect for personal use and development.

## Quick Setup

```bash
# 1. Initialize
vultrino init

# 2. Add credentials
vultrino add --alias github-api --key ghp_xxx

# 3. Start services
vultrino web &          # Web UI on :7879
vultrino serve --mcp    # MCP server (stdio)
```

## Running Components

### Web UI Only

```bash
export VULTRINO_PASSWORD="your-password"
vultrino web
# Access at http://127.0.0.1:7879
```

### MCP Server Only

For AI agent integration:

```bash
export VULTRINO_PASSWORD="your-password"
vultrino serve --mcp
```

### HTTP Proxy

```bash
export VULTRINO_PASSWORD="your-password"
vultrino serve
# Proxy on http://127.0.0.1:7878
```

## Configuration for Local Use

The default configuration is optimized for local development:

```toml
[server]
bind = "127.0.0.1:7878"  # Localhost only
mode = "local"

[storage]
backend = "file"
```

## Using with Claude Desktop

Add to your Claude Desktop MCP configuration (`~/Library/Application Support/Claude/claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "vultrino": {
      "command": "/path/to/vultrino",
      "args": ["serve", "--mcp"],
      "env": {
        "VULTRINO_PASSWORD": "your-password"
      }
    }
  }
}
```

## Running as Background Process

### macOS (launchd)

Create `~/Library/LaunchAgents/dev.vultrino.web.plist`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>dev.vultrino.web</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/vultrino</string>
        <string>web</string>
    </array>
    <key>EnvironmentVariables</key>
    <dict>
        <key>VULTRINO_PASSWORD</key>
        <string>your-password</string>
    </dict>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
</dict>
</plist>
```

Load it:
```bash
launchctl load ~/Library/LaunchAgents/dev.vultrino.web.plist
```

### Linux (systemd user service)

Create `~/.config/systemd/user/vultrino-web.service`:

```ini
[Unit]
Description=Vultrino Web UI
After=network.target

[Service]
Type=simple
Environment="VULTRINO_PASSWORD=your-password"
ExecStart=/usr/local/bin/vultrino web
Restart=always

[Install]
WantedBy=default.target
```

Enable and start:
```bash
systemctl --user enable vultrino-web
systemctl --user start vultrino-web
```

## Tips

1. **Store password in keychain** — Use OS keychain to avoid plaintext passwords
2. **Use aliases** — Add `alias vreq='vultrino request'` to your shell
3. **Tab completion** — Generate with `vultrino completions bash > /etc/bash_completion.d/vultrino`

## Troubleshooting

### "Device not configured" error
The password prompt requires a terminal. Set `VULTRINO_PASSWORD` environment variable instead.

### "Address already in use"
Another process is using the port. Check with:
```bash
lsof -i :7879
```

### Credentials not loading
Ensure you're using the same `VULTRINO_PASSWORD` that was used when creating credentials.
