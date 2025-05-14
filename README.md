# MCP Gateway

Model Context Protocol Gateway - A server for managing and proxying MCP server connections.

## Overview

MCP Gateway acts as a central proxy for Model Context Protocol servers, providing a unified interface for clients to connect to multiple MCP services through a single endpoint.

## Features

- Single endpoint for multiple MCP servers
- Server-side event (SSE) streaming support
- Simple configuration through JSON file
- Support for multiple server types (fetch, filesystem, etc.)

## Installation

### Requirements

- Rust 2024 edition or later
- Cargo package manager

### Quick Start

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/mcp-gateway.git
   cd mcp-gateway
   ```

2. Build the project:
   ```bash
   cargo build
   ```

3. Run with default configuration:
   ```bash
   ./target/debug/mcp-gateway
   ```

## Configuration

Configuration is done via a JSON file (`config.json` by default):

```json
{
  "sseProxy": {
    "allowedServers": ["fetch"],
    "authenticate": {
      "bearer": {
        "token": "your-authentication-token"
      }
    },
    "address": "0.0.0.0",
    "port": 3000,
    "workers": 4
  },
  "mcpServers": {
    "fetch": {
      "command": "command-to-start-fetch-server",
      "args": ["arg1", "arg2"]
    },
    "filesystem": {
      "command": "command-to-start-filesystem-server",
      "args": ["path/to/root"]
    }
  }
}
```

## Running as a systemd Service

For production deployments on Linux, it's recommended to run MCP Gateway as a systemd service:

1. Create a systemd service file:
   ```bash
   sudo nano /etc/systemd/system/mcp-gateway.service
   ```

2. Add the following configuration (adjust paths as needed):
   ```ini
   [Unit]
   Description=MCP Gateway Service
   After=network.target

   [Service]
   Type=simple
   User=mcp
   WorkingDirectory=/opt/mcp-gateway
   ExecStart=/opt/mcp-gateway/mcp-gateway
   Restart=on-failure
   # Optional: Environment variables
   Environment=MCP_GW_LOG=info

   [Install]
   WantedBy=multi-user.target
   ```

3. Reload systemd, enable and start the service:
   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable mcp-gateway
   sudo systemctl start mcp-gateway
   ```

4. Check the service status:
   ```bash
   sudo systemctl status mcp-gateway
   ```

5. View logs:
   ```bash
   journalctl -u mcp-gateway -f
   ```

## Building Production Releases

### Linux

1. Build an optimized release:
   ```bash
   cargo build --release
   ```

2. The binary will be available at `target/release/mcp-gateway`

3. (Optional) Strip debug symbols for smaller file size:
   ```bash
   strip target/release/mcp-gateway
   ```

4. Deploy the binary and config file:
   ```bash
   mkdir -p /opt/mcp-gateway
   cp target/release/mcp-gateway /opt/mcp-gateway/
   cp config.json /opt/mcp-gateway/
   ```

### macOS

1. Build an optimized release:
   ```bash
   cargo build --release
   ```

2. The binary will be available at `target/release/mcp-gateway`

3. Create a deployable package (optional):
   ```bash
   mkdir -p MCP-Gateway.app/Contents/MacOS
   cp target/release/mcp-gateway MCP-Gateway.app/Contents/MacOS/
   cp config.json MCP-Gateway.app/Contents/MacOS/
   ```

4. To run as a LaunchAgent, create a plist file at `~/Library/LaunchAgents/com.yourdomain.mcp-gateway.plist`:
   ```xml
   <?xml version="1.0" encoding="UTF-8"?>
   <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
   <plist version="1.0">
   <dict>
       <key>Label</key>
       <string>com.yourdomain.mcp-gateway</string>
       <key>ProgramArguments</key>
       <array>
           <string>/path/to/mcp-gateway</string>
       </array>
       <key>RunAtLoad</key>
       <true/>
       <key>KeepAlive</key>
       <true/>
       <key>WorkingDirectory</key>
       <string>/path/to/mcp-gateway/directory</string>
       <key>StandardOutPath</key>
       <string>/path/to/mcp-gateway.log</string>
       <key>StandardErrorPath</key>
       <string>/path/to/mcp-gateway.err</string>
   </dict>
   </plist>
   ```

### Windows

1. Build an optimized release:
   ```bash
   cargo build --release
   ```

2. The binary will be available at `target\release\mcp-gateway.exe`

3. To set up as a Windows Service, you can use tools like NSSM (Non-Sucking Service Manager):
   - Download NSSM from [nssm.cc](https://nssm.cc/)
   - Install the service:
     ```
     nssm install MCP-Gateway
     ```
   - Configure the service in the dialog that appears:
     - Path: path\to\mcp-gateway.exe
     - Startup directory: path\to\mcp-gateway\directory
     - Arguments: (if needed)

4. Start the service:
   ```
   nssm start MCP-Gateway
   ```

## Cross-Compilation

For cross-compilation to different target platforms:

1. Add targets:
   ```bash
   rustup target add x86_64-unknown-linux-gnu
   rustup target add x86_64-apple-darwin
   rustup target add x86_64-pc-windows-msvc
   ```

2. Build for specific targets:
   ```bash
   cargo build --release --target x86_64-unknown-linux-gnu
   cargo build --release --target x86_64-apple-darwin
   cargo build --release --target x86_64-pc-windows-msvc
   ```

Note: Cross-compilation might require additional toolchains and libraries depending on your host system.

## Command Line Options

- `--config=<path>` - Specify a custom config file path (default: ./config.json)
- `--help` - Show help message

## License

This project is licensed under the [GNU General Public License v3.0 (GPL-3.0)](https://www.gnu.org/licenses/gpl-3.0.en.html).

The GPL-3.0 is a strong copyleft license that requires anyone who distributes your code or derivative works to make the source available under the same terms. This ensures the software remains free and open source.

Key points of the GPL-3.0:
- Freedom to use, study, share, and modify the software
- Derivative works must be distributed under the same license terms
- Source code must be made available when distributing the software
- Patent rights are explicitly granted
