# MCP Demo Server - Phase 2 (Network Transport)

A Model Context Protocol (MCP) server implementation in Go that demonstrates network-based communication using HTTP transport. This is the second phase of the educational MCP server series, building upon the stdio version with network capabilities.

## Features

This MCP server implements the same three primary tools as Phase 1, but with HTTP network transport:

1. **File Reader** (`read_file`) - Read the contents of any file from the filesystem
2. **Directory Lister** (`list_directory`) - List the contents of any directory
3. **System Information** (`get_system_info`) - Get various system information (OS, architecture, Go version, working directory)

## Requirements

- Go 1.24.5 or later
- Compatible with MCP 2025-06-18 specification
- Network connectivity for HTTP transport

## Installation

1. Clone or download this repository
2. Navigate to the network directory
3. Install dependencies:
   ```bash
   go mod download
   ```

## Usage

### Building the Server

Build the server binary to ~/bin/ for execution:

```bash
go build -o ~/bin/mcp-demo-server-network .
```

### Running the Server

The server runs using HTTP transport on port 8080 by default:

```bash
mcp-demo-server-network
```

You can customize the port using the `MCP_SERVER_PORT` environment variable:

```bash
MCP_SERVER_PORT=9090 mcp-demo-server-network
```

### Testing the Server

You can test the server using any MCP-compatible client that supports HTTP transport, or use HTTP clients like curl:

```bash
# Server will be available at http://localhost:8080
curl -X POST http://localhost:8080/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc": "2.0", "method": "tools/list", "id": 1}'
```

## Available Tools

### read_file
- **Description**: Read the contents of a file from the filesystem
- **Parameters**:
  - `file_path` (string, required): Path to the file to read
- **Example**: Read a configuration file or source code file

### list_directory
- **Description**: List the contents of a directory
- **Parameters**:
  - `directory_path` (string, required): Path to the directory to list
- **Example**: Explore directory structure and file organization

### get_system_info
- **Description**: Get various system information
- **Parameters**:
  - `info_type` (string, required): Type of information to retrieve
    - `os`: Operating system name
    - `arch`: System architecture
    - `go_version`: Go runtime version
    - `working_dir`: Current working directory
- **Example**: Get environment information for debugging

## Network Transport Details

This Phase 2 implementation adds:

- **HTTP Server**: Listens on configurable port (default 8080)
- **JSON-RPC over HTTP**: Handles MCP protocol messages via HTTP POST requests
- **Concurrent Handling**: Supports multiple simultaneous client connections
- **Environment Configuration**: Port configuration via `MCP_SERVER_PORT` environment variable

## Code Structure

The server maintains the same clean architecture as Phase 1 with additional network components:

- **HTTP Transport**: Uses MCP Go SDK's HTTP transport
- **Concurrent Server**: Runs MCP server and HTTP server concurrently
- **Environment Configuration**: Configurable port and network settings
- **Same Tool Implementation**: Identical business logic to Phase 1

## MCP Compliance

This server implements the MCP 2025-06-18 specification with HTTP transport:

- Uses official MCP Go SDK with HTTP transport
- Implements proper tool registration
- Follows structured tool output format
- Includes comprehensive error handling
- Uses HTTP transport for network communication
- Supports JSON-RPC 2.0 over HTTP

## Development Notes

This is Phase 2 of a three-phase implementation:

1. **Phase 1**: Simple stdio-based MCP server - see `../stdio/`
2. **Phase 2** (This version): Network listener with HTTP transport
3. **Phase 3**: Add OAuth 2.1 authentication and security features - see `../auth/`

This implementation demonstrates how to convert a stdio-based MCP server to a network-based one while maintaining the same functionality. The HTTP transport allows for more flexible deployment and integration scenarios.

## Security Considerations

This Phase 2 implementation includes basic network security practices:

- HTTP server with proper request handling
- Input validation for all parameters
- Error handling without information leakage
- Configurable network binding

**Note**: This version does not include authentication. See Phase 3 for OAuth 2.1 authentication implementation.

## Contributing

This is a demo/educational project. Feel free to extend it with additional tools or modify it for your learning purposes.

## License

This project is provided as-is for educational purposes.