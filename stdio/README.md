# MCP Demo Server - Phase 1 (Stdio Transport)

A simple Model Context Protocol (MCP) server implementation in Go for educational purposes. This server demonstrates the core concepts of MCP by providing basic file system and system information tools using stdio transport.

## Features

This MCP server implements three primary tools:

1. **File Reader** (`read_file`) - Read the contents of any file from the filesystem
2. **Directory Lister** (`list_directory`) - List the contents of any directory
3. **System Information** (`get_system_info`) - Get various system information (OS, architecture, Go version, working directory)

## Requirements

- Go 1.24.5 or later
- Compatible with MCP 2025-06-18 specification

## Installation

1. Clone or download this repository
2. Navigate to the server directory
3. Install dependencies:
   ```bash
   go mod download
   ```

## Usage

### Building the Server

Build the server binary to ~/bin/ for execution:

```bash
go build -o ~/bin/mcp-demo-server .
```

### Running the Server

The server runs using stdio transport, which means it communicates via standard input/output:

```bash
mcp-demo-server
```

### Testing the Server

You can test the server using any MCP-compatible client. The server will log its startup information and wait for MCP protocol messages.

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

## Code Structure

The server follows Go best practices with:

- **Clear separation of concerns**: Each tool is implemented as a separate function
- **Comprehensive error handling**: All operations include proper error checking and meaningful error messages
- **Descriptive naming**: Functions, variables, and types use descriptive names
- **Detailed comments**: All major components are documented
- **Type safety**: Uses Go's strong typing system with struct definitions for parameters

## MCP Compliance

This server implements the MCP 2025-06-18 specification:

- Uses official MCP Go SDK
- Implements proper tool registration
- Follows structured tool output format
- Includes comprehensive error handling
- Uses stdio transport for communication

## Development Notes

This is Phase 1 of a three-phase implementation:

1. **Phase 1** (This version): Simple stdio-based MCP server
2. **Phase 2**: Convert to network listener (HTTP/TCP) - see `../network/`
3. **Phase 3**: Add OAuth 2.1 authentication and security features - see `../auth/`

This implementation focuses on clarity and educational value, making it easy to understand MCP concepts and server architecture. The stdio transport is perfect for learning the basics of MCP protocol communication.

## Contributing

This is a demo/educational project. Feel free to extend it with additional tools or modify it for your learning purposes.

## License

This project is provided as-is for educational purposes.