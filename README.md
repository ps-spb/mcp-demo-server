# MCP Demo Server - Educational Implementation Series

A comprehensive three-phase educational implementation of Model Context Protocol (MCP) servers in Go, demonstrating the progression from simple stdio communication to full OAuth 2.1 authentication. This project follows the MCP 2025-06-18 specification and serves as a practical learning resource for understanding MCP concepts and server development.

## Overview

This repository contains three complete MCP server implementations, each building upon the previous phase:

1. **Phase 1 (stdio/)** - Simple stdio-based MCP server
2. **Phase 2 (network/)** - HTTP network transport server
3. **Phase 3 (auth/)** - OAuth 2.1 authenticated server

Each phase implements the same core functionality (file reading, directory listing, system information) while adding increasingly sophisticated transport and security features.

## Phase Progression

### Phase 1: Stdio Transport
- **Purpose**: Learn MCP fundamentals
- **Transport**: Standard input/output (stdio)
- **Features**: Basic tool implementation, JSON-RPC 2.0 communication
- **Use Case**: Local development, CLI integration
- **Directory**: `stdio/`

### Phase 2: Network Transport
- **Purpose**: Understand network-based MCP
- **Transport**: HTTP with JSON-RPC over HTTP
- **Features**: HTTP server, concurrent connections, environment configuration
- **Use Case**: Network services, web integration
- **Directory**: `network/`

### Phase 3: Authenticated Transport
- **Purpose**: Production-ready security
- **Transport**: HTTPS with OAuth 2.1 authentication
- **Features**: Bearer tokens, security headers, TLS, token validation
- **Use Case**: Production deployment, secure services
- **Directory**: `auth/`

## Quick Start

### Prerequisites
- Go 1.24.5 or later
- Compatible with MCP 2025-06-18 specification

### Running Each Phase

```bash
# Phase 1 - Stdio Transport
cd stdio/
go build -o ~/bin/mcp-demo-server-stdio .
mcp-demo-server-stdio

# Phase 2 - Network Transport  
cd network/
go build -o ~/bin/mcp-demo-server-network .
mcp-demo-server-network
# Available at http://localhost:8080

# Phase 3 - OAuth 2.1 Authentication
cd auth/
go build -o ~/bin/mcp-demo-server-auth .
mcp-demo-server-auth
# Available at https://localhost:8443
```

### Testing Each Phase

```bash
# Phase 1: Use any MCP-compatible client with stdio transport

# Phase 2: HTTP requests
curl -X POST http://localhost:8080/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc": "2.0", "method": "tools/list", "id": 1}'

# Phase 3: OAuth 2.1 authentication flow
# 1. Get token
TOKEN=$(curl -s -X POST https://localhost:8443/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials" | jq -r '.access_token')

# 2. Use authenticated endpoint
curl -X POST https://localhost:8443/mcp \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc": "2.0", "method": "tools/list", "id": 1}'
```

## Available Tools

All phases implement the same three tools:

### read_file
- **Description**: Read the contents of any file from the filesystem
- **Parameters**: `file_path` (string, required)
- **Example**: Read configuration files, source code, logs

### list_directory
- **Description**: List the contents of any directory
- **Parameters**: `directory_path` (string, required)  
- **Example**: Explore directory structures, file organization

### get_system_info
- **Description**: Get various system information
- **Parameters**: `info_type` (string, required)
  - `os`: Operating system name
  - `arch`: System architecture  
  - `go_version`: Go runtime version
  - `working_dir`: Current working directory
- **Example**: Environment debugging, system diagnostics

## Educational Value

### Learning Objectives

1. **MCP Protocol Understanding**: Learn JSON-RPC 2.0 over different transports
2. **Transport Evolution**: Understand stdio → HTTP → HTTPS progression
3. **Security Implementation**: Learn OAuth 2.1 authentication patterns
4. **Go Development**: See clean, idiomatic Go code with proper error handling
5. **Production Readiness**: Understand security considerations for real deployments

### Code Quality Features

- **Descriptive Names**: Clear function, variable, and type names
- **Comprehensive Comments**: Detailed documentation for all major components
- **Error Handling**: Proper error checking with meaningful error messages
- **Type Safety**: Go's strong typing with struct definitions
- **Security Best Practices**: Modern security headers, TLS configuration
- **Clean Architecture**: Separation of concerns, middleware patterns

## Documentation

### Project Documentation
- `docs/mcp-full.txt` - Complete MCP specification reference
- `docs/oauth-2.1-spec.md` - OAuth 2.1 implementation requirements

### Phase-Specific Documentation
- `stdio/README.md` - Phase 1 implementation details
- `network/README.md` - Phase 2 implementation details
- `auth/README.md` - Phase 3 implementation details

## MCP Compliance

All phases implement the MCP 2025-06-18 specification:

- ✅ Official MCP Go SDK usage
- ✅ Proper tool registration and discovery
- ✅ Structured tool output format
- ✅ Comprehensive error handling
- ✅ JSON-RPC 2.0 compliance
- ✅ Transport-appropriate security

### OAuth 2.1 Compliance (Phase 3)

- ✅ Bearer token authentication
- ✅ Protected Resource Metadata endpoint
- ✅ Resource-specific token validation
- ✅ Token expiration and cleanup
- ✅ Proper HTTP status codes
- ✅ Security headers implementation

## Development Environment

### Project Structure
```
/server/
├── README.md              # This file
├── docs/                  # Documentation
│   ├── mcp-full.txt      # MCP specification
│   └── oauth-2.1-spec.md # OAuth 2.1 requirements
├── stdio/                 # Phase 1: Stdio transport
│   ├── main.go
│   ├── go.mod
│   └── README.md
├── network/               # Phase 2: HTTP transport
│   ├── main.go
│   ├── go.mod
│   └── README.md
└── auth/                  # Phase 3: OAuth 2.1 auth
    ├── main.go
    ├── go.mod
    └── README.md
```

### Environment Variables

```bash
# Phase 2 & 3: Server port configuration
MCP_SERVER_PORT=8080      # Default: 8080 (Phase 2), 8443 (Phase 3)

# Phase 3: TLS configuration
MCP_USE_TLS=true          # Default: true (set to "false" to disable)
```

## Security Considerations

### Phase 1 (Stdio)
- Basic input validation
- File system access controls
- No network exposure

### Phase 2 (Network)
- HTTP server security
- Input validation and sanitization
- Basic error handling
- No authentication (educational only)

### Phase 3 (OAuth 2.1)
- ✅ Bearer token authentication
- ✅ TLS encryption
- ✅ Security headers
- ✅ Token validation and expiration
- ✅ Resource-specific tokens
- ✅ Secure cipher suites
- ✅ Connection timeouts

### Production Deployment

For production use of Phase 3, consider:

1. **Certificate Management**: Use proper TLS certificates
2. **Token Storage**: Persistent, secure token storage (Redis, database)
3. **Client Authentication**: Implement client authentication for token endpoint
4. **Rate Limiting**: Add rate limiting to prevent abuse
5. **Audit Logging**: Comprehensive audit logging
6. **Input Validation**: Enhanced validation and sanitization
7. **PKCE Support**: Implement PKCE for authorization code flow
8. **Scope-Based Authorization**: Implement proper scope validation

## Contributing

This is an educational project designed for learning MCP concepts. Feel free to:

- Extend with additional tools
- Implement additional authentication methods
- Add more comprehensive error handling
- Improve security features
- Add tests and documentation

## License

This project is provided as-is for educational purposes.

## Support

For questions about MCP specification or implementation:
- MCP Specification: https://modelcontextprotocol.io/
- MCP Go SDK: https://github.com/modelcontextprotocol/go-sdk

---

*This educational implementation demonstrates the progression from basic MCP concepts to production-ready authenticated servers, providing a comprehensive learning path for developers interested in MCP server development.*