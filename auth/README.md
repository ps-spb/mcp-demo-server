# MCP Demo Server - Phase 3 (OAuth 2.1 Authentication)

A Model Context Protocol (MCP) server implementation in Go that demonstrates OAuth 2.1 authentication following the MCP 2025-06-18 specification. This is the third and final phase of the educational MCP server series, adding comprehensive authentication and security features.

## Features

This MCP server implements the same three primary tools as previous phases, but with OAuth 2.1 authentication and security features:

1. **File Reader** (`read_file`) - Read the contents of any file from the filesystem
2. **Directory Lister** (`list_directory`) - List the contents of any directory
3. **System Information** (`get_system_info`) - Get various system information (OS, architecture, Go version, working directory)

## Security Features

### OAuth 2.1 Authentication
- **Bearer Token Authentication**: Validates tokens in Authorization header
- **Token Validation**: Resource-specific token validation
- **Token Expiration**: Automatic token expiration and cleanup
- **Protected Resource Metadata**: OAuth 2.0 discovery endpoint
- **Client Credentials Grant**: Supports client_credentials grant type

### Security Headers
- **X-Content-Type-Options**: Prevents MIME type sniffing
- **X-Frame-Options**: Prevents clickjacking attacks
- **X-XSS-Protection**: Enables XSS protection
- **Strict-Transport-Security**: Enforces HTTPS connections
- **Content-Security-Policy**: Prevents code injection

### Transport Security
- **TLS Support**: Optional HTTPS with configurable TLS settings
- **Secure Ciphers**: Modern cipher suites only
- **Connection Timeouts**: Prevents resource exhaustion
- **Input Validation**: Comprehensive request validation

## Requirements

- Go 1.24.5 or later
- Compatible with MCP 2025-06-18 specification
- Network connectivity for HTTP/HTTPS transport
- Optional: TLS certificates for production use

## Installation

1. Clone or download this repository
2. Navigate to the auth directory
3. Install dependencies:
   ```bash
   go mod download
   ```

## Usage

### Building the Server

Build the server binary to ~/bin/ for execution:

```bash
go build -o ~/bin/mcp-demo-server-auth .
```

### Running the Server

The server runs using HTTPS transport on port 8443 by default:

```bash
mcp-demo-server-auth
```

### Environment Variables

- `MCP_SERVER_PORT`: Server port (default: 8443)
- `MCP_USE_TLS`: Enable TLS (default: true, set to "false" to disable)

```bash
# Run on custom port with HTTP (not recommended for production)
MCP_SERVER_PORT=9090 MCP_USE_TLS=false mcp-demo-server-auth
```

### Authentication Flow

1. **Get OAuth Metadata** (optional):
   ```bash
   curl https://localhost:8443/.well-known/oauth-authorization-server
   ```

2. **Obtain Access Token**:
   ```bash
   curl -X POST https://localhost:8443/oauth/token \
     -H "Content-Type: application/x-www-form-urlencoded" \
     -d "grant_type=client_credentials"
   ```

3. **Use Token to Access MCP API**:
   ```bash
   curl -X POST https://localhost:8443/mcp \
     -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"jsonrpc": "2.0", "method": "tools/list", "id": 1}'
   ```

### Testing the Server

Example authentication and tool usage:

```bash
# 1. Get access token
TOKEN=$(curl -s -X POST http://localhost:8443/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials" | jq -r '.access_token')

# 2. Use token to list available tools
curl -X POST http://localhost:8443/mcp \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc": "2.0", "method": "tools/list", "id": 1}'

# 3. Use a tool with authentication
curl -X POST http://localhost:8443/mcp \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc": "2.0", "method": "tools/call", "params": {"name": "get_system_info", "arguments": {"info_type": "os"}}, "id": 2}'
```

## Available Tools

### read_file
- **Description**: Read the contents of a file from the filesystem
- **Parameters**:
  - `file_path` (string, required): Path to the file to read
- **Authentication**: Bearer token required

### list_directory
- **Description**: List the contents of a directory
- **Parameters**:
  - `directory_path` (string, required): Path to the directory to list
- **Authentication**: Bearer token required

### get_system_info
- **Description**: Get various system information
- **Parameters**:
  - `info_type` (string, required): Type of information to retrieve
    - `os`: Operating system name
    - `arch`: System architecture
    - `go_version`: Go runtime version
    - `working_dir`: Current working directory
- **Authentication**: Bearer token required

## OAuth 2.1 Endpoints

### Protected Resource Metadata
- **Endpoint**: `/.well-known/oauth-authorization-server`
- **Method**: GET
- **Description**: OAuth 2.0 discovery endpoint
- **Authentication**: None required

### Token Endpoint
- **Endpoint**: `/oauth/token`
- **Method**: POST
- **Content-Type**: `application/x-www-form-urlencoded`
- **Parameters**:
  - `grant_type`: Must be "client_credentials"
- **Authentication**: None required (returns token)

### MCP Endpoint
- **Endpoint**: `/mcp` or `/`
- **Method**: POST
- **Content-Type**: `application/json`
- **Authentication**: Bearer token required

## Error Responses

### 401 Unauthorized
- Missing or invalid Authorization header
- Expired or invalid token
- Token not valid for this resource

### 403 Forbidden
- Insufficient permissions (if scope validation is implemented)

### 400 Bad Request
- Malformed OAuth request
- Invalid JSON-RPC request

## Code Structure

The server maintains clean architecture with additional authentication components:

- **OAuth 2.1 Implementation**: Token generation, validation, and metadata
- **Authentication Middleware**: Bearer token validation for all protected endpoints
- **Security Headers**: Comprehensive security header implementation
- **TLS Configuration**: Modern TLS settings with secure cipher suites
- **Token Management**: In-memory token store with expiration handling

## MCP Compliance

This server implements the MCP 2025-06-18 specification with OAuth 2.1 authentication:

- Uses official MCP Go SDK with HTTP transport
- Implements OAuth 2.1 Protected Resource Metadata
- Follows Bearer token validation requirements
- Includes comprehensive error handling with proper HTTP status codes
- Uses HTTPS transport with security headers
- Supports resource-specific token validation
- Implements token expiration and cleanup

## Development Notes

This is Phase 3 of a three-phase implementation:

1. **Phase 1**: Simple stdio-based MCP server - see `../stdio/`
2. **Phase 2**: Network listener with HTTP transport - see `../network/`
3. **Phase 3** (This version): OAuth 2.1 authentication and security features

This implementation demonstrates a production-ready MCP server with proper authentication, authorization, and security features following industry best practices.

## Security Considerations

### Production Deployment

For production use, consider:

1. **TLS Certificates**: Use proper TLS certificates instead of self-signed
2. **Token Storage**: Use persistent, secure token storage (Redis, database)
3. **Client Authentication**: Implement proper client authentication for token endpoint
4. **Rate Limiting**: Add rate limiting to prevent abuse
5. **Audit Logging**: Implement comprehensive audit logging
6. **Input Validation**: Enhanced input validation and sanitization
7. **PKCE**: Implement PKCE for authorization code flow
8. **Scopes**: Implement proper scope-based authorization

### Current Implementation

This demo implementation includes:

- ✅ Bearer token authentication
- ✅ Token expiration and validation
- ✅ Resource-specific token validation
- ✅ Security headers
- ✅ TLS support
- ✅ Input validation
- ✅ Error handling without information leakage

### Demo Limitations

- Uses in-memory token storage (not persistent)
- Self-signed certificates for TLS demo
- Simplified client credentials flow
- Basic scope validation

## Contributing

This is a demo/educational project. Feel free to extend it with additional security features or modify it for your learning purposes.

## License

This project is provided as-is for educational purposes.