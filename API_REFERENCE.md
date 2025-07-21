# MCP Server API Reference

## Overview

This document provides a complete API reference for all three phases of the MCP server implementation. Each phase implements the same MCP tools but with different transport and authentication mechanisms.

## Table of Contents

1. [Phase 1: Stdio Transport API](#phase-1-stdio-transport-api)
2. [Phase 2: Network Transport API](#phase-2-network-transport-api)
3. [Phase 3: OAuth 2.1 Authentication API](#phase-3-oauth-21-authentication-api)
4. [MCP Tools Reference](#mcp-tools-reference)
5. [Error Handling](#error-handling)
6. [Rate Limits and Constraints](#rate-limits-and-constraints)

## Phase 1: Stdio Transport API

### Transport Protocol
- **Protocol**: JSON-RPC 2.0 over standard input/output
- **Content-Type**: application/json (implicit)
- **Authentication**: None

### Connection Method
```bash
# Direct execution with stdin/stdout
echo '{"jsonrpc":"2.0","method":"tools/list","id":1}' | mcp-demo-server-stdio
```

### Supported Methods
- `tools/list` - List available tools
- `tools/call` - Execute a specific tool

## Phase 2: Network Transport API

### Base URL
```
http://localhost:8080
```

### Transport Protocol
- **Protocol**: JSON-RPC 2.0 over HTTP POST
- **Content-Type**: application/json
- **Authentication**: None
- **CORS**: Enabled for all origins

### Endpoints

#### POST /mcp
Main MCP endpoint for all JSON-RPC requests.

**Headers:**
```
Content-Type: application/json
```

**Request Format:**
```json
{
  "jsonrpc": "2.0",
  "method": "string",
  "params": {},
  "id": "string|number|null"
}
```

**Response Format:**
```json
{
  "jsonrpc": "2.0",
  "result": {},
  "id": "string|number|null"
}
```

#### POST / (Root)
Alias for `/mcp` endpoint. Same functionality and format.

### Supported Methods
- `tools/list` - List available tools
- `tools/call` - Execute a specific tool

## Phase 3: OAuth 2.1 Authentication API

### Base URL
```
http://localhost:8443  (default, configurable via MCP_SERVER_PORT)
https://localhost:8443 (when MCP_USE_TLS=true)
```

### Authentication Flow
OAuth 2.1 Client Credentials Grant implementation following RFC 6749 and RFC 6750.

### OAuth 2.1 Endpoints

#### GET /.well-known/oauth-authorization-server
OAuth 2.0 Protected Resource Metadata endpoint (RFC 8414).

**Authentication:** None required  
**Content-Type:** application/json

**Response:**
```json
{
  "issuer": "http://localhost:8443",
  "authorization_endpoint": "http://localhost:8443/oauth/authorize",
  "token_endpoint": "http://localhost:8443/oauth/token", 
  "resource": "http://localhost:8443",
  "scopes_supported": ["read", "write", "admin"],
  "response_types_supported": ["code"],
  "grant_types_supported": ["authorization_code", "client_credentials"],
  "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
  "code_challenge_methods_supported": ["S256"]
}
```

**Response Status Codes:**
- `200 OK` - Metadata retrieved successfully
- `405 Method Not Allowed` - Non-GET request

#### POST /oauth/token
Token endpoint for OAuth 2.1 Client Credentials Grant.

**Authentication:** None required (this IS the authentication endpoint)  
**Content-Type:** application/x-www-form-urlencoded

**Request Parameters:**
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| grant_type | string | Yes | Must be "client_credentials" |

**Request Example:**
```bash
curl -X POST http://localhost:8443/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials"
```

**Success Response (200 OK):**
```json
{
  "access_token": "dGVzdF9zZWNyZXRfa2V5X2Zvcl9kZW1vX3B1cnBvc2U=",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "read write"
}
```

**Error Response (400 Bad Request):**
```json
{
  "error": "unsupported_grant_type",
  "error_description": "Only client_credentials grant type is supported"
}
```

**Response Status Codes:**
- `200 OK` - Token issued successfully
- `400 Bad Request` - Invalid grant type or malformed request
- `405 Method Not Allowed` - Non-POST request
- `500 Internal Server Error` - Server error generating token

### Protected MCP Endpoints

#### POST /mcp
Main MCP endpoint requiring Bearer token authentication.

**Authentication:** Bearer token required  
**Content-Type:** application/json

**Headers:**
```
Authorization: Bearer <access_token>
Content-Type: application/json
```

**Request Format:**
```json
{
  "jsonrpc": "2.0",
  "method": "string",
  "params": {},
  "id": "string|number|null"
}
```

**Success Response (200 OK):**
```json
{
  "jsonrpc": "2.0",
  "result": {},
  "id": "string|number|null"
}
```

**Authentication Error (401 Unauthorized):**
```json
{
  "error": "invalid_token",
  "error_description": "missing Authorization header"
}
```

**Authentication Error Headers:**
```
WWW-Authenticate: Bearer realm="MCP Server", error="invalid_token"
Content-Type: application/json
```

#### POST / (Root)
Alias for `/mcp` endpoint with same authentication requirements.

### Security Headers
All responses include comprehensive security headers:

```
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block
Strict-Transport-Security: max-age=31536000; includeSubDomains
Content-Security-Policy: default-src 'self'
```

### Token Lifecycle
- **Token Format**: Base64URL-encoded random 32-byte value
- **Token Type**: Bearer (RFC 6750)
- **Default Expiry**: 3600 seconds (1 hour)
- **Scope**: "read write" (basic implementation)
- **Storage**: In-memory with automatic expiration cleanup
- **Resource Binding**: Tokens are bound to the issuing server's resource URI

## MCP Tools Reference

All three phases implement the same set of MCP tools with identical interfaces.

### tools/list

Lists all available tools on the server.

**Method:** `tools/list`  
**Parameters:** None

**Request Example:**
```json
{
  "jsonrpc": "2.0",
  "method": "tools/list",
  "id": 1
}
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "result": {
    "tools": [
      {
        "name": "read_file",
        "description": "Read the contents of a file from the filesystem",
        "inputSchema": {
          "type": "object",
          "properties": {
            "file_path": {
              "type": "string",
              "description": "Path to the file to read"
            }
          },
          "required": ["file_path"]
        }
      },
      {
        "name": "list_directory", 
        "description": "List the contents of a directory",
        "inputSchema": {
          "type": "object",
          "properties": {
            "directory_path": {
              "type": "string",
              "description": "Path to the directory to list"
            }
          },
          "required": ["directory_path"]
        }
      },
      {
        "name": "get_system_info",
        "description": "Get various system information (OS, architecture, Go version, working directory)",
        "inputSchema": {
          "type": "object",
          "properties": {
            "info_type": {
              "type": "string", 
              "description": "Type of system information to retrieve",
              "enum": ["os", "arch", "go_version", "working_dir"]
            }
          },
          "required": ["info_type"]
        }
      }
    ]
  },
  "id": 1
}
```

### tools/call

Executes a specific tool with provided arguments.

**Method:** `tools/call`  
**Parameters:**
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| name | string | Yes | Name of the tool to execute |
| arguments | object | Yes | Tool-specific arguments |

**Request Example:**
```json
{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "name": "read_file",
    "arguments": {
      "file_path": "/etc/hostname"
    }
  },
  "id": 2
}
```

### Tool: read_file

Reads the contents of a file from the filesystem.

**Tool Name:** `read_file`

**Arguments:**
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| file_path | string | Yes | Absolute or relative path to the file to read |

**Request Example:**
```json
{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "name": "read_file",
    "arguments": {
      "file_path": "/etc/hostname"
    }
  },
  "id": 1
}
```

**Success Response:**
```json
{
  "jsonrpc": "2.0",
  "result": {
    "content": [
      {
        "type": "text",
        "text": "File: /etc/hostname\n\nmyhostname.local"
      }
    ]
  },
  "id": 1
}
```

**Error Cases:**
- File does not exist
- File is not readable (permissions)
- Invalid file path format
- File path parameter missing

**Error Response Example:**
```json
{
  "jsonrpc": "2.0", 
  "error": {
    "message": "file does not exist: /nonexistent/file.txt"
  },
  "id": 1
}
```

### Tool: list_directory

Lists the contents of a directory with file type identification.

**Tool Name:** `list_directory`

**Arguments:**
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| directory_path | string | Yes | Absolute or relative path to the directory to list |

**Request Example:**
```json
{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "name": "list_directory", 
    "arguments": {
      "directory_path": "/tmp"
    }
  },
  "id": 1
}
```

**Success Response:**
```json
{
  "jsonrpc": "2.0",
  "result": {
    "content": [
      {
        "type": "text",
        "text": "Directory: /tmp\n\n- file1.txt (file)\n- subdir (directory)\n- data.json (file)"
      }
    ]
  },
  "id": 1
}
```

**Empty Directory Response:**
```json
{
  "jsonrpc": "2.0",
  "result": {
    "content": [
      {
        "type": "text", 
        "text": "Directory: /empty\n\n(empty directory)"
      }
    ]
  },
  "id": 1
}
```

**Error Cases:**
- Directory does not exist
- Path is not a directory (is a file)
- Directory is not readable (permissions)
- Directory path parameter missing

**Error Response Example:**
```json
{
  "jsonrpc": "2.0",
  "error": {
    "message": "directory does not exist: /nonexistent/dir"
  },
  "id": 1
}
```

### Tool: get_system_info

Retrieves various system information for debugging and environment discovery.

**Tool Name:** `get_system_info`

**Arguments:**
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| info_type | string | Yes | Type of system information to retrieve |

**Supported info_type Values:**
| Value | Description | Example Output |
|-------|-------------|----------------|
| os | Operating system name | "darwin", "linux", "windows" |
| arch | System architecture | "amd64", "arm64", "386" |
| go_version | Go runtime version | "go1.21.0", "go1.20.5" |
| working_dir | Current working directory | "/Users/username/project" |

**Request Examples:**

```json
{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "name": "get_system_info",
    "arguments": {
      "info_type": "os"
    }
  },
  "id": 1
}
```

**Success Responses:**

**OS Information:**
```json
{
  "jsonrpc": "2.0",
  "result": {
    "content": [
      {
        "type": "text",
        "text": "Operating System: darwin"
      }
    ]
  },
  "id": 1
}
```

**Architecture Information:**
```json
{
  "jsonrpc": "2.0",
  "result": {
    "content": [
      {
        "type": "text",
        "text": "Architecture: amd64"
      }
    ]
  },
  "id": 1
}
```

**Go Version Information:**
```json
{
  "jsonrpc": "2.0",
  "result": {
    "content": [
      {
        "type": "text",
        "text": "Go Version: go1.21.0"
      }
    ]
  },
  "id": 1
}
```

**Working Directory Information:**
```json
{
  "jsonrpc": "2.0",
  "result": {
    "content": [
      {
        "type": "text",
        "text": "Working Directory: /Users/username/mcp-demo/server"
      }
    ]
  },
  "id": 1
}
```

**Error Cases:**
- Invalid info_type value (not in enum)
- info_type parameter missing
- System error retrieving working directory

**Error Response Example:**
```json
{
  "jsonrpc": "2.0",
  "error": {
    "message": "invalid info_type: invalid_type. Valid options: os, arch, go_version, working_dir"
  },
  "id": 1
}
```

## Error Handling

### JSON-RPC 2.0 Error Format

All errors follow JSON-RPC 2.0 specification:

```json
{
  "jsonrpc": "2.0",
  "error": {
    "message": "Human-readable error message"
  },
  "id": "request_id"
}
```

### HTTP Status Codes

#### Phase 2 (Network) Status Codes
- `200 OK` - All requests (success and JSON-RPC errors)
- `400 Bad Request` - Invalid JSON or malformed JSON-RPC
- `405 Method Not Allowed` - Non-POST requests
- `500 Internal Server Error` - Server errors

#### Phase 3 (Authenticated) Status Codes
- `200 OK` - Successful requests
- `400 Bad Request` - Invalid JSON, malformed JSON-RPC, or invalid OAuth parameters
- `401 Unauthorized` - Missing, invalid, or expired Bearer token
- `405 Method Not Allowed` - Invalid HTTP method
- `500 Internal Server Error` - Server errors

### Authentication Errors (Phase 3 Only)

#### Missing Authorization Header
```json
{
  "error": "invalid_token",
  "error_description": "missing Authorization header"
}
```

#### Invalid Bearer Token Format  
```json
{
  "error": "invalid_token",
  "error_description": "invalid Authorization header format, expected Bearer token"
}
```

#### Token Not Found or Expired
```json
{
  "error": "invalid_token", 
  "error_description": "invalid or expired token"
}
```

#### Token Expired
```json
{
  "error": "invalid_token",
  "error_description": "token has expired"  
}
```

#### Resource Mismatch
```json
{
  "error": "invalid_token",
  "error_description": "token not valid for this resource"
}
```

### Tool-Specific Errors

#### File System Errors
```json
{
  "jsonrpc": "2.0",
  "error": {
    "message": "file does not exist: /path/to/file"
  },
  "id": 1
}
```

```json
{
  "jsonrpc": "2.0", 
  "error": {
    "message": "failed to read file: permission denied"
  },
  "id": 1
}
```

#### Parameter Validation Errors
```json
{
  "jsonrpc": "2.0",
  "error": {
    "message": "file_path parameter is required"
  },
  "id": 1
}
```

```json
{
  "jsonrpc": "2.0",
  "error": {
    "message": "invalid info_type: xyz. Valid options: os, arch, go_version, working_dir"
  },
  "id": 1
}
```

#### Unknown Tool Errors
```json
{
  "jsonrpc": "2.0",
  "error": {
    "message": "unknown tool: nonexistent_tool"
  },
  "id": 1
}
```

## Rate Limits and Constraints

### Phase 1 (Stdio)
- **Connection Limit**: Single connection (stdio)
- **Concurrency**: Single-threaded request processing
- **Rate Limit**: None (process-based)
- **Timeout**: None (controlled by caller)

### Phase 2 (Network)
- **Connection Limit**: Operating system limits
- **Concurrency**: Go HTTP server default (no explicit limit)
- **Rate Limit**: None implemented
- **Timeout**: Default Go HTTP server timeouts
- **Request Size**: No explicit limit

### Phase 3 (Authenticated)
- **Connection Limit**: Operating system limits
- **Concurrency**: Go HTTP server with configured timeouts
- **Rate Limit**: None implemented (production should add)
- **Timeouts**:
  - Read Timeout: 10 seconds
  - Write Timeout: 10 seconds
  - Idle Timeout: 60 seconds
- **Request Size**: No explicit limit
- **Token Limits**:
  - Token Lifetime: 3600 seconds (1 hour)
  - Token Storage: In-memory (no persistence)
  - Concurrent Tokens: No limit

### File System Constraints
- **File Size**: No explicit limit (limited by available memory)
- **Path Length**: Operating system limits
- **File Permissions**: Respects OS file permissions
- **Directory Depth**: No explicit limit
- **Concurrent File Operations**: No explicit limit

### Production Recommendations
- **Rate Limiting**: Implement per-client rate limiting
- **Request Size Limits**: Add maximum request body size limits
- **Connection Limits**: Configure maximum concurrent connections
- **Token Management**: Use persistent storage with cleanup jobs
- **Monitoring**: Add metrics and alerting for usage patterns
- **Circuit Breakers**: Implement circuit breakers for file system operations

## OpenAPI Specification

### Phase 3 (Authenticated) OpenAPI 3.0 Spec

```yaml
openapi: 3.0.3
info:
  title: MCP Demo Server API
  description: OAuth 2.1 authenticated MCP server with file system tools
  version: 3.0.0
  
servers:
  - url: http://localhost:8443
    description: Local development server

paths:
  /.well-known/oauth-authorization-server:
    get:
      summary: OAuth 2.0 Protected Resource Metadata
      responses:
        '200':
          description: OAuth metadata
          content:
            application/json:
              schema:
                type: object
                
  /oauth/token:
    post:
      summary: OAuth 2.1 Token Endpoint
      requestBody:
        required: true
        content:
          application/x-www-form-urlencoded:
            schema:
              type: object
              properties:
                grant_type:
                  type: string
                  enum: [client_credentials]
              required: [grant_type]
      responses:
        '200':
          description: Access token issued
          content:
            application/json:
              schema:
                type: object
                properties:
                  access_token:
                    type: string
                  token_type:
                    type: string
                    enum: [Bearer]
                  expires_in:
                    type: integer
                  scope:
                    type: string
                    
  /mcp:
    post:
      summary: MCP Protocol Endpoint
      security:
        - BearerAuth: []
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              properties:
                jsonrpc:
                  type: string
                  enum: ["2.0"]
                method:
                  type: string
                  enum: [tools/list, tools/call]
                params:
                  type: object
                id:
                  oneOf:
                    - type: string
                    - type: number
                    - type: "null"
              required: [jsonrpc, method, id]
      responses:
        '200':
          description: MCP response
          content:
            application/json:
              schema:
                type: object
        '401':
          description: Authentication required
          
components:
  securitySchemes:
    BearerAuth:
      type: http
      scheme: bearer
      bearerFormat: token
```

This comprehensive API reference provides complete documentation for all endpoints, methods, parameters, responses, and error conditions across all three phases of the MCP server implementation.