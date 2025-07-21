# MCP Server Architecture Documentation

## Overview

This document explains the architectural decisions and design patterns used across the three-phase MCP server implementation. Each phase builds upon the previous one, demonstrating the evolution from basic MCP functionality to production-ready OAuth 2.1 authentication.

## Table of Contents

1. [Three-Phase Architecture](#three-phase-architecture)
2. [Design Patterns](#design-patterns)
3. [Security Evolution](#security-evolution)
4. [Code Organization](#code-organization)
5. [Protocol Implementation](#protocol-implementation)
6. [Error Handling Strategy](#error-handling-strategy)
7. [Production Considerations](#production-considerations)

## Three-Phase Architecture

### Phase 1: Stdio Transport (Foundation)
**Purpose**: Establish MCP protocol fundamentals
**Transport**: Standard input/output (stdio)
**Architecture Pattern**: Simple function-based design

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   MCP Client    │ <->│  Stdio Transport │ <->│   MCP Server    │
│                 │    │                  │    │   (Phase 1)     │
└─────────────────┘    └──────────────────┘    └─────────────────┘
                                               ┌─────────────────┐
                                               │ Direct Function │
                                               │     Calls       │
                                               └─────────────────┘
```

**Key Design Decisions**:
- **Direct SDK Integration**: Uses MCP Go SDK transport layer directly
- **Simple Tool Registration**: Tools registered with SDK without abstraction
- **Minimal Error Handling**: Basic error propagation through SDK
- **No Authentication**: Focus on MCP protocol understanding

**Learning Objectives**:
- MCP protocol basics (JSON-RPC 2.0 over stdio)
- Tool registration and discovery patterns  
- Structured response formatting
- Error handling within MCP specification

### Phase 2: Network Transport (Scalability)
**Purpose**: Add network capabilities for multi-client scenarios
**Transport**: HTTP with JSON-RPC over HTTP POST
**Architecture Pattern**: HTTP server with MCP protocol bridging

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   HTTP Client   │ <->│   HTTP Server    │    │   MCP Server    │
│                 │    │                  │    │   (Phase 2)     │
└─────────────────┘    └──────────────────┘    └─────────────────┘
                                |                        │
                       ┌──────────────────┐    ┌─────────────────┐
                       │ JSON-RPC Bridge  │ <->│ Tool Functions  │
                       │     Handler      │    │   (Duplicated)  │
                       └──────────────────┘    └─────────────────┘
```

**Key Design Decisions**:
- **HTTP Bridge Pattern**: Custom JSON-RPC over HTTP implementation
- **Tool Logic Duplication**: Tools reimplemented for HTTP handling (educational)
- **CORS Support**: Enables browser-based MCP clients
- **Environment Configuration**: Port configuration via environment variables
- **No Authentication**: Open HTTP endpoints for learning

**Learning Objectives**:
- Network protocol handling (HTTP server setup)
- JSON-RPC over HTTP implementation patterns
- Concurrent request handling
- CORS configuration for web clients

### Phase 3: Authenticated Transport (Security)
**Purpose**: Production-ready security with OAuth 2.1 authentication
**Transport**: HTTP(S) with comprehensive authentication and security
**Architecture Pattern**: Layered security with middleware pattern

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│  OAuth Client   │ <->│  Security Layer  │    │   MCP Server    │
│                 │    │                  │    │   (Phase 3)     │
└─────────────────┘    └──────────────────┘    └─────────────────┘
         │                        │                        │
    ┌──────────┐         ┌──────────────────┐    ┌─────────────────┐
    │  Token   │ <------ │  OAuth 2.1       │    │ MCP Protocol    │
    │ Endpoint │         │ Authentication    │    │    Handler      │
    └──────────┘         └──────────────────┘    └─────────────────┘
         │                        │                        │
    ┌──────────┐         ┌──────────────────┐    ┌─────────────────┐
    │Metadata  │         │   Middleware     │ <->│ Tool Functions  │
    │Endpoint  │         │   Pattern        │    │  (HTTP-based)   │
    └──────────┘         └──────────────────┘    └─────────────────┘
```

**Key Design Decisions**:
- **Middleware Architecture**: Clean separation of authentication and business logic
- **OAuth 2.1 Compliance**: Full specification implementation with Bearer tokens
- **Security Headers**: Comprehensive security header implementation
- **TLS Configuration**: Modern cipher suites and security settings
- **Token Management**: In-memory storage with expiration and cleanup
- **Resource Validation**: Prevents confused deputy attacks

**Learning Objectives**:
- OAuth 2.1 authentication patterns
- HTTP middleware implementation
- Security header configuration
- Token lifecycle management
- Production security considerations

## Design Patterns

### 1. Progressive Enhancement Pattern
Each phase builds upon the previous one while maintaining the same core functionality:

```go
// Phase 1: Direct MCP SDK usage
mcp.AddTool(server, toolDef, toolFunc)

// Phase 2: HTTP bridging with tool reimplementation  
func handleMCPRequest(server *mcp.Server, req *JSONRPCRequest) JSONRPCResponse {
    // Custom JSON-RPC handling with tool logic duplication
}

// Phase 3: Authenticated HTTP with middleware
protectedHandler := authenticationMiddleware(mcpHandler)
```

**Benefits**:
- Clear learning progression from simple to complex
- Consistent functionality across all phases
- Easy comparison of different approaches
- Demonstrates evolution of real-world systems

### 2. Middleware Pattern (Phase 3)
**Implementation**: HTTP middleware for cross-cutting concerns

```go
func authenticationMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        // Authentication logic
        if authenticated {
            next.ServeHTTP(w, r) // Chain to next handler
        } else {
            // Return authentication error
        }
    })
}
```

**Benefits**:
- Separation of concerns (auth vs business logic)
- Reusable across different endpoints
- Easy to test and maintain
- Standard Go HTTP pattern

### 3. Tool Abstraction Pattern
**Consistent Tool Interface** across all phases:

```go
// Common tool signature pattern
func toolFunction(ctx context.Context, session *mcp.ServerSession, 
    params *mcp.CallToolParamsFor[ToolParams]) (*mcp.CallToolResultFor[any], error)
```

**Evolution**:
- Phase 1: Direct SDK integration
- Phase 2: Manual JSON-RPC handling with tool logic duplication
- Phase 3: HTTP-based with authentication context

### 4. Configuration Pattern
**Environment-Based Configuration** with sensible defaults:

```go
port := os.Getenv("MCP_SERVER_PORT")
if port == "" {
    port = "8443" // Secure default
}

useTLS := os.Getenv("MCP_USE_TLS") != "false" // Secure by default
```

**Benefits**:
- Easy deployment configuration
- Secure defaults (HTTPS enabled, secure ports)
- Development-friendly overrides
- Cloud-native configuration pattern

## Security Evolution

### Phase 1: Basic Security
- File system access validation
- Input parameter validation
- No network exposure
- Process-level isolation

### Phase 2: Network Security  
- HTTP server security
- Input sanitization
- Basic error handling
- CORS configuration
- **Note**: No authentication (educational only)

### Phase 3: Production Security
- **Authentication**: OAuth 2.1 Bearer token validation
- **Authorization**: Token-based access control
- **Transport Security**: TLS with modern cipher suites
- **Security Headers**: HSTS, CSP, X-Frame-Options, etc.
- **Token Security**: Secure generation, expiration, cleanup
- **Attack Prevention**: Resource validation, confused deputy protection
- **Audit Logging**: Security event logging
- **Error Handling**: No information leakage

## Code Organization

### Directory Structure
```
/server/
├── README.md              # Project overview
├── ARCHITECTURE.md        # This document
├── TESTING_STATUS.md      # Testing and status documentation
├── docs/                  # Specification and integration docs
│   ├── mcp-full.txt      # MCP specification
│   ├── oauth-2.1-spec.md # OAuth 2.1 requirements
│   └── azure-enterprise-integration.md # Azure integration guide
├── stdio/                 # Phase 1: Stdio transport
├── network/              # Phase 2: HTTP transport  
└── auth/                 # Phase 3: OAuth 2.1 authentication
```

### File Organization Pattern
Each phase maintains consistent file structure:
- `main.go`: Complete implementation in single file (educational)
- `README.md`: Phase-specific documentation with examples
- `go.mod/go.sum`: Go module definition and dependencies

### Code Structure Pattern
```go
// 1. Package documentation and imports
// 2. Data structures and types  
// 3. Global state (minimal)
// 4. Core functionality functions
// 5. HTTP handlers (Phases 2&3)
// 6. Main function with configuration
```

## Protocol Implementation

### JSON-RPC 2.0 Compliance
All phases implement proper JSON-RPC 2.0 formatting:

```go
type JSONRPCRequest struct {
    JSONRpc string      `json:"jsonrpc"`    // Always "2.0"
    Method  string      `json:"method"`     // MCP method name
    Params  interface{} `json:"params"`     // Method parameters
    ID      interface{} `json:"id"`         // Request correlation ID
}

type JSONRPCResponse struct {
    JSONRpc string      `json:"jsonrpc"`    // Always "2.0"  
    Result  interface{} `json:"result"`     // Success response
    Error   interface{} `json:"error"`      // Error response
    ID      interface{} `json:"id"`         // Matches request ID
}
```

### MCP Tool Implementation Pattern
Consistent tool response structure:

```go
return &mcp.CallToolResultFor[any]{
    Content: []mcp.Content{
        &mcp.TextContent{
            Text: result,
        },
    },
}, nil
```

### Error Handling Pattern
Structured error responses with proper HTTP status codes:

```go
// Success: 200 OK with result
// Client Error: 400 Bad Request with error details
// Auth Error: 401 Unauthorized with WWW-Authenticate header
// Server Error: 500 Internal Server Error with generic error
```

## Error Handling Strategy

### 1. Defensive Programming
- Input validation at all entry points
- Parameter existence and type checking
- File system access validation
- Network request validation

### 2. Graceful Degradation
- Non-fatal errors don't crash server
- Expired tokens automatically cleaned up
- Invalid requests return proper error responses
- Resource not found handled gracefully

### 3. Security-Conscious Error Messages
- No information leakage in error responses
- Generic error messages for authentication failures
- Detailed logging for debugging without client exposure
- Proper HTTP status codes for different error types

### 4. Error Propagation Pattern
```go
if err != nil {
    // Log error details for debugging
    log.Printf("Operation failed: %v", err)
    
    // Return appropriate error to client
    return nil, fmt.Errorf("operation failed")
}
```

## Production Considerations

### What's Included (Reference Implementation)
- ✅ OAuth 2.1 authentication with Bearer tokens
- ✅ TLS configuration with secure cipher suites
- ✅ Security headers (HSTS, CSP, etc.)
- ✅ Token expiration and cleanup
- ✅ Resource-specific token validation
- ✅ Input validation and sanitization
- ✅ Proper error handling without information leakage
- ✅ Comprehensive documentation and comments

### Production Enhancements Needed
- **Persistent Token Storage**: Redis, database instead of in-memory
- **Client Authentication**: Proper client credentials for token endpoint
- **Rate Limiting**: Prevent abuse and DoS attacks
- **Audit Logging**: Comprehensive audit trail
- **Health Checks**: Monitoring and observability endpoints
- **Graceful Shutdown**: Proper connection draining
- **Certificate Management**: Automated certificate rotation
- **Horizontal Scaling**: Load balancing and session management
- **Metrics and Monitoring**: Performance and security metrics
- **Configuration Management**: External configuration with secrets management

### Deployment Architecture (Production)
```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│  Load Balancer  │ <->│   TLS Termination│ <->│  MCP Server     │
│                 │    │                  │    │    Instance     │
└─────────────────┘    └──────────────────┘    └─────────────────┘
         │                        │                        │
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│  Rate Limiting  │    │  Certificate     │    │  Token Store    │
│     Service     │    │   Management     │    │    (Redis)      │
└─────────────────┘    └──────────────────┘    └─────────────────┘
         │                        │                        │
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Monitoring    │    │     Logging      │    │   Database      │
│   & Metrics     │    │   Aggregation    │    │   (Optional)    │
└─────────────────┘    └──────────────────┘    └─────────────────┘
```

## Conclusion

This three-phase architecture demonstrates the evolution from basic MCP protocol implementation to production-ready authenticated services. Each phase builds upon the previous one while maintaining clean code organization and comprehensive documentation.

The progression from stdio → network → authentication provides a complete learning path for developers implementing MCP servers, while the final phase serves as a solid foundation for production deployments with appropriate enhancements.

Key architectural principles demonstrated:
- **Progressive Enhancement**: Building complexity gradually
- **Security by Design**: Security considerations integrated throughout  
- **Clean Architecture**: Separation of concerns and proper abstraction
- **Standards Compliance**: Full MCP and OAuth 2.1 specification adherence
- **Production Readiness**: Foundation for real-world deployment

This reference implementation serves as both an educational resource and a starting point for production MCP server development.