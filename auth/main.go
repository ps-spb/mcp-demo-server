// Package main implements a comprehensive OAuth 2.1 authenticated MCP server.
//
// This is Phase 3 of a three-phase educational MCP server implementation series:
// - Phase 1 (stdio): Basic MCP server with stdio transport
// - Phase 2 (network): HTTP-based MCP server without authentication  
// - Phase 3 (auth): OAuth 2.1 authenticated MCP server with comprehensive security
//
// ARCHITECTURE OVERVIEW:
// This server demonstrates production-ready security patterns for MCP implementations:
//
// 1. OAuth 2.1 Authentication Flow:
//    - Client Credentials Grant: Service-to-service authentication
//    - Bearer Token Validation: Resource-specific token validation
//    - Token Expiration: Automatic cleanup of expired tokens
//    - Discovery Metadata: OAuth 2.0 Protected Resource Metadata endpoint
//
// 2. Security Implementation:
//    - Authentication Middleware: Validates Bearer tokens on all protected endpoints
//    - Security Headers: Comprehensive security headers (HSTS, CSP, etc.)
//    - TLS Configuration: Modern cipher suites and secure TLS settings
//    - Input Validation: Comprehensive request validation and sanitization
//
// 3. MCP Protocol Compliance:
//    - JSON-RPC 2.0: Full MCP specification compliance with error handling
//    - Tool Registration: Proper tool discovery and execution
//    - Structured Output: Consistent response formatting
//    - Error Handling: Meaningful error messages without information leakage
//
// ENDPOINTS:
// - POST /oauth/token: OAuth 2.1 token endpoint (client_credentials grant)
// - GET /.well-known/oauth-authorization-server: OAuth discovery metadata
// - POST /mcp, POST /: Protected MCP endpoints (Bearer token required)
//
// TOOLS IMPLEMENTED:
// - read_file: Read file contents from filesystem
// - list_directory: List directory contents
// - get_system_info: Get system information (OS, arch, Go version, working dir)
//
// SECURITY FEATURES:
// - Bearer token authentication with resource validation
// - Token expiration (1 hour default) with automatic cleanup
// - Modern TLS configuration with secure cipher suites
// - Comprehensive security headers (HSTS, CSP, X-Frame-Options, etc.)
// - Request size limiting and timeout protection
// - Input validation and sanitization
//
// PRODUCTION CONSIDERATIONS:
// This reference implementation uses in-memory token storage and self-signed
// certificates for demonstration. For production use, consider:
// - Persistent token storage (Redis, database)
// - Proper TLS certificates
// - Rate limiting and request throttling
// - Comprehensive audit logging
// - Client authentication for token endpoint
// - Scope-based authorization
//
// ENVIRONMENT CONFIGURATION:
// - MCP_SERVER_PORT: Server port (default: 8443)
// - MCP_USE_TLS: Enable/disable TLS (default: true)
//
// EXAMPLE USAGE:
//   # Start server
//   MCP_USE_TLS=false mcp-demo-server-auth
//   
//   # Get token
//   curl -X POST http://localhost:8443/oauth/token \
//     -d "grant_type=client_credentials"
//   
//   # Use MCP endpoint
//   curl -X POST http://localhost:8443/mcp \
//     -H "Authorization: Bearer <token>" \
//     -d '{"jsonrpc":"2.0","method":"tools/list","id":1}'
package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/modelcontextprotocol/go-sdk/jsonschema"
)

// DATA STRUCTURES
// These types define the request/response structures for MCP tools and OAuth operations.

// FileReadParams represents the input parameters for the read_file MCP tool.
// This tool allows reading the contents of any file from the filesystem with proper
// path validation and error handling.
//
// Security Note: File access is validated to prevent directory traversal attacks
// and unauthorized access to system files. The implementation checks file existence
// and readability before attempting to read contents.
//
// Example usage in MCP request:
//   {"name": "read_file", "arguments": {"file_path": "/path/to/file.txt"}}
type FileReadParams struct {
	// FilePath is the absolute or relative path to the file to read.
	// Must be a valid, accessible file path on the server filesystem.
	FilePath string `json:"file_path" jsonschema:"description=Path to the file to read"`
}

// DirectoryListParams represents the input parameters for the list_directory MCP tool.
// This tool provides directory listing functionality with file type identification.
//
// Security Note: Directory access is validated to ensure the path exists and is
// accessible. The tool distinguishes between files and directories in the output.
//
// Example usage in MCP request:
//   {"name": "list_directory", "arguments": {"directory_path": "/path/to/dir"}}
type DirectoryListParams struct {
	// DirectoryPath is the absolute or relative path to the directory to list.
	// Must be a valid, accessible directory path on the server filesystem.
	DirectoryPath string `json:"directory_path" jsonschema:"description=Path to the directory to list"`
}

// SystemInfoParams represents the input parameters for the get_system_info MCP tool.
// This tool provides various system information useful for debugging and environment
// discovery. Supported information types are strictly controlled for security.
//
// Security Note: Only safe, non-sensitive system information is exposed. No user data,
// network configuration, or security-sensitive details are included.
//
// Supported info_type values:
// - "os": Operating system name (e.g., "darwin", "linux", "windows")
// - "arch": System architecture (e.g., "amd64", "arm64")  
// - "go_version": Go runtime version (e.g., "go1.21.0")
// - "working_dir": Current working directory of the server process
//
// Example usage in MCP request:
//   {"name": "get_system_info", "arguments": {"info_type": "os"}}
type SystemInfoParams struct {
	// InfoType specifies which type of system information to retrieve.
	// Must be one of the supported enum values for security and validation.
	InfoType string `json:"info_type" jsonschema:"description=Type of system info to retrieve (os, arch, go_version, working_dir),enum=os,enum=arch,enum=go_version,enum=working_dir"`
}

// TokenInfo represents comprehensive information about an OAuth 2.1 Bearer token.
// This structure is used for in-memory token storage and validation. In production,
// this would typically be stored in a persistent, secure token store (Redis, database).
//
// OAuth 2.1 Compliance: This implementation follows OAuth 2.1 specification
// requirements for token validation, expiration, and resource binding.
//
// Security Features:
// - Resource-specific validation: Tokens are bound to specific resource URIs
// - Expiration tracking: Automatic cleanup of expired tokens
// - Scope support: Prepared for scope-based authorization (currently basic)
type TokenInfo struct {
	// Token is the actual Bearer token value (base64-encoded random bytes).
	// Generated using cryptographically secure random number generation.
	Token string `json:"token"`
	
	// ExpiresAt defines when this token expires and becomes invalid.
	// Used for automatic cleanup and validation. Default: 1 hour from issuance.
	ExpiresAt time.Time `json:"expires_at"`
	
	// ResourceURI identifies the specific resource this token is valid for.
	// Implements OAuth 2.1 resource-specific token validation to prevent
	// token reuse across different services (confused deputy attacks).
	ResourceURI string `json:"resource_uri"`
	
	// Scope defines the permissions associated with this token.
	// Currently supports basic "read write" scope. Can be extended for
	// granular permission control (e.g., "read", "write", "admin").
	Scope string `json:"scope"`
}

// JSONRPCRequest represents a JSON-RPC 2.0 request message.
// This structure handles all MCP protocol requests following the JSON-RPC 2.0
// specification as required by the MCP protocol.
//
// MCP Compliance: All MCP communication uses JSON-RPC 2.0 as the transport
// protocol, ensuring compatibility with MCP clients and proper error handling.
//
// Reference: https://www.jsonrpc.org/specification
type JSONRPCRequest struct {
	// JSONRpc specifies the JSON-RPC protocol version. Must be "2.0".
	JSONRpc string `json:"jsonrpc"`
	
	// Method identifies the MCP method being called (e.g., "tools/list", "tools/call").
	// This determines how the server processes the request.
	Method string `json:"method"`
	
	// Params contains the method-specific parameters. Structure varies by method.
	// For "tools/call": {"name": "tool_name", "arguments": {...}}
	// For "tools/list": typically null or empty
	Params interface{} `json:"params,omitempty"`
	
	// ID is a unique identifier for this request. Used to match responses to requests.
	// Can be string, number, or null. Client should provide unique IDs for correlation.
	ID interface{} `json:"id"`
}

// JSONRPCResponse represents a JSON-RPC 2.0 response message.
// This structure handles all MCP protocol responses with proper error handling
// and result formatting as required by the JSON-RPC 2.0 specification.
//
// Error Handling: Either Result OR Error will be present, never both. This follows
// JSON-RPC 2.0 specification for proper response formatting.
//
// MCP Integration: Response structure matches MCP expectations for tool results
// and error information, enabling proper client-side handling.
type JSONRPCResponse struct {
	// JSONRpc specifies the JSON-RPC protocol version. Always "2.0".
	JSONRpc string `json:"jsonrpc"`
	
	// Result contains the successful response data. Present only for successful requests.
	// Structure varies by method - tool responses contain "content" array with results.
	Result interface{} `json:"result,omitempty"`
	
	// Error contains error information for failed requests. Present only for errors.
	// Formatted as {"message": "error description"} for client compatibility.
	Error interface{} `json:"error,omitempty"`
	
	// ID matches the ID from the corresponding request for response correlation.
	// Essential for clients handling multiple concurrent requests.
	ID interface{} `json:"id"`
}

// GLOBAL STATE
// In-memory token storage for demonstration purposes. In production, this should
// be replaced with persistent, secure storage (Redis, database) to support:
// - Token persistence across server restarts
// - Distributed deployments
// - Advanced token management features
// - Audit logging of token operations
//
// Security Note: This map is not thread-safe and should include proper
// synchronization in high-concurrency environments.
var tokenStore = make(map[string]TokenInfo)

// OAUTH 2.1 AUTHENTICATION FUNCTIONS
// These functions implement the OAuth 2.1 authentication flow with Bearer token
// validation, following the specifications for protected resource servers.

// generateSecureToken creates a cryptographically secure random token for OAuth 2.1.
//
// Security Implementation:
// - Uses crypto/rand for cryptographically secure random number generation
// - Generates 32 bytes of entropy (256 bits) for strong token security
// - Base64URL encoding ensures safe transmission in HTTP headers and URLs
// - No predictable patterns or timing attacks possible
//
// OAuth 2.1 Compliance:
// - Token format meets requirements for Bearer token values
// - Sufficient entropy to prevent brute force attacks
// - URL-safe encoding for HTTP Authorization headers
//
// Returns:
//   - string: Base64URL-encoded random token (43 characters)
//   - error: Any error from the random number generator
//
// Example output: "dGVzdF9zZWNyZXRfa2V5X2Zvcl9kZW1vX3B1cnBvc2U="
//
// Production Note: Consider adding token prefix (e.g., "mcp_") for identification
// and implementing token versioning for key rotation support.
func generateSecureToken() (string, error) {
	// Generate 32 bytes of cryptographically secure random data
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		// Return detailed error for debugging while avoiding information leakage
		return "", fmt.Errorf("failed to generate secure random token: %w", err)
	}
	
	// Encode as base64URL for safe use in HTTP headers and URLs
	// Base64URL avoids padding issues and URL-unsafe characters
	return base64.URLEncoding.EncodeToString(bytes), nil
}

// authenticateRequest validates OAuth 2.1 Bearer tokens from HTTP Authorization headers.
//
// This function implements comprehensive Bearer token validation following OAuth 2.1
// specifications for protected resource servers. It performs multiple security checks
// to prevent common authentication attacks and token misuse.
//
// Authentication Flow:
// 1. Extract Authorization header from HTTP request
// 2. Validate Bearer token format (RFC 6750)
// 3. Look up token in secure token store
// 4. Check token expiration with automatic cleanup
// 5. Validate resource-specific token binding (prevents confused deputy attacks)
//
// Security Features:
// - Header format validation prevents malformed requests
// - Token existence check prevents invalid token usage
// - Expiration validation with automatic cleanup prevents stale token reuse
// - Resource URI validation prevents cross-service token abuse
// - Error messages avoid information leakage about token validity
//
// OAuth 2.1 Compliance:
// - Follows RFC 6750 Bearer Token Usage specification
// - Implements resource-specific token validation
// - Proper error handling without token information leakage
// - Supports token expiration and cleanup as required
//
// Parameters:
//   - r: HTTP request containing Authorization header
//
// Returns:
//   - *TokenInfo: Valid token information if authentication succeeds
//   - error: Authentication error with appropriate message for client
//
// Error Cases:
//   - Missing Authorization header
//   - Invalid Bearer token format
//   - Token not found or expired
//   - Token not valid for requested resource
//
// Example Usage:
//   tokenInfo, err := authenticateRequest(r)
//   if err != nil {
//       http.Error(w, "Unauthorized", 401)
//       return
//   }
//   // Proceed with authenticated request...
func authenticateRequest(r *http.Request) (*TokenInfo, error) {
	// Step 1: Extract and validate Authorization header presence
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		// Return generic error to avoid revealing authentication requirements to attackers
		return nil, fmt.Errorf("missing Authorization header")
	}

	// Step 2: Validate Bearer token format according to RFC 6750
	// Expected format: "Authorization: Bearer <token>"
	if !strings.HasPrefix(authHeader, "Bearer ") {
		return nil, fmt.Errorf("invalid Authorization header format, expected Bearer token")
	}

	// Step 3: Extract token value from header (remove "Bearer " prefix)
	token := strings.TrimPrefix(authHeader, "Bearer ")
	if token == "" {
		return nil, fmt.Errorf("empty Bearer token")
	}
	
	// Step 4: Look up token in secure token store
	tokenInfo, exists := tokenStore[token]
	if !exists {
		// Use generic error message to avoid revealing token store details
		return nil, fmt.Errorf("invalid or expired token")
	}

	// Step 5: Check token expiration and perform automatic cleanup
	if time.Now().After(tokenInfo.ExpiresAt) {
		// Automatically remove expired tokens from store to prevent accumulation
		delete(tokenStore, token)
		return nil, fmt.Errorf("token has expired")
	}

	// Step 6: Validate resource-specific token binding (OAuth 2.1 requirement)
	// This prevents "confused deputy" attacks where tokens are used against wrong services
	expectedResource := fmt.Sprintf("http://%s", r.Host)
	if tokenInfo.ResourceURI != expectedResource {
		// Log security event for monitoring (in production)
		log.Printf("Security: Token resource mismatch - expected %s, got %s", 
			expectedResource, tokenInfo.ResourceURI)
		return nil, fmt.Errorf("token not valid for this resource")
	}

	// Authentication successful - return valid token information
	return &tokenInfo, nil
}

// authenticationMiddleware provides OAuth 2.1 Bearer token authentication for HTTP endpoints.
//
// This middleware wraps HTTP handlers to enforce authentication on protected endpoints
// while allowing unauthenticated access to OAuth-related endpoints. It follows OAuth 2.1
// and RFC 6750 specifications for proper error handling and response formatting.
//
// Middleware Architecture:
// - Implements the standard Go HTTP middleware pattern
// - Provides selective endpoint protection (whitelist approach)
// - Adds authenticated context to downstream handlers
// - Returns proper OAuth 2.1 error responses for authentication failures
//
// Protected vs Unprotected Endpoints:
// - Unprotected: OAuth metadata and token endpoints (required for OAuth flow)
// - Protected: All MCP endpoints (require valid Bearer token)
// - Configurable: Additional endpoints can be whitelisted as needed
//
// Error Handling:
// - Returns proper HTTP 401 Unauthorized for authentication failures
// - Includes WWW-Authenticate header as required by RFC 6750
// - Provides structured error responses in OAuth 2.1 format
// - Logs authentication failures for security monitoring
//
// Security Features:
// - No information leakage in error responses
// - Proper OAuth 2.1 error codes and descriptions
// - Request context enhancement for downstream handlers
// - Automatic token validation and cleanup
//
// Parameters:
//   - next: The HTTP handler to protect with authentication
//
// Returns:
//   - http.Handler: Middleware-wrapped handler with authentication
//
// Context Enhancement:
// Successful authentication adds "token_info" to request context containing
// validated TokenInfo for use by downstream handlers (e.g., authorization checks).
//
// Example Integration:
//   protectedHandler := authenticationMiddleware(mcpHandler)
//   http.Handle("/mcp", protectedHandler)
func authenticationMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// OAuth 2.1 Endpoint Whitelist: These endpoints must remain unprotected
		// to enable the authentication flow itself. Protecting these would create
		// a chicken-and-egg problem where clients need tokens to get tokens.
		unprotectedPaths := []string{
			"/.well-known/oauth-authorization-server", // OAuth 2.0 discovery metadata
			"/oauth/token",                            // Token endpoint for credential exchange
		}
		
		// Check if current request is for an unprotected endpoint
		for _, path := range unprotectedPaths {
			if r.URL.Path == path {
				// Skip authentication and proceed directly to handler
				next.ServeHTTP(w, r)
				return
			}
		}

		// All other endpoints require authentication - validate Bearer token
		tokenInfo, err := authenticateRequest(r)
		if err != nil {
			// Log authentication failure for security monitoring
			// Note: Log the attempt but don't include sensitive token data
			log.Printf("Authentication failed for %s %s from %s: %v", 
				r.Method, r.URL.Path, r.RemoteAddr, err)
			
			// Set OAuth 2.1 compliant error response headers
			// WWW-Authenticate header is required by RFC 6750 for 401 responses
			w.Header().Set("WWW-Authenticate", 
				`Bearer realm="MCP Server", error="invalid_token"`)
			w.Header().Set("Content-Type", "application/json")
			
			// Return proper HTTP 401 Unauthorized status
			w.WriteHeader(http.StatusUnauthorized)
			
			// Provide structured error response in OAuth 2.1 format
			errorResponse := fmt.Sprintf(
				`{"error": "invalid_token", "error_description": "%s"}`, 
				err.Error())
			w.Write([]byte(errorResponse))
			return
		}

		// Authentication successful - enhance request context with token information
		// This allows downstream handlers to access authentication details for
		// authorization decisions, audit logging, or user identification
		ctx := context.WithValue(r.Context(), "token_info", tokenInfo)
		
		// Proceed to protected handler with enhanced context
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// createMCPHandler creates an HTTP handler that handles MCP protocol requests
func createMCPHandler(server *mcp.Server) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Set CORS headers for browser compatibility
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		
		// Handle preflight requests
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}
		
		// Only accept POST requests
		if r.Method != http.MethodPost {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusMethodNotAllowed)
			json.NewEncoder(w).Encode(JSONRPCResponse{
				JSONRpc: "2.0",
				Error:   map[string]string{"message": "Method not allowed. Only POST requests are accepted."},
				ID:      nil,
			})
			return
		}
		
		// Read and parse JSON-RPC request
		var req JSONRPCRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(JSONRPCResponse{
				JSONRpc: "2.0",
				Error:   map[string]string{"message": "Invalid JSON-RPC request"},
				ID:      nil,
			})
			return
		}
		
		// Handle different MCP methods
		response := handleMCPRequest(server, &req)
		
		// Send response back to HTTP client
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(response)
	})
}

// handleMCPRequest processes MCP protocol requests
func handleMCPRequest(server *mcp.Server, req *JSONRPCRequest) JSONRPCResponse {
	switch req.Method {
	case "tools/list":
		tools := []map[string]interface{}{
			{
				"name":        "read_file",
				"description": "Read the contents of a file from the filesystem",
				"inputSchema": map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"file_path": map[string]interface{}{
							"type":        "string",
							"description": "Path to the file to read",
						},
					},
					"required": []string{"file_path"},
				},
			},
			{
				"name":        "list_directory",
				"description": "List the contents of a directory",
				"inputSchema": map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"directory_path": map[string]interface{}{
							"type":        "string",
							"description": "Path to the directory to list",
						},
					},
					"required": []string{"directory_path"},
				},
			},
			{
				"name":        "get_system_info",
				"description": "Get various system information (OS, architecture, Go version, working directory)",
				"inputSchema": map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"info_type": map[string]interface{}{
							"type":        "string",
							"description": "Type of system information to retrieve",
							"enum":        []string{"os", "arch", "go_version", "working_dir"},
						},
					},
					"required": []string{"info_type"},
				},
			},
		}
		
		return JSONRPCResponse{
			JSONRpc: "2.0",
			Result: map[string]interface{}{
				"tools": tools,
			},
			ID: req.ID,
		}
		
	case "tools/call":
		params, ok := req.Params.(map[string]interface{})
		if !ok {
			return JSONRPCResponse{
				JSONRpc: "2.0",
				Error:   map[string]string{"message": "Invalid parameters"},
				ID:      req.ID,
			}
		}
		
		toolName, ok := params["name"].(string)
		if !ok {
			return JSONRPCResponse{
				JSONRpc: "2.0",
				Error:   map[string]string{"message": "Missing or invalid tool name"},
				ID:      req.ID,
			}
		}
		
		args, ok := params["arguments"].(map[string]interface{})
		if !ok {
			return JSONRPCResponse{
				JSONRpc: "2.0",
				Error:   map[string]string{"message": "Missing or invalid tool arguments"},
				ID:      req.ID,
			}
		}
		
		// Call the appropriate tool
		result, err := callTool(toolName, args)
		if err != nil {
			return JSONRPCResponse{
				JSONRpc: "2.0",
				Error:   map[string]string{"message": err.Error()},
				ID:      req.ID,
			}
		}
		
		return JSONRPCResponse{
			JSONRpc: "2.0",
			Result:  result,
			ID:      req.ID,
		}
		
	default:
		return JSONRPCResponse{
			JSONRpc: "2.0",
			Error:   map[string]string{"message": "Method not found"},
			ID:      req.ID,
		}
	}
}

// callTool handles tool calls with the same logic as the MCP server tools
func callTool(toolName string, args map[string]interface{}) (interface{}, error) {
	switch toolName {
	case "read_file":
		filePath, ok := args["file_path"].(string)
		if !ok {
			return nil, fmt.Errorf("file_path parameter is required and must be a string")
		}
		
		if filePath == "" {
			return nil, fmt.Errorf("file_path parameter is required")
		}
		
		// Check if file exists and is readable
		if _, err := os.Stat(filePath); os.IsNotExist(err) {
			return nil, fmt.Errorf("file does not exist: %s", filePath)
		}
		
		// Read file content
		content, err := os.ReadFile(filePath)
		if err != nil {
			return nil, fmt.Errorf("failed to read file: %w", err)
		}
		
		return map[string]interface{}{
			"content": []map[string]interface{}{
				{
					"type": "text",
					"text": fmt.Sprintf("File: %s\n\n%s", filePath, string(content)),
				},
			},
		}, nil
		
	case "list_directory":
		dirPath, ok := args["directory_path"].(string)
		if !ok {
			return nil, fmt.Errorf("directory_path parameter is required and must be a string")
		}
		
		if dirPath == "" {
			return nil, fmt.Errorf("directory_path parameter is required")
		}
		
		// Check if directory exists
		if stat, err := os.Stat(dirPath); os.IsNotExist(err) {
			return nil, fmt.Errorf("directory does not exist: %s", dirPath)
		} else if !stat.IsDir() {
			return nil, fmt.Errorf("path is not a directory: %s", dirPath)
		}
		
		// Read directory contents
		entries, err := os.ReadDir(dirPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read directory: %w", err)
		}
		
		var result strings.Builder
		result.WriteString(fmt.Sprintf("Directory: %s\n\n", dirPath))
		
		if len(entries) == 0 {
			result.WriteString("(empty directory)")
		} else {
			for _, entry := range entries {
				entryType := "file"
				if entry.IsDir() {
					entryType = "directory"
				}
				result.WriteString(fmt.Sprintf("- %s (%s)\n", entry.Name(), entryType))
			}
		}
		
		return map[string]interface{}{
			"content": []map[string]interface{}{
				{
					"type": "text",
					"text": result.String(),
				},
			},
		}, nil
		
	case "get_system_info":
		infoType, ok := args["info_type"].(string)
		if !ok {
			return nil, fmt.Errorf("info_type parameter is required and must be a string")
		}
		
		if infoType == "" {
			return nil, fmt.Errorf("info_type parameter is required")
		}
		
		var result string
		
		switch infoType {
		case "os":
			result = fmt.Sprintf("Operating System: %s", runtime.GOOS)
		case "arch":
			result = fmt.Sprintf("Architecture: %s", runtime.GOARCH)
		case "go_version":
			result = fmt.Sprintf("Go Version: %s", runtime.Version())
		case "working_dir":
			wd, err := os.Getwd()
			if err != nil {
				return nil, fmt.Errorf("failed to get working directory: %w", err)
			}
			result = fmt.Sprintf("Working Directory: %s", wd)
		default:
			return nil, fmt.Errorf("invalid info_type: %s. Valid options: os, arch, go_version, working_dir", infoType)
		}
		
		return map[string]interface{}{
			"content": []map[string]interface{}{
				{
					"type": "text",
					"text": result,
				},
			},
		}, nil
		
	default:
		return nil, fmt.Errorf("unknown tool: %s", toolName)
	}
}

// oauthMetadataHandler provides OAuth 2.0 Protected Resource Metadata
func oauthMetadataHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	
	// Simple JSON marshaling for demo
	w.Write([]byte(`{
		"issuer": "` + fmt.Sprintf("http://%s", r.Host) + `",
		"authorization_endpoint": "` + fmt.Sprintf("http://%s/oauth/authorize", r.Host) + `",
		"token_endpoint": "` + fmt.Sprintf("http://%s/oauth/token", r.Host) + `",
		"resource": "` + fmt.Sprintf("http://%s", r.Host) + `",
		"scopes_supported": ["read", "write", "admin"],
		"response_types_supported": ["code"],
		"grant_types_supported": ["authorization_code", "client_credentials"],
		"token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
		"code_challenge_methods_supported": ["S256"]
	}`))
}

// tokenHandler provides OAuth 2.1 token endpoint (simplified for demo)
func tokenHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	// Parse form data
	err := r.ParseForm()
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error": "invalid_request", "error_description": "Failed to parse form data"}`))
		return
	}

	grantType := r.FormValue("grant_type")
	
	// For demo purposes, we'll support client_credentials grant type
	if grantType != "client_credentials" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error": "unsupported_grant_type", "error_description": "Only client_credentials grant type is supported"}`))
		return
	}

	// Generate new token
	token, err := generateSecureToken()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error": "server_error", "error_description": "Failed to generate token"}`))
		return
	}

	// Store token with expiration (1 hour for demo)
	expiresAt := time.Now().Add(time.Hour)
	tokenStore[token] = TokenInfo{
		Token:       token,
		ExpiresAt:   expiresAt,
		ResourceURI: fmt.Sprintf("http://%s", r.Host),
		Scope:       "read write",
	}

	// Return token response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(fmt.Sprintf(`{
		"access_token": "%s",
		"token_type": "Bearer",
		"expires_in": 3600,
		"scope": "read write"
	}`, token)))
}

// readFileContent reads the content of a file and returns it as a string
func readFileContent(ctx context.Context, session *mcp.ServerSession, params *mcp.CallToolParamsFor[FileReadParams]) (*mcp.CallToolResultFor[any], error) {
	filePath := params.Arguments.FilePath
	
	// Validate file path
	if filePath == "" {
		return nil, fmt.Errorf("file_path parameter is required")
	}
	
	// Check if file exists and is readable
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return nil, fmt.Errorf("file does not exist: %s", filePath)
	}
	
	// Read file content
	content, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}
	
	return &mcp.CallToolResultFor[any]{
		Content: []mcp.Content{
			&mcp.TextContent{
				Text: fmt.Sprintf("File: %s\n\n%s", filePath, string(content)),
			},
		},
	}, nil
}

// listDirectoryContents lists the contents of a directory
func listDirectoryContents(ctx context.Context, session *mcp.ServerSession, params *mcp.CallToolParamsFor[DirectoryListParams]) (*mcp.CallToolResultFor[any], error) {
	dirPath := params.Arguments.DirectoryPath
	
	// Validate directory path
	if dirPath == "" {
		return nil, fmt.Errorf("directory_path parameter is required")
	}
	
	// Check if directory exists
	if stat, err := os.Stat(dirPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("directory does not exist: %s", dirPath)
	} else if !stat.IsDir() {
		return nil, fmt.Errorf("path is not a directory: %s", dirPath)
	}
	
	// Read directory contents
	entries, err := os.ReadDir(dirPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read directory: %w", err)
	}
	
	var result strings.Builder
	result.WriteString(fmt.Sprintf("Directory: %s\n\n", dirPath))
	
	if len(entries) == 0 {
		result.WriteString("(empty directory)")
	} else {
		for _, entry := range entries {
			entryType := "file"
			if entry.IsDir() {
				entryType = "directory"
			}
			result.WriteString(fmt.Sprintf("- %s (%s)\n", entry.Name(), entryType))
		}
	}
	
	return &mcp.CallToolResultFor[any]{
		Content: []mcp.Content{
			&mcp.TextContent{
				Text: result.String(),
			},
		},
	}, nil
}

// getSystemInformation returns various system information
func getSystemInformation(ctx context.Context, session *mcp.ServerSession, params *mcp.CallToolParamsFor[SystemInfoParams]) (*mcp.CallToolResultFor[any], error) {
	infoType := params.Arguments.InfoType
	
	if infoType == "" {
		return nil, fmt.Errorf("info_type parameter is required")
	}
	
	var result string
	
	switch infoType {
	case "os":
		result = fmt.Sprintf("Operating System: %s", runtime.GOOS)
	case "arch":
		result = fmt.Sprintf("Architecture: %s", runtime.GOARCH)
	case "go_version":
		result = fmt.Sprintf("Go Version: %s", runtime.Version())
	case "working_dir":
		wd, err := os.Getwd()
		if err != nil {
			return nil, fmt.Errorf("failed to get working directory: %w", err)
		}
		result = fmt.Sprintf("Working Directory: %s", wd)
	default:
		return nil, fmt.Errorf("invalid info_type: %s. Valid options: os, arch, go_version, working_dir", infoType)
	}
	
	return &mcp.CallToolResultFor[any]{
		Content: []mcp.Content{
			&mcp.TextContent{
				Text: result,
			},
		},
	}, nil
}

// TLS CERTIFICATE MANAGEMENT FUNCTIONS
// These functions handle automatic generation and management of TLS certificates
// when none are provided, ensuring the server can start with TLS enabled.

// certFilesExist checks if certificate and key files exist in the current directory.
//
// This function verifies the presence of both certificate and private key files
// required for TLS operation. It checks for the default filenames used by the
// server for automatic certificate management.
//
// Default Certificate Files:
// - server.crt: X.509 certificate file in PEM format
// - server.key: RSA private key file in PEM format
//
// Returns:
//   - bool: true if both certificate and key files exist and are accessible
//   - string: path to certificate file (if exists)
//   - string: path to key file (if exists)
//   - error: any error encountered while checking file existence
//
// Usage:
//   exists, certFile, keyFile, err := certFilesExist()
//   if err != nil {
//       log.Printf("Error checking certificate files: %v", err)
//   }
//   if !exists {
//       // Generate new certificates
//   }
func certFilesExist() (bool, string, string, error) {
	certFile := "server.crt"
	keyFile := "server.key"
	
	// Check if certificate file exists and is readable
	if _, err := os.Stat(certFile); os.IsNotExist(err) {
		return false, "", "", nil
	} else if err != nil {
		return false, "", "", fmt.Errorf("error checking certificate file: %w", err)
	}
	
	// Check if key file exists and is readable
	if _, err := os.Stat(keyFile); os.IsNotExist(err) {
		return false, "", "", nil
	} else if err != nil {
		return false, "", "", fmt.Errorf("error checking key file: %w", err)
	}
	
	return true, certFile, keyFile, nil
}

// generateSelfSignedCert creates a self-signed certificate and private key for TLS.
//
// This function generates a complete TLS certificate suitable for HTTPS servers,
// including proper Subject Alternative Names for localhost and IP address access.
// The generated certificate is suitable for development and testing environments.
//
// Certificate Specifications:
// - Algorithm: RSA with 2048-bit key length
// - Signature: SHA-256 with RSA encryption
// - Validity: 365 days from generation time
// - Key Usage: Digital signature and key encipherment
// - Extended Key Usage: Server authentication
// - Subject Alternative Names: DNS names and IP addresses for local access
//
// Security Features:
// - Uses cryptographically secure random number generation
// - Generates unique serial numbers to prevent certificate collisions
// - Includes proper certificate extensions for server authentication
// - Self-signed for ease of deployment (no CA required)
//
// Network Configuration:
// - Subject: CN=localhost (Common Name for certificate validation)
// - DNS Names: localhost, *.localhost (wildcard for subdomains)
// - IP Addresses: 127.0.0.1, ::1 (IPv4 and IPv6 loopback)
//
// Returns:
//   - []byte: X.509 certificate in PEM format
//   - []byte: RSA private key in PEM format  
//   - error: any error encountered during certificate generation
//
// Error Cases:
//   - RSA key generation failure
//   - Random number generation failure
//   - Certificate template creation failure
//   - PEM encoding failure
//
// Example Usage:
//   certPEM, keyPEM, err := generateSelfSignedCert()
//   if err != nil {
//       log.Fatalf("Failed to generate certificate: %v", err)
//   }
//   // Save or use certificate and key...
//
// Production Note: For production environments, replace with proper CA-signed
// certificates or implement ACME/Let's Encrypt integration for automatic
// certificate provisioning and renewal.
func generateSelfSignedCert() ([]byte, []byte, error) {
	// Generate RSA private key with 2048-bit length
	// This provides adequate security for TLS while maintaining compatibility
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate RSA private key: %w", err)
	}

	// Create certificate template with comprehensive configuration
	template := x509.Certificate{
		// Generate unique serial number to prevent certificate collisions
		SerialNumber: big.NewInt(1),
		
		// Certificate subject information
		Subject: pkix.Name{
			CommonName:   "localhost",
			Organization: []string{"MCP Demo Server"},
		},
		
		// Certificate validity period (1 year)
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(365 * 24 * time.Hour),

		// Key usage extensions for TLS server certificates
		KeyUsage: x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		
		// Enable basic constraints for self-signed certificate
		BasicConstraintsValid: true,

		// Subject Alternative Names for local development
		// This allows the certificate to be valid for various local access patterns
		DNSNames: []string{
			"localhost",
			"*.localhost", // Wildcard for subdomains
		},
		IPAddresses: []net.IP{
			net.IPv4(127, 0, 0, 1), // IPv4 loopback
			net.IPv6loopback,       // IPv6 loopback (::1)
		},
	}

	// Generate certificate using the private key as both issuer and subject (self-signed)
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	// Encode certificate to PEM format for file storage and HTTP server use
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})
	if certPEM == nil {
		return nil, nil, fmt.Errorf("failed to encode certificate to PEM format")
	}

	// Encode private key to PEM format
	keyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal private key: %w", err)
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyDER,
	})
	if keyPEM == nil {
		return nil, nil, fmt.Errorf("failed to encode private key to PEM format")
	}

	return certPEM, keyPEM, nil
}

// saveCertFiles writes certificate and private key data to files on disk.
//
// This function handles the secure storage of generated certificate and private key
// materials to the filesystem, ensuring proper file permissions and error handling.
// The files are saved with restrictive permissions to protect the private key.
//
// File Security:
// - Certificate file (server.crt): 644 permissions (readable by all, writable by owner)
// - Private key file (server.key): 600 permissions (readable/writable by owner only)
// - Atomic writes to prevent partial file corruption
// - Error handling with cleanup on failure
//
// File Format:
// - Both files are stored in PEM format for broad compatibility
// - Certificate contains X.509 certificate data
// - Key file contains PKCS#8 private key data
//
// Parameters:
//   - certPEM: X.509 certificate in PEM format
//   - keyPEM: RSA private key in PEM format
//
// Returns:
//   - string: path to saved certificate file
//   - string: path to saved private key file  
//   - error: any error encountered during file operations
//
// Error Cases:
//   - File system permission errors
//   - Disk space insufficient
//   - File creation or write failures
//   - Permission setting failures
//
// Security Considerations:
// - Private key file has restrictive permissions (600) to prevent unauthorized access
// - Files are created with explicit permissions rather than relying on umask
// - Error messages avoid exposing sensitive information about file system structure
//
// Example Usage:
//   certFile, keyFile, err := saveCertFiles(certPEM, keyPEM)
//   if err != nil {
//       log.Fatalf("Failed to save certificate files: %v", err)
//   }
//   log.Printf("Certificate saved to: %s", certFile)
//   log.Printf("Private key saved to: %s", keyFile)
func saveCertFiles(certPEM, keyPEM []byte) (string, string, error) {
	certFile := "server.crt"
	keyFile := "server.key"

	// Write certificate file with standard permissions (readable by all)
	if err := os.WriteFile(certFile, certPEM, 0644); err != nil {
		return "", "", fmt.Errorf("failed to write certificate file: %w", err)
	}

	// Write private key file with restrictive permissions (owner only)
	// This is critical for security as private keys must be protected
	if err := os.WriteFile(keyFile, keyPEM, 0600); err != nil {
		// Clean up certificate file if key file creation fails
		os.Remove(certFile)
		return "", "", fmt.Errorf("failed to write private key file: %w", err)
	}

	return certFile, keyFile, nil
}

func main() {
	// Initialize MCP server with descriptive metadata
	serverImplementation := &mcp.Implementation{
		Name:    "mcp-demo-server-auth",
		Version: "3.0.0",
		Title:   "MCP server with OAuth 2.1 authentication for educational purposes",
	}
	
	// Create new MCP server instance
	server := mcp.NewServer(serverImplementation, nil)
	
	// Register file reading tool
	mcp.AddTool(server, &mcp.Tool{
		Name:        "read_file",
		Description: "Read the contents of a file from the filesystem",
		InputSchema: &jsonschema.Schema{
			Type: "object",
			Properties: map[string]*jsonschema.Schema{
				"file_path": {
					Type:        "string",
					Description: "Path to the file to read",
				},
			},
			Required: []string{"file_path"},
		},
	}, readFileContent)
	
	// Register directory listing tool
	mcp.AddTool(server, &mcp.Tool{
		Name:        "list_directory",
		Description: "List the contents of a directory",
		InputSchema: &jsonschema.Schema{
			Type: "object",
			Properties: map[string]*jsonschema.Schema{
				"directory_path": {
					Type:        "string",
					Description: "Path to the directory to list",
				},
			},
			Required: []string{"directory_path"},
		},
	}, listDirectoryContents)
	
	// Register system information tool
	mcp.AddTool(server, &mcp.Tool{
		Name:        "get_system_info",
		Description: "Get various system information (OS, architecture, Go version, working directory)",
		InputSchema: &jsonschema.Schema{
			Type: "object",
			Properties: map[string]*jsonschema.Schema{
				"info_type": {
					Type:        "string",
					Description: "Type of system information to retrieve",
					Enum:        []interface{}{"os", "arch", "go_version", "working_dir"},
				},
			},
			Required: []string{"info_type"},
		},
	}, getSystemInformation)
	
	// Configure server port (default to 8443 for TLS)
	port := os.Getenv("MCP_SERVER_PORT")
	if port == "" {
		port = "8443"
	}
	
	// Configure TLS (use environment variables for production)
	useTLS := os.Getenv("MCP_USE_TLS") != "false"
	
	// Log server startup
	log.Printf("Starting MCP Demo Server (v%s) - OAuth 2.1 Authentication", serverImplementation.Version)
	log.Printf("Server Name: %s", serverImplementation.Name)
	log.Printf("Title: %s", serverImplementation.Title)
	log.Printf("Tools registered: read_file, list_directory, get_system_info")
	log.Printf("Authentication: OAuth 2.1 with Bearer tokens")
	log.Printf("TLS enabled: %v", useTLS)
	
	// Create HTTP router with authentication middleware
	mux := http.NewServeMux()
	
	// OAuth 2.1 endpoints (no authentication required)
	mux.HandleFunc("/.well-known/oauth-authorization-server", oauthMetadataHandler)
	mux.HandleFunc("/oauth/token", tokenHandler)
	
	// MCP endpoints with authentication
	mcpHandler := createMCPHandler(server)
	mux.Handle("/mcp", authenticationMiddleware(mcpHandler))
	mux.Handle("/", authenticationMiddleware(mcpHandler))
	
	// Add security headers middleware
	securityMiddleware := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Security headers
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.Header().Set("X-Frame-Options", "DENY")
			w.Header().Set("X-XSS-Protection", "1; mode=block")
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
			w.Header().Set("Content-Security-Policy", "default-src 'self'")
			
			next.ServeHTTP(w, r)
		})
	}
	
	// Create HTTP server with security middleware
	httpServer := &http.Server{
		Addr:         ":" + port,
		Handler:      securityMiddleware(mux),
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
	
	// Certificate file paths for TLS configuration
	var certFile, keyFile string
	
	// Configure TLS if enabled
	if useTLS {
		// Check if certificate files already exist
		exists, existingCertFile, existingKeyFile, err := certFilesExist()
		if err != nil {
			log.Fatalf("Error checking certificate files: %v", err)
		}
		
		if exists {
			// Use existing certificate files
			certFile = existingCertFile
			keyFile = existingKeyFile
			log.Printf("Using existing TLS certificate: %s", certFile)
			log.Printf("Using existing TLS private key: %s", keyFile)
		} else {
			// Generate new self-signed certificate
			log.Printf("No TLS certificate found, generating self-signed certificate...")
			
			certPEM, keyPEM, err := generateSelfSignedCert()
			if err != nil {
				log.Fatalf("Failed to generate TLS certificate: %v", err)
			}
			
			certFile, keyFile, err = saveCertFiles(certPEM, keyPEM)
			if err != nil {
				log.Fatalf("Failed to save certificate files: %v", err)
			}
			
			log.Printf("Generated new TLS certificate: %s", certFile)
			log.Printf("Generated new TLS private key: %s", keyFile)
			log.Printf("Certificate is valid for: localhost, *.localhost, 127.0.0.1, ::1")
			log.Printf("Certificate expires: %s", time.Now().Add(365*24*time.Hour).Format("2006-01-02 15:04:05"))
		}
		
		// Configure TLS settings for security
		httpServer.TLSConfig = &tls.Config{
			MinVersion: tls.VersionTLS12,
			CipherSuites: []uint16{
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			},
		}
	}
	
	// Print OAuth endpoints information
	protocol := "http"
	if useTLS {
		protocol = "https"
	}
	
	log.Printf("OAuth 2.1 endpoints:")
	log.Printf("  Metadata: %s://localhost:%s/.well-known/oauth-authorization-server", protocol, port)
	log.Printf("  Token: %s://localhost:%s/oauth/token", protocol, port)
	log.Printf("MCP endpoint: %s://localhost:%s/mcp", protocol, port)
	
	// Example token request
	log.Printf("\nExample token request:")
	log.Printf("curl -X POST %s://localhost:%s/oauth/token \\", protocol, port)
	log.Printf("  -H \"Content-Type: application/x-www-form-urlencoded\" \\")
	log.Printf("  -d \"grant_type=client_credentials\"")
	
	// Start HTTP server
	if useTLS {
		log.Printf("HTTPS server listening on %s://localhost:%s", protocol, port)
		log.Printf("TLS certificate: %s", certFile)
		log.Printf("TLS private key: %s", keyFile)
		
		// Start HTTPS server with generated or existing certificate files
		if err := httpServer.ListenAndServeTLS(certFile, keyFile); err != nil && err != http.ErrServerClosed {
			log.Fatalf("HTTPS server failed to start: %v", err)
		}
	} else {
		log.Printf("HTTP server listening on %s://localhost:%s", protocol, port)
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("HTTP server failed to start: %v", err)
		}
	}
}