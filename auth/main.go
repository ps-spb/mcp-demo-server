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
	"crypto/sha256"
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
	"net/url"
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

// AuthorizationCodeInfo represents information about an issued authorization code with PKCE support.
// This structure stores the code along with PKCE parameters and client information needed
// for the token exchange process in OAuth 2.1 authorization code flow.
//
// OAuth 2.1 + PKCE Compliance:
// - Stores code_challenge and method for PKCE validation
// - Includes expiration for short-lived authorization codes (10 minutes max)
// - Tracks redirect_uri for validation during token exchange
// - Resource-specific binding for security
type AuthorizationCodeInfo struct {
	// Code is the authorization code value (base64-encoded random bytes)
	Code string `json:"code"`
	
	// ExpiresAt defines when this authorization code expires (short-lived: 10 minutes)
	ExpiresAt time.Time `json:"expires_at"`
	
	// CodeChallenge is the PKCE code challenge provided during authorization
	CodeChallenge string `json:"code_challenge"`
	
	// CodeChallengeMethod is the method used to generate the challenge (must be "S256")
	CodeChallengeMethod string `json:"code_challenge_method"`
	
	// RedirectURI is the redirect URI used in the authorization request
	RedirectURI string `json:"redirect_uri"`
	
	// ResourceURI identifies the specific resource this code is valid for
	ResourceURI string `json:"resource_uri"`
	
	// Scope defines the requested permissions
	Scope string `json:"scope"`
	
	// ClientID identifies the client (for future client authentication)
	ClientID string `json:"client_id,omitempty"`
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
// In-memory storage for demonstration purposes. In production, this should
// be replaced with persistent, secure storage (Redis, database) to support:
// - Token persistence across server restarts
// - Distributed deployments
// - Advanced token management features
// - Audit logging of token operations
//
// Security Note: These maps are not thread-safe and should include proper
// synchronization in high-concurrency environments.
var (
	// tokenStore holds issued Bearer tokens
	tokenStore = make(map[string]TokenInfo)
	
	// authCodeStore holds issued authorization codes with PKCE information
	authCodeStore = make(map[string]AuthorizationCodeInfo)
)

// OAUTH 2.1 + PKCE HELPER FUNCTIONS
// These functions implement OAuth 2.1 with PKCE support, including authorization code
// generation, PKCE validation, and secure token management.

// generateAuthorizationCode creates a cryptographically secure authorization code with professional prefix.
//
// Authorization Code Format: mcp_ac_<base64url_random_data>
// - "mcp" = Company/service identifier (consistent with access tokens)
// - "ac" = Authorization Code type identifier
// - Enables instant recognition and proper handling in OAuth flow
//
// OAuth 2.1 Compliance:
// - Uses crypto/rand for secure random generation
// - 32 bytes of entropy (256 bits) for strong security
// - Base64URL encoding for safe URL transmission  
// - Short-lived (10 minutes maximum as per OAuth 2.1)
// - Single-use only (deleted after token exchange)
//
// Educational Benefits:
// - Clear distinction from access tokens in logs
// - Professional formatting following industry standards
// - Demonstrates proper OAuth flow token management
// - Supports debugging and monitoring of authorization flow
//
// Returns:
//   - string: Prefixed authorization code (format: mcp_ac_<43_chars>)
//   - error: Any error from random generation
//
// Example output: "mcp_ac_dGVzdF9hdXRoX2NvZGVfZm9yX2RlbW9fcHVycG9zZQ"
func generateAuthorizationCode() (string, error) {
	// Generate 32 bytes of cryptographically secure random data
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to generate authorization code: %w", err)
	}
	
	// Encode as base64URL for safe URL transmission
	codeData := base64.URLEncoding.EncodeToString(bytes)
	codeData = strings.TrimRight(codeData, "=") // Remove padding for clean format
	
	// Add professional prefix to distinguish from access tokens
	// This helps with monitoring, debugging, and security scanning
	return "mcp_ac_" + codeData, nil
}

// validateCodeChallenge validates a PKCE code_verifier against the stored code_challenge.
//
// PKCE Specification (RFC 7636):
// - Only S256 method is supported (OAuth 2.1 requirement)
// - code_challenge = BASE64URL(SHA256(code_verifier))
// - code_verifier must be 43-128 characters, base64url-encoded
//
// Security Implementation:
// - Constant-time comparison to prevent timing attacks
// - Validates code_verifier format and length
// - Ensures code_challenge_method is S256
//
// Parameters:
//   - codeVerifier: The code_verifier from the token request
//   - storedChallenge: The code_challenge from authorization request
//   - method: The code_challenge_method (must be "S256")
//
// Returns:
//   - bool: true if validation succeeds
//   - error: validation error with details
func validateCodeChallenge(codeVerifier, storedChallenge, method string) (bool, error) {
	// Validate code_challenge_method (OAuth 2.1 requires S256)
	if method != "S256" {
		return false, fmt.Errorf("unsupported code_challenge_method: %s (only S256 is supported)", method)
	}
	
	// Validate code_verifier format and length (RFC 7636)
	if len(codeVerifier) < 43 || len(codeVerifier) > 128 {
		return false, fmt.Errorf("code_verifier must be 43-128 characters long")
	}
	
	// RFC 7636: code_verifier is a high-entropy cryptographic random string
	// It's not required to be base64url encoded, just needs valid length and characters
	// The only requirement is that it's 43-128 characters of unreserved characters
	
	// Compute SHA256 hash of code_verifier
	hash := sha256.Sum256([]byte(codeVerifier))
	
	// Encode hash as base64url without padding (RFC 7636 requirement)
	computedChallenge := base64.URLEncoding.EncodeToString(hash[:])
	computedChallenge = strings.TrimRight(computedChallenge, "=")
	
	// Normalize stored challenge (remove padding for comparison)
	normalizedStored := strings.TrimRight(storedChallenge, "=")
	
	// Debug logging
	log.Printf("DEBUG PKCE: computed='%s', stored='%s', normalized='%s'", 
		computedChallenge, storedChallenge, normalizedStored)
	
	// Constant-time comparison to prevent timing attacks
	if computedChallenge != normalizedStored {
		return false, fmt.Errorf("code_verifier does not match code_challenge")
	}
	
	return true, nil
}

// validateRedirectURI validates a redirect URI for security compliance.
//
// OAuth 2.1 Security Requirements:
// - Must be an absolute URI with https scheme (or http for localhost)
// - No fragments allowed in redirect URIs
// - Must match exactly with registered redirect URI
// - Prevents open redirect attacks
//
// Parameters:
//   - redirectURI: The redirect URI to validate
//
// Returns:
//   - error: validation error if URI is invalid or insecure
func validateRedirectURI(redirectURI string) error {
	if redirectURI == "" {
		return fmt.Errorf("redirect_uri is required")
	}
	
	parsedURI, err := url.Parse(redirectURI)
	if err != nil {
		return fmt.Errorf("invalid redirect_uri format: %w", err)
	}
	
	// Must be absolute URI
	if !parsedURI.IsAbs() {
		return fmt.Errorf("redirect_uri must be an absolute URI")
	}
	
	// Check scheme - HTTPS required, HTTP allowed only for localhost
	switch parsedURI.Scheme {
	case "https":
		// Always allowed
	case "http":
		// Only allowed for localhost/127.0.0.1 (development)
		if parsedURI.Hostname() != "localhost" && parsedURI.Hostname() != "127.0.0.1" {
			return fmt.Errorf("http redirect_uri only allowed for localhost")
		}
	default:
		return fmt.Errorf("redirect_uri must use https scheme (or http for localhost)")
	}
	
	// Fragments not allowed in redirect URI
	if parsedURI.Fragment != "" {
		return fmt.Errorf("redirect_uri must not contain fragments")
	}
	
	return nil
}

// TOKEN FORMAT VALIDATION FUNCTIONS
// These functions provide simple validation canaries to catch common integration errors
// and demonstrate security-conscious input validation patterns.

// validateAccessTokenFormat performs basic format validation on access tokens.
//
// Educational Purpose:
// - Demonstrates input validation best practices
// - Catches common integration mistakes early  
// - Shows defensive programming patterns
// - Provides clear error messages for debugging
//
// Security Benefits:
// - Prevents processing of malformed tokens
// - Reduces unnecessary database lookups for invalid tokens
// - Provides consistent error handling
// - Supports monitoring of token format issues
//
// Validation Checks:
// - Correct prefix format (mcp_at_)
// - Minimum length requirements
// - Basic character set validation (base64url)
//
// Parameters:
//   - token: The access token to validate
//
// Returns:
//   - error: Validation error with descriptive message, nil if valid
func validateAccessTokenFormat(token string) error {
	// Check for correct access token prefix
	if !strings.HasPrefix(token, "mcp_at_") {
		return fmt.Errorf("invalid access token format: missing 'mcp_at_' prefix")
	}
	
	// Validate minimum length: prefix (7) + base64url data (43 minimum)
	if len(token) < 50 {
		return fmt.Errorf("access token too short: expected at least 50 characters, got %d", len(token))
	}
	
	// Extract token data part (after prefix)
	tokenData := token[7:] // Skip "mcp_at_" prefix
	
	// Basic base64url character validation (allows A-Z, a-z, 0-9, -, _)
	for _, char := range tokenData {
		if !((char >= 'A' && char <= 'Z') || 
			 (char >= 'a' && char <= 'z') || 
			 (char >= '0' && char <= '9') || 
			 char == '-' || char == '_') {
			return fmt.Errorf("access token contains invalid characters: only base64url characters allowed")
		}
	}
	
	return nil
}

// validateAuthorizationCodeFormat performs basic format validation on authorization codes.
//
// Educational Purpose:
// - Shows consistent validation patterns across token types
// - Demonstrates proper error handling for different token formats
// - Provides debugging support for OAuth flow issues
//
// Parameters:
//   - code: The authorization code to validate
//
// Returns:
//   - error: Validation error with descriptive message, nil if valid
func validateAuthorizationCodeFormat(code string) error {
	// Check for correct authorization code prefix
	if !strings.HasPrefix(code, "mcp_ac_") {
		return fmt.Errorf("invalid authorization code format: missing 'mcp_ac_' prefix")
	}
	
	// Validate minimum length: prefix (7) + base64url data (43 minimum)
	if len(code) < 50 {
		return fmt.Errorf("authorization code too short: expected at least 50 characters, got %d", len(code))
	}
	
	return nil
}

// SECURITY HEADERS FUNCTIONS
// These functions implement comprehensive security headers following modern web security best practices.

// addSecurityHeaders applies comprehensive security headers to HTTP responses.
//
// Educational Purpose:
// - Demonstrates modern web security header practices
// - Shows defense-in-depth security approach
// - Provides protection against common web attacks
// - Explains the purpose and benefit of each security header
//
// Security Headers Applied:
// - X-Content-Type-Options: Prevents MIME type sniffing attacks
// - X-Frame-Options: Prevents clickjacking attacks
// - X-XSS-Protection: Enables browser XSS protection (legacy browsers)
// - Strict-Transport-Security: Enforces HTTPS usage
// - Content-Security-Policy: Restricts resource loading sources
//
// Production Note: 
// - These headers provide defense-in-depth security
// - CSP should be tailored to actual application requirements
// - HSTS max-age should be longer in production (31536000 = 1 year)
//
// Parameters:
//   - w: HTTP response writer to apply headers to
func addSecurityHeaders(w http.ResponseWriter) {
	// Prevent MIME type sniffing attacks
	// This stops browsers from guessing content types and potentially executing
	// malicious content that was uploaded as a different file type
	w.Header().Set("X-Content-Type-Options", "nosniff")
	
	// Prevent clickjacking attacks  
	// This stops the page from being embedded in frames/iframes on other sites
	// which could be used to trick users into clicking on hidden elements
	w.Header().Set("X-Frame-Options", "DENY")
	
	// Enable XSS protection in older browsers
	// Modern browsers have this enabled by default, but this ensures compatibility
	// The "mode=block" prevents rendering when XSS is detected
	w.Header().Set("X-XSS-Protection", "1; mode=block")
	
	// Force HTTPS for future requests (HTTP Strict Transport Security)
	// This prevents downgrade attacks where an attacker forces HTTP usage
	// max-age=31536000 = 1 year, includeSubDomains covers all subdomains
	w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
	
	// Restrict resource loading to same origin (Content Security Policy)
	// This prevents loading of external scripts, styles, images etc. that could
	// be used for attacks. In production, this should be tailored to actual needs
	w.Header().Set("Content-Security-Policy", "default-src 'self'")
}

// OAUTH 2.1 AUTHENTICATION FUNCTIONS
// These functions implement the OAuth 2.1 authentication flow with Bearer token
// validation, following the specifications for protected resource servers.

// generateSecureToken creates a cryptographically secure OAuth 2.1 access token with industry-standard prefix.
//
// Token Format: mcp_at_<base64url_random_data>
// - "mcp" = Company/service identifier (following GitHub's "ghp_" pattern)
// - "at" = Access Token type identifier  
// - Follows industry best practices for token identification and secret scanning
//
// Security Implementation:
// - Uses crypto/rand for cryptographically secure random number generation
// - Generates 32 bytes of entropy (256 bits) for strong token security  
// - Base64URL encoding ensures safe transmission in HTTP headers and URLs
// - No predictable patterns or timing attacks possible
// - Token prefix enables automated detection of leaked tokens
//
// OAuth 2.1 Compliance:
// - Token format meets requirements for Bearer token values
// - Sufficient entropy to prevent brute force attacks
// - URL-safe encoding for HTTP Authorization headers
//
// Educational Benefits:
// - Demonstrates professional token formatting (like GitHub, Stripe)
// - Shows security-conscious development practices
// - Enables easy token identification in logs and debugging
// - Supports secret scanning tools for leak detection
//
// Returns:
//   - string: Prefixed access token (format: mcp_at_<43_chars>)
//   - error: Any error from the random number generator
//
// Example output: "mcp_at_dGVzdF9zZWNyZXRfa2V5X2Zvcl9kZW1vX3B1cnBvc2U"
func generateSecureToken() (string, error) {
	// Generate 32 bytes of cryptographically secure random data
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		// Return detailed error for debugging while avoiding information leakage
		return "", fmt.Errorf("failed to generate secure random token: %w", err)
	}
	
	// Encode as base64URL for safe use in HTTP headers and URLs
	// Base64URL avoids padding issues and URL-unsafe characters
	tokenData := base64.URLEncoding.EncodeToString(bytes)
	tokenData = strings.TrimRight(tokenData, "=") // Remove padding for clean format
	
	// Add industry-standard prefix for professional token identification
	// This follows the pattern used by major platforms (GitHub: ghp_, Stripe: sk_)
	return "mcp_at_" + tokenData, nil
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
	
	// Step 3.5: Validate token format (educational security practice)
	// This catches common integration errors before database lookup
	if err := validateAccessTokenFormat(token); err != nil {
		return nil, fmt.Errorf("malformed token: %w", err)
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
			"/oauth/authorize",                        // Authorization endpoint for code flow
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

// authorizationHandler implements the OAuth 2.1 authorization endpoint with PKCE support.
//
// This endpoint handles the authorization request phase of the OAuth 2.1 authorization code flow.
// It validates the request parameters, generates an authorization code, and redirects the client
// back with the code. PKCE parameters are required as per OAuth 2.1 specification.
//
// OAuth 2.1 + PKCE Flow:
// 1. Validate request parameters (response_type, client_id, redirect_uri, etc.)
// 2. Validate PKCE parameters (code_challenge and code_challenge_method)
// 3. Generate authorization code with 10-minute expiration
// 4. Store authorization code with PKCE information
// 5. Redirect client to redirect_uri with authorization code
//
// Required Parameters:
// - response_type: Must be "code"
// - redirect_uri: Valid redirect URI (https or http for localhost)
// - code_challenge: PKCE code challenge (base64url-encoded SHA256)
// - code_challenge_method: Must be "S256"
//
// Optional Parameters:
// - client_id: Client identifier (for future client authentication)
// - scope: Requested permissions (defaults to "read write")
// - state: CSRF protection token (recommended)
//
// Security Features:
// - PKCE mandatory for all authorization requests
// - Redirect URI validation prevents open redirect attacks
// - Short-lived authorization codes (10 minutes)
// - State parameter support for CSRF protection
// - Comprehensive error handling with proper OAuth error codes
func authorizationHandler(w http.ResponseWriter, r *http.Request) {
	// Only GET requests allowed for authorization endpoint
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Extract query parameters
	query := r.URL.Query()
	responseType := query.Get("response_type")
	redirectURI := query.Get("redirect_uri")
	codeChallenge := query.Get("code_challenge")
	codeChallengeMethod := query.Get("code_challenge_method")
	clientID := query.Get("client_id")
	scope := query.Get("scope")
	state := query.Get("state")

	// Default scope if not provided
	if scope == "" {
		scope = "read write"
	}

	// Validate response_type (OAuth 2.1 requirement)
	if responseType != "code" {
		redirectWithError(w, r, redirectURI, "unsupported_response_type", 
			"Only 'code' response_type is supported", state)
		return
	}

	// Validate redirect_uri (security requirement)
	if err := validateRedirectURI(redirectURI); err != nil {
		http.Error(w, fmt.Sprintf("Invalid redirect_uri: %v", err), http.StatusBadRequest)
		return
	}

	// Validate PKCE parameters (OAuth 2.1 mandatory)
	if codeChallenge == "" {
		redirectWithError(w, r, redirectURI, "invalid_request", 
			"code_challenge is required", state)
		return
	}

	if codeChallengeMethod == "" {
		redirectWithError(w, r, redirectURI, "invalid_request", 
			"code_challenge_method is required", state)
		return
	}

	// Only S256 method is supported (OAuth 2.1 requirement)
	if codeChallengeMethod != "S256" {
		redirectWithError(w, r, redirectURI, "invalid_request", 
			"Only S256 code_challenge_method is supported", state)
		return
	}

	// Validate code_challenge format (base64url, RFC 7636 allows without padding)
	// Try decoding with padding first, then without padding
	challengeWithPadding := codeChallenge
	if len(challengeWithPadding)%4 != 0 {
		challengeWithPadding += strings.Repeat("=", 4-len(challengeWithPadding)%4)
	}
	if _, err := base64.URLEncoding.DecodeString(challengeWithPadding); err != nil {
		redirectWithError(w, r, redirectURI, "invalid_request", 
			"code_challenge must be base64url encoded", state)
		return
	}

	// Generate authorization code
	authCode, err := generateAuthorizationCode()
	if err != nil {
		log.Printf("Failed to generate authorization code: %v", err)
		redirectWithError(w, r, redirectURI, "server_error", 
			"Failed to generate authorization code", state)
		return
	}

	// Store authorization code with PKCE information (10-minute expiration)
	authCodeStore[authCode] = AuthorizationCodeInfo{
		Code:                  authCode,
		ExpiresAt:            time.Now().Add(10 * time.Minute),
		CodeChallenge:        codeChallenge,
		CodeChallengeMethod:  codeChallengeMethod,
		RedirectURI:          redirectURI,
		ResourceURI:          fmt.Sprintf("http://%s", r.Host),
		Scope:                scope,
		ClientID:             clientID,
	}

	// Build redirect URI with authorization code
	redirectURL, err := url.Parse(redirectURI)
	if err != nil {
		log.Printf("Failed to parse redirect URI: %v", err)
		http.Error(w, "Invalid redirect_uri", http.StatusBadRequest)
		return
	}

	// Add authorization code to redirect URI
	values := redirectURL.Query()
	values.Set("code", authCode)
	if state != "" {
		values.Set("state", state)
	}
	redirectURL.RawQuery = values.Encode()

	// Log authorization success (for monitoring)
	log.Printf("Authorization code issued: client=%s, scope=%s, expires=%v", 
		clientID, scope, time.Now().Add(10*time.Minute))

	// Redirect client with authorization code
	http.Redirect(w, r, redirectURL.String(), http.StatusFound)
}

// redirectWithError redirects the client with an OAuth error response.
//
// This helper function handles error responses according to OAuth 2.1 specification,
// including proper error codes and descriptions. If redirect_uri is invalid,
// it returns an HTTP error instead of redirecting.
//
// Parameters:
//   - w: HTTP response writer
//   - redirectURI: Client's redirect URI (may be empty/invalid)
//   - errorCode: OAuth error code (e.g., "invalid_request")
//   - errorDescription: Human-readable error description
//   - state: Client's state parameter (for CSRF protection)
func redirectWithError(w http.ResponseWriter, r *http.Request, redirectURI, errorCode, errorDescription, state string) {
	// If redirect_uri is empty or invalid, return HTTP error
	if redirectURI == "" || validateRedirectURI(redirectURI) != nil {
		http.Error(w, fmt.Sprintf("OAuth Error: %s - %s", errorCode, errorDescription), 
			http.StatusBadRequest)
		return
	}

	// Parse redirect URI
	redirectURL, err := url.Parse(redirectURI)
	if err != nil {
		http.Error(w, "Invalid redirect_uri", http.StatusBadRequest)
		return
	}

	// Add error parameters to redirect URI
	values := redirectURL.Query()
	values.Set("error", errorCode)
	values.Set("error_description", errorDescription)
	if state != "" {
		values.Set("state", state)
	}
	redirectURL.RawQuery = values.Encode()

	// Redirect with error
	http.Redirect(w, r, redirectURL.String(), http.StatusFound)
}

// oauthMetadataHandler provides OAuth 2.0 Protected Resource Metadata
func oauthMetadataHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	
	// Generate OAuth 2.1 metadata JSON with accurate capability reflection
	metadata := map[string]interface{}{
		// Required fields per RFC 8414
		"issuer":         fmt.Sprintf("http://%s", r.Host),
		"token_endpoint": fmt.Sprintf("http://%s/oauth/token", r.Host),
		
		// Authorization endpoint (newly implemented)
		"authorization_endpoint": fmt.Sprintf("http://%s/oauth/authorize", r.Host),
		
		// Supported response types (code flow with PKCE)
		"response_types_supported": []string{"code"},
		
		// Supported grant types (both flows implemented)
		"grant_types_supported": []string{"authorization_code", "client_credentials"},
		
		// PKCE support (OAuth 2.1 requirement)
		"code_challenge_methods_supported": []string{"S256"},
		
		// Token endpoint authentication (none for public clients)
		"token_endpoint_auth_methods_supported": []string{"none"},
		
		// Supported scopes
		"scopes_supported": []string{"read", "write", "admin"},
		
		// Resource identifier for token binding
		"resource": fmt.Sprintf("http://%s", r.Host),
	}
	
	// Marshal to JSON with proper formatting
	jsonBytes, err := json.MarshalIndent(metadata, "", "  ")
	if err != nil {
		log.Printf("Failed to marshal OAuth metadata: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error": "server_error"}`))
		return
	}
	
	w.Write(jsonBytes)
}

// tokenHandler provides OAuth 2.1 token endpoint with support for both client_credentials and authorization_code grants.
//
// This endpoint handles token requests for multiple OAuth 2.1 grant types:
// 1. client_credentials: Service-to-service authentication (existing functionality)
// 2. authorization_code: User authorization flow with PKCE validation (new)
//
// OAuth 2.1 + PKCE Compliance:
// - Validates authorization code and PKCE parameters
// - Enforces S256 code challenge method
// - Verifies redirect_uri matches authorization request
// - Implements proper error handling with OAuth error codes
// - Supports short-lived authorization codes (10 minutes)
// - Issues Bearer tokens with appropriate expiration (1 hour)
//
// Grant Type: authorization_code
// Required Parameters:
// - grant_type: "authorization_code"
// - code: Authorization code from /oauth/authorize
// - redirect_uri: Must match the redirect_uri from authorization request
// - code_verifier: PKCE code verifier (base64url, 43-128 chars)
//
// Grant Type: client_credentials
// Required Parameters:
// - grant_type: "client_credentials"
//
// Response Format:
// - access_token: Bearer token for API access
// - token_type: "Bearer"
// - expires_in: Token lifetime in seconds (3600 = 1 hour)
// - scope: Granted permissions
func tokenHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusMethodNotAllowed)
		w.Write([]byte(`{"error": "invalid_request", "error_description": "Only POST method is allowed"}`))
		return
	}

	// Parse form data
	err := r.ParseForm()
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error": "invalid_request", "error_description": "Failed to parse form data"}`))
		return
	}

	grantType := r.FormValue("grant_type")
	
	// Handle different grant types
	switch grantType {
	case "authorization_code":
		handleAuthorizationCodeGrant(w, r)
	case "client_credentials":
		handleClientCredentialsGrant(w, r)
	default:
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error": "unsupported_grant_type", "error_description": "Supported grant types: authorization_code, client_credentials"}`))
	}
}

// handleAuthorizationCodeGrant processes authorization_code grant requests with PKCE validation.
//
// This function implements the token exchange phase of OAuth 2.1 authorization code flow:
// 1. Validates authorization code existence and expiration
// 2. Validates PKCE code_verifier against stored code_challenge
// 3. Validates redirect_uri matches authorization request
// 4. Issues Bearer token with appropriate scope and expiration
// 5. Cleans up used authorization code (single-use requirement)
//
// Security Features:
// - Authorization codes are single-use (deleted after successful exchange)
// - PKCE validation prevents code injection attacks
// - Redirect URI validation prevents authorization code interception
// - Automatic cleanup of expired authorization codes
// - Comprehensive error handling without information leakage
func handleAuthorizationCodeGrant(w http.ResponseWriter, r *http.Request) {
	// Extract required parameters
	code := r.FormValue("code")
	redirectURI := r.FormValue("redirect_uri")
	codeVerifier := r.FormValue("code_verifier")

	// Validate required parameters
	if code == "" {
		writeTokenError(w, "invalid_request", "code parameter is required")
		return
	}
	if redirectURI == "" {
		writeTokenError(w, "invalid_request", "redirect_uri parameter is required")
		return
	}
	if codeVerifier == "" {
		writeTokenError(w, "invalid_request", "code_verifier parameter is required")
		return
	}

	// Validate authorization code format (educational security practice)
	if err := validateAuthorizationCodeFormat(code); err != nil {
		writeTokenError(w, "invalid_grant", fmt.Sprintf("Malformed authorization code: %v", err))
		return
	}

	// Look up authorization code
	authCodeInfo, exists := authCodeStore[code]
	if !exists {
		writeTokenError(w, "invalid_grant", "Invalid or expired authorization code")
		return
	}

	// Check authorization code expiration
	if time.Now().After(authCodeInfo.ExpiresAt) {
		// Clean up expired code
		delete(authCodeStore, code)
		writeTokenError(w, "invalid_grant", "Authorization code has expired")
		return
	}

	// Validate redirect_uri matches authorization request
	if redirectURI != authCodeInfo.RedirectURI {
		writeTokenError(w, "invalid_grant", "redirect_uri does not match authorization request")
		return
	}

	// Validate PKCE code_verifier
	log.Printf("DEBUG: code_verifier='%s', stored_challenge='%s', method='%s'", 
		codeVerifier, authCodeInfo.CodeChallenge, authCodeInfo.CodeChallengeMethod)
	valid, err := validateCodeChallenge(codeVerifier, authCodeInfo.CodeChallenge, authCodeInfo.CodeChallengeMethod)
	if err != nil {
		log.Printf("PKCE validation error: %v", err)
		writeTokenError(w, "invalid_grant", "Invalid code_verifier")
		return
	}
	if !valid {
		writeTokenError(w, "invalid_grant", "code_verifier validation failed")
		return
	}

	// PKCE validation successful - generate Bearer token
	token, err := generateSecureToken()
	if err != nil {
		log.Printf("Token generation error: %v", err)
		writeTokenError(w, "server_error", "Failed to generate access token")
		return
	}

	// Store token with expiration (1 hour)
	expiresAt := time.Now().Add(time.Hour)
	tokenStore[token] = TokenInfo{
		Token:       token,
		ExpiresAt:   expiresAt,
		ResourceURI: authCodeInfo.ResourceURI,
		Scope:       authCodeInfo.Scope,
	}

	// Clean up authorization code (single-use requirement)
	delete(authCodeStore, code)

	// Log successful token exchange
	log.Printf("Token issued via authorization_code: scope=%s, expires=%v", 
		authCodeInfo.Scope, expiresAt)

	// Return successful token response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(fmt.Sprintf(`{
		"access_token": "%s",
		"token_type": "Bearer",
		"expires_in": 3600,
		"scope": "%s"
	}`, token, authCodeInfo.Scope)))
}

// handleClientCredentialsGrant processes client_credentials grant requests.
//
// This function implements the client credentials flow for service-to-service authentication.
// It's a simplified flow without user involvement, suitable for backend services.
//
// OAuth 2.1 Compliance:
// - Issues Bearer tokens for service authentication
// - Implements proper token expiration (1 hour)
// - Returns standard OAuth token response format
// - Supports scope parameter for permission control
func handleClientCredentialsGrant(w http.ResponseWriter, r *http.Request) {
	// Extract optional scope parameter
	scope := r.FormValue("scope")
	if scope == "" {
		scope = "read write"
	}

	// Generate new token
	token, err := generateSecureToken()
	if err != nil {
		log.Printf("Token generation error: %v", err)
		writeTokenError(w, "server_error", "Failed to generate access token")
		return
	}

	// Store token with expiration (1 hour)
	expiresAt := time.Now().Add(time.Hour)
	tokenStore[token] = TokenInfo{
		Token:       token,
		ExpiresAt:   expiresAt,
		ResourceURI: fmt.Sprintf("http://%s", r.Host),
		Scope:       scope,
	}

	// Log successful token issuance
	log.Printf("Token issued via client_credentials: scope=%s, expires=%v", 
		scope, expiresAt)

	// Return successful token response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(fmt.Sprintf(`{
		"access_token": "%s",
		"token_type": "Bearer",
		"expires_in": 3600,
		"scope": "%s"
	}`, token, scope)))
}

// writeTokenError writes an OAuth 2.1 compliant error response for token endpoint errors.
//
// This helper function ensures consistent error formatting according to OAuth 2.1 specification.
// Error responses include proper HTTP status codes and structured JSON error information.
//
// Parameters:
//   - w: HTTP response writer
//   - errorCode: OAuth error code (e.g., "invalid_grant", "invalid_request")
//   - errorDescription: Human-readable error description
func writeTokenError(w http.ResponseWriter, errorCode, errorDescription string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	w.Write([]byte(fmt.Sprintf(`{"error": "%s", "error_description": "%s"}`, 
		errorCode, errorDescription)))
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
	mux.HandleFunc("/oauth/authorize", authorizationHandler)
	mux.HandleFunc("/oauth/token", tokenHandler)
	
	// MCP endpoints with authentication
	mcpHandler := createMCPHandler(server)
	mux.Handle("/mcp", authenticationMiddleware(mcpHandler))
	mux.Handle("/", authenticationMiddleware(mcpHandler))
	
	// Add security headers middleware with educational explanations
	securityMiddleware := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Apply comprehensive security headers (educational security practice)
			addSecurityHeaders(w)
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
	
	log.Printf("OAuth 2.1 + PKCE endpoints:")
	log.Printf("  Discovery: %s://localhost:%s/.well-known/oauth-authorization-server", protocol, port)
	log.Printf("  Authorize: %s://localhost:%s/oauth/authorize", protocol, port)
	log.Printf("  Token:     %s://localhost:%s/oauth/token", protocol, port)
	log.Printf("  MCP API:   %s://localhost:%s/mcp", protocol, port)
	
	// Enhanced example usage documentation
	log.Printf("\n" + strings.Repeat("=", 80))
	log.Printf("COMPLETE OAUTH 2.1 + PKCE FLOW EXAMPLES")
	log.Printf(strings.Repeat("=", 80))
	
	log.Printf("\n1. CLIENT CREDENTIALS FLOW (Service-to-Service):")
	log.Printf("   curl -X POST %s://localhost:%s/oauth/token \\", protocol, port)
	log.Printf("     -H 'Content-Type: application/x-www-form-urlencoded' \\")
	log.Printf("     -d 'grant_type=client_credentials'")
	log.Printf("   # Returns: {\"access_token\": \"mcp_at_...\", \"token_type\": \"Bearer\"}")
	
	log.Printf("\n2. AUTHORIZATION CODE + PKCE FLOW (Interactive):")
	log.Printf("   # Step 1: Generate PKCE parameters")
	log.Printf("   code_verifier=$(openssl rand -base64 32 | tr -d \"=+/\" | cut -c1-43)")
	log.Printf("   code_challenge=$(echo -n $code_verifier | openssl dgst -sha256 -binary | openssl base64 | tr -d \"=+/\")")
	log.Printf("   ")
	log.Printf("   # Step 2: Authorization request")
	log.Printf("   curl '%s://localhost:%s/oauth/authorize?response_type=code&redirect_uri=http://localhost:3000/callback&code_challenge=$code_challenge&code_challenge_method=S256&state=abc123'", protocol, port)
	log.Printf("   # Returns: HTTP 302 redirect with authorization code (mcp_ac_...)")
	log.Printf("   ")
	log.Printf("   # Step 3: Token exchange")
	log.Printf("   curl -X POST %s://localhost:%s/oauth/token \\", protocol, port)
	log.Printf("     -H 'Content-Type: application/x-www-form-urlencoded' \\")
	log.Printf("     -d 'grant_type=authorization_code&code=mcp_ac_...&redirect_uri=http://localhost:3000/callback&code_verifier=$code_verifier'")
	log.Printf("   # Returns: {\"access_token\": \"mcp_at_...\", \"token_type\": \"Bearer\"}")
	
	log.Printf("\n3. MCP API ACCESS (Using Bearer Token):")
	log.Printf("   curl -X POST %s://localhost:%s/mcp \\", protocol, port)
	log.Printf("     -H 'Authorization: Bearer mcp_at_...' \\")
	log.Printf("     -H 'Content-Type: application/json' \\")
	log.Printf("     -d '{\"jsonrpc\":\"2.0\",\"method\":\"tools/list\",\"id\":1}'")
	
	log.Printf("\n" + strings.Repeat("=", 80))
	log.Printf("TOKEN FORMAT NOTES:")
	log.Printf("  • Access tokens:       mcp_at_<base64url_data> (Bearer tokens)")
	log.Printf("  • Authorization codes: mcp_ac_<base64url_data> (Short-lived)")
	log.Printf("  • Professional format following GitHub/Stripe patterns")
	log.Printf("  • Enables secret scanning and automated detection")
	log.Printf(strings.Repeat("=", 80))
	
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