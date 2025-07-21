# OAuth 2.1 Authorization for MCP Servers

## Overview

This document outlines the OAuth 2.1 authorization requirements for MCP servers based on the MCP 2025-06-18 specification.

## Key Requirements

### Authorization Server Discovery

- Servers must implement OAuth 2.0 Protected Resource Metadata
- Provide location of authorization servers via metadata
- Support dynamic client registration

### Token Handling

- Use "Bearer" token in Authorization header
- Tokens must be:
  - Specific to the target resource
  - Short-lived
  - Validated by resource server

### Security Considerations

- Implement PKCE (Proof Key for Code Exchange)
- Validate token audiences
- Prevent token theft and redirection attacks
- Protect against "confused deputy" vulnerabilities

### Client Requirements

- Include `resource` parameter in authorization requests
- Use canonical server URI for resource identification
- Support dynamic client registration

### Error Handling

- **401 Unauthorized**: Authentication required/invalid token
- **403 Forbidden**: Insufficient permissions
- **400 Bad Request**: Malformed authorization request

## Critical Security Principles

1. **Token Validation**: MCP servers MUST validate that tokens were issued specifically for them
2. **Resource-Specific Tokens**: Authorization servers MUST only accept tokens valid for their resources
3. **No Token Passthrough**: Prevent token passthrough between services

## Implementation Checklist

- [ ] Implement OAuth 2.0 Protected Resource Metadata endpoint
- [ ] Add Bearer token validation middleware
- [ ] Create token introspection endpoint
- [ ] Implement resource-specific token validation
- [ ] Add PKCE support
- [ ] Configure proper error responses
- [ ] Add security headers and TLS configuration
- [ ] Implement rate limiting
- [ ] Add request validation and sanitization
- [ ] Configure connection origin validation

## Transport Security

- Use TLS for all remote connections
- Validate connection origins
- Implement authentication when needed
- Monitor resource usage
- Rate limit requests

## Message Validation

- Validate all incoming messages
- Sanitize inputs
- Check message size limits
- Verify JSON-RPC format
- Log security-relevant errors