# MCP Server Usage Examples

## Overview

This document provides comprehensive examples for interacting with all three phases of the MCP server implementation. Each example includes detailed explanations and practical usage scenarios.

## Table of Contents

1. [Phase 1: Stdio Transport Examples](#phase-1-stdio-transport-examples)
2. [Phase 2: Network Transport Examples](#phase-2-network-transport-examples)  
3. [Phase 3: OAuth 2.1 Authentication Examples](#phase-3-oauth-21-authentication-examples)
4. [Client Integration Examples](#client-integration-examples)
5. [Troubleshooting Examples](#troubleshooting-examples)

## Phase 1: Stdio Transport Examples

### Starting the Server

```bash
# Build the server
cd stdio/
go build -o ~/bin/mcp-demo-server-stdio .

# Start the server (stdio mode - interactive)
mcp-demo-server-stdio
```

### Using with MCP-Compatible Clients

#### Claude Code Integration
Add to `~/.config/claude-code/mcp.json`:
```json
{
  "mcpServers": {
    "file-system-stdio": {
      "command": "mcp-demo-server-stdio",
      "args": [],
      "transport": "stdio",
      "description": "File system MCP server with stdio transport"
    }
  }
}
```

#### Manual Testing with stdio
```bash
# Send JSON-RPC request via stdin
echo '{"jsonrpc": "2.0", "method": "tools/list", "id": 1}' | mcp-demo-server-stdio
```

**Expected Response:**
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
      }
      // ... other tools
    ]
  },
  "id": 1
}
```

## Phase 2: Network Transport Examples

### Starting the Server

```bash
# Build the server
cd network/
go build -o ~/bin/mcp-demo-server-network .

# Start on default port (8080)
mcp-demo-server-network &

# Start on custom port
MCP_SERVER_PORT=9090 mcp-demo-server-network &
```

### HTTP Client Examples

#### Using curl

**List Available Tools:**
```bash
curl -X POST http://localhost:8080/mcp \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "tools/list",
    "id": 1
  }'
```

**Read a File:**
```bash
curl -X POST http://localhost:8080/mcp \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "tools/call",
    "params": {
      "name": "read_file",
      "arguments": {
        "file_path": "/etc/hostname"
      }
    },
    "id": 2
  }'
```

**List Directory Contents:**
```bash
curl -X POST http://localhost:8080/mcp \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "tools/call",
    "params": {
      "name": "list_directory",
      "arguments": {
        "directory_path": "/tmp"
      }
    },
    "id": 3
  }'
```

**Get System Information:**
```bash
curl -X POST http://localhost:8080/mcp \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "tools/call",
    "params": {
      "name": "get_system_info",
      "arguments": {
        "info_type": "os"
      }
    },
    "id": 4
  }'
```

#### Using JavaScript/Node.js

```javascript
// Simple HTTP MCP client
const axios = require('axios');

class SimpleMCPClient {
  constructor(baseURL) {
    this.baseURL = baseURL;
    this.requestId = 1;
  }

  async callTool(toolName, arguments) {
    const request = {
      jsonrpc: "2.0",
      method: "tools/call",
      params: {
        name: toolName,
        arguments: arguments
      },
      id: this.requestId++
    };

    try {
      const response = await axios.post(this.baseURL, request, {
        headers: { 'Content-Type': 'application/json' }
      });
      return response.data.result;
    } catch (error) {
      console.error('MCP request failed:', error.response?.data || error.message);
      throw error;
    }
  }

  async listTools() {
    const request = {
      jsonrpc: "2.0", 
      method: "tools/list",
      id: this.requestId++
    };

    const response = await axios.post(this.baseURL, request, {
      headers: { 'Content-Type': 'application/json' }
    });
    return response.data.result.tools;
  }
}

// Usage example
async function example() {
  const client = new SimpleMCPClient('http://localhost:8080/mcp');

  // List available tools
  const tools = await client.listTools();
  console.log('Available tools:', tools.map(t => t.name));

  // Read a file
  const fileContent = await client.callTool('read_file', {
    file_path: '/etc/hostname'
  });
  console.log('File content:', fileContent);

  // Get system info
  const osInfo = await client.callTool('get_system_info', {
    info_type: 'os'
  });
  console.log('OS Info:', osInfo);
}
```

#### Using Python

```python
import requests
import json

class SimpleMCPClient:
    def __init__(self, base_url):
        self.base_url = base_url
        self.request_id = 1
        
    def call_tool(self, tool_name, arguments):
        request_data = {
            "jsonrpc": "2.0",
            "method": "tools/call", 
            "params": {
                "name": tool_name,
                "arguments": arguments
            },
            "id": self.request_id
        }
        self.request_id += 1
        
        response = requests.post(
            self.base_url,
            json=request_data,
            headers={"Content-Type": "application/json"}
        )
        response.raise_for_status()
        return response.json()["result"]
    
    def list_tools(self):
        request_data = {
            "jsonrpc": "2.0",
            "method": "tools/list",
            "id": self.request_id
        }
        self.request_id += 1
        
        response = requests.post(
            self.base_url,
            json=request_data,
            headers={"Content-Type": "application/json"}
        )
        response.raise_for_status()
        return response.json()["result"]["tools"]

# Usage example
if __name__ == "__main__":
    client = SimpleMCPClient("http://localhost:8080/mcp")
    
    # List tools
    tools = client.list_tools()
    print(f"Available tools: {[tool['name'] for tool in tools]}")
    
    # Read system info
    os_info = client.call_tool("get_system_info", {"info_type": "os"})
    print(f"OS Info: {os_info}")
    
    # List directory
    dir_contents = client.call_tool("list_directory", {"directory_path": "/tmp"})
    print(f"Directory contents: {dir_contents}")
```

### Claude Code Integration

Add to `~/.config/claude-code/mcp.json`:
```json
{
  "mcpServers": {
    "file-system-network": {
      "url": "http://localhost:8080",
      "transport": "http",
      "description": "Network MCP server with HTTP transport"
    }
  }
}
```

## Phase 3: OAuth 2.1 Authentication Examples

### Starting the Server

```bash
# Build the server
cd auth/
go build -o ~/bin/mcp-demo-server-auth .

# Start with HTTPS (default)
mcp-demo-server-auth &

# Start with HTTP for testing
MCP_USE_TLS=false MCP_SERVER_PORT=8443 mcp-demo-server-auth &
```

### OAuth 2.1 Authentication Flow

#### Step 1: Discover OAuth Endpoints

```bash
curl http://localhost:8443/.well-known/oauth-authorization-server
```

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

#### Step 2: Obtain Access Token

```bash
curl -X POST http://localhost:8443/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials"
```

**Response:**
```json
{
  "access_token": "dGVzdF9zZWNyZXRfa2V5X2Zvcl9kZW1vX3B1cnBvc2U=",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "read write"
}
```

#### Step 3: Use Access Token for MCP Requests

```bash
# Store token for convenience
TOKEN="dGVzdF9zZWNyZXRfa2V5X2Zvcl9kZW1vX3B1cnBvc2U="

# List tools with authentication
curl -X POST http://localhost:8443/mcp \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "tools/list", 
    "id": 1
  }'

# Call tool with authentication
curl -X POST http://localhost:8443/mcp \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "tools/call",
    "params": {
      "name": "get_system_info",
      "arguments": {
        "info_type": "working_dir"
      }
    },
    "id": 2
  }'
```

#### Complete Authentication Example Script

```bash
#!/bin/bash
# complete_auth_example.sh

set -e

MCP_SERVER="http://localhost:8443"
echo "🔐 MCP OAuth 2.1 Authentication Example"
echo "======================================"

# Step 1: Get OAuth metadata
echo "📋 Step 1: Discovering OAuth endpoints..."
curl -s "$MCP_SERVER/.well-known/oauth-authorization-server" | jq .
echo

# Step 2: Get access token  
echo "🎟️  Step 2: Obtaining access token..."
TOKEN_RESPONSE=$(curl -s -X POST "$MCP_SERVER/oauth/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials")

echo "Token response: $TOKEN_RESPONSE" | jq .
ACCESS_TOKEN=$(echo "$TOKEN_RESPONSE" | jq -r '.access_token')
echo "Access token: $ACCESS_TOKEN"
echo

# Step 3: Test authentication failure
echo "❌ Step 3: Testing request without authentication..."
curl -s -X POST "$MCP_SERVER/mcp" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc": "2.0", "method": "tools/list", "id": 1}' || true
echo
echo

# Step 4: List tools with authentication
echo "✅ Step 4: Listing tools with authentication..."
curl -s -X POST "$MCP_SERVER/mcp" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc": "2.0", "method": "tools/list", "id": 1}' | jq .
echo

# Step 5: Call tool with authentication
echo "🔧 Step 5: Calling tool with authentication..."
curl -s -X POST "$MCP_SERVER/mcp" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "tools/call",
    "params": {
      "name": "get_system_info", 
      "arguments": {"info_type": "os"}
    },
    "id": 2
  }' | jq .

echo "🎉 Authentication example completed successfully!"
```

Make it executable and run:
```bash
chmod +x complete_auth_example.sh
./complete_auth_example.sh
```

### Authenticated Client Examples

#### JavaScript/Node.js with OAuth

```javascript
const axios = require('axios');

class AuthenticatedMCPClient {
  constructor(baseURL, tokenEndpoint) {
    this.baseURL = baseURL;
    this.tokenEndpoint = tokenEndpoint;
    this.accessToken = null;
    this.tokenExpiry = null;
    this.requestId = 1;
  }

  async authenticate() {
    try {
      const response = await axios.post(this.tokenEndpoint, 
        'grant_type=client_credentials',
        {
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded'
          }
        }
      );

      this.accessToken = response.data.access_token;
      // Calculate expiry time (subtract 60s for safety margin)
      this.tokenExpiry = new Date(Date.now() + (response.data.expires_in - 60) * 1000);
      
      console.log('Authentication successful');
      return this.accessToken;
    } catch (error) {
      console.error('Authentication failed:', error.response?.data || error.message);
      throw error;
    }
  }

  async ensureAuthenticated() {
    if (!this.accessToken || new Date() >= this.tokenExpiry) {
      await this.authenticate();
    }
  }

  async makeRequest(method, params = null) {
    await this.ensureAuthenticated();

    const request = {
      jsonrpc: "2.0",
      method: method,
      id: this.requestId++
    };

    if (params) {
      request.params = params;
    }

    try {
      const response = await axios.post(this.baseURL, request, {
        headers: {
          'Authorization': `Bearer ${this.accessToken}`,
          'Content-Type': 'application/json'
        }
      });
      return response.data.result;
    } catch (error) {
      console.error('MCP request failed:', error.response?.data || error.message);
      throw error;
    }
  }

  async listTools() {
    return await this.makeRequest('tools/list');
  }

  async callTool(toolName, arguments) {
    return await this.makeRequest('tools/call', {
      name: toolName,
      arguments: arguments
    });
  }
}

// Usage example
async function authenticatedExample() {
  const client = new AuthenticatedMCPClient(
    'http://localhost:8443/mcp',
    'http://localhost:8443/oauth/token'
  );

  try {
    // Authentication is handled automatically
    const tools = await client.listTools();
    console.log('Available tools:', tools.tools.map(t => t.name));

    // Call tools
    const osInfo = await client.callTool('get_system_info', { info_type: 'os' });
    console.log('OS Info:', osInfo);

    const fileContent = await client.callTool('read_file', { 
      file_path: '/etc/hostname' 
    });
    console.log('Hostname:', fileContent);

  } catch (error) {
    console.error('Example failed:', error.message);
  }
}

// Run the example
authenticatedExample();
```

#### Python with OAuth

```python
import requests
import time
from datetime import datetime, timedelta

class AuthenticatedMCPClient:
    def __init__(self, base_url, token_endpoint):
        self.base_url = base_url
        self.token_endpoint = token_endpoint
        self.access_token = None
        self.token_expiry = None
        self.request_id = 1
        
    def authenticate(self):
        """Obtain OAuth 2.1 access token"""
        try:
            response = requests.post(
                self.token_endpoint,
                data={"grant_type": "client_credentials"},
                headers={"Content-Type": "application/x-www-form-urlencoded"}
            )
            response.raise_for_status()
            
            token_data = response.json()
            self.access_token = token_data["access_token"]
            # Calculate expiry (subtract 60s for safety margin)
            expires_in = token_data.get("expires_in", 3600)
            self.token_expiry = datetime.now() + timedelta(seconds=expires_in - 60)
            
            print("Authentication successful")
            return self.access_token
            
        except requests.RequestException as e:
            print(f"Authentication failed: {e}")
            raise
    
    def ensure_authenticated(self):
        """Ensure we have a valid access token"""
        if not self.access_token or datetime.now() >= self.token_expiry:
            self.authenticate()
    
    def make_request(self, method, params=None):
        """Make authenticated MCP request"""
        self.ensure_authenticated()
        
        request_data = {
            "jsonrpc": "2.0",
            "method": method,
            "id": self.request_id
        }
        if params:
            request_data["params"] = params
        
        self.request_id += 1
        
        try:
            response = requests.post(
                self.base_url,
                json=request_data,
                headers={
                    "Authorization": f"Bearer {self.access_token}",
                    "Content-Type": "application/json"
                }
            )
            response.raise_for_status()
            return response.json()["result"]
            
        except requests.RequestException as e:
            print(f"MCP request failed: {e}")
            raise
    
    def list_tools(self):
        return self.make_request("tools/list")
    
    def call_tool(self, tool_name, arguments):
        return self.make_request("tools/call", {
            "name": tool_name,
            "arguments": arguments
        })

# Usage example
if __name__ == "__main__":
    client = AuthenticatedMCPClient(
        "http://localhost:8443/mcp",
        "http://localhost:8443/oauth/token"
    )
    
    try:
        # List tools (authentication handled automatically)
        tools = client.list_tools()
        print(f"Available tools: {[tool['name'] for tool in tools['tools']]}")
        
        # Call tools
        os_info = client.call_tool("get_system_info", {"info_type": "os"})
        print(f"OS Info: {os_info}")
        
        dir_contents = client.call_tool("list_directory", {"directory_path": "/tmp"})
        print(f"Directory listing: {dir_contents}")
        
    except Exception as e:
        print(f"Example failed: {e}")
```

### Claude Code Integration with Authentication

Add to `~/.config/claude-code/mcp.json`:
```json
{
  "mcpServers": {
    "file-system-auth": {
      "url": "http://localhost:8443",
      "transport": "http",
      "description": "OAuth 2.1 authenticated MCP server",
      "headers": {
        "Authorization": "Bearer YOUR_TOKEN_HERE"
      }
    }
  }
}
```

**Note**: Replace `YOUR_TOKEN_HERE` with an actual token obtained from the token endpoint. In production, consider implementing automatic token refresh.

## Client Integration Examples

### Integration with Popular HTTP Clients

#### Postman Collection

Create a Postman collection for testing:

1. **Collection Variables**:
   - `baseUrl`: `http://localhost:8443`
   - `accessToken`: (will be set automatically)

2. **Pre-request Script** (for authenticated requests):
```javascript
// Auto-authenticate if no token or token expired
if (!pm.collectionVariables.get("accessToken") || 
    !pm.collectionVariables.get("tokenExpiry") ||
    new Date() >= new Date(pm.collectionVariables.get("tokenExpiry"))) {
    
    pm.sendRequest({
        url: pm.collectionVariables.get("baseUrl") + "/oauth/token",
        method: "POST",
        header: {
            "Content-Type": "application/x-www-form-urlencoded"
        },
        body: {
            mode: "urlencoded",
            urlencoded: [
                {key: "grant_type", value: "client_credentials"}
            ]
        }
    }, function (err, response) {
        if (!err && response.code === 200) {
            const tokenData = response.json();
            pm.collectionVariables.set("accessToken", tokenData.access_token);
            
            // Set expiry time
            const expiryTime = new Date(Date.now() + (tokenData.expires_in - 60) * 1000);
            pm.collectionVariables.set("tokenExpiry", expiryTime.toISOString());
        }
    });
}
```

3. **Request Headers** (for authenticated requests):
```
Authorization: Bearer {{accessToken}}
Content-Type: application/json
```

#### HTTPie Examples

```bash
# Get token and store in variable
export TOKEN=$(http POST localhost:8443/oauth/token \
  grant_type=client_credentials \
  --print=b | jq -r '.access_token')

# List tools
http POST localhost:8443/mcp \
  "Authorization:Bearer $TOKEN" \
  jsonrpc:="2.0" method:="tools/list" id:=1

# Call tool
http POST localhost:8443/mcp \
  "Authorization:Bearer $TOKEN" \
  jsonrpc:="2.0" \
  method:="tools/call" \
  params:='{"name":"get_system_info","arguments":{"info_type":"arch"}}' \
  id:=2
```

## Troubleshooting Examples

### Common Issues and Solutions

#### Issue: Connection Refused
```bash
# Check if server is running
ps aux | grep mcp-demo-server

# Check port availability
lsof -i :8443

# Start server with debug output
MCP_USE_TLS=false mcp-demo-server-auth
```

#### Issue: Authentication Failures

**Invalid Token Format:**
```bash
# Wrong - missing "Bearer " prefix
curl -H "Authorization: abc123" http://localhost:8443/mcp

# Correct - with "Bearer " prefix  
curl -H "Authorization: Bearer abc123" http://localhost:8443/mcp
```

**Expired Token:**
```bash
# Check token expiry in response
curl -X POST http://localhost:8443/oauth/token \
  -d "grant_type=client_credentials" | jq .

# Response shows expires_in: 3600 (1 hour)
```

#### Issue: Tool Call Failures

**Missing Required Parameters:**
```json
// Wrong - missing required file_path
{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "name": "read_file",
    "arguments": {}
  },
  "id": 1
}

// Correct - includes required file_path
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

**Invalid File Paths:**
```bash
# This will fail - file doesn't exist
curl -X POST http://localhost:8443/mcp \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "jsonrpc": "2.0",
    "method": "tools/call", 
    "params": {
      "name": "read_file",
      "arguments": {"file_path": "/nonexistent/file.txt"}
    },
    "id": 1
  }'

# Error response:
# {"jsonrpc":"2.0","error":{"message":"file does not exist: /nonexistent/file.txt"},"id":1}
```

#### Debugging Network Issues

```bash
# Test basic connectivity
curl -v http://localhost:8443/.well-known/oauth-authorization-server

# Check TLS connectivity (if using HTTPS)
openssl s_client -connect localhost:8443 -servername localhost

# Monitor server logs
tail -f /var/log/mcp-server.log  # if logging to file

# Test with verbose curl output
curl -v -X POST http://localhost:8443/mcp \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"tools/list","id":1}'
```

### Performance Testing Examples

#### Basic Load Testing with curl

```bash
#!/bin/bash
# simple_load_test.sh

# Get token first
TOKEN=$(curl -s -X POST http://localhost:8443/oauth/token \
  -d "grant_type=client_credentials" | jq -r '.access_token')

echo "Starting load test with token: $TOKEN"

# Run 100 concurrent requests
for i in {1..100}; do
  curl -s -X POST http://localhost:8443/mcp \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"jsonrpc\":\"2.0\",\"method\":\"tools/list\",\"id\":$i}" &
done

wait
echo "Load test completed"
```

#### Monitoring Response Times

```bash
# Test response times
time curl -X POST http://localhost:8443/mcp \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"get_system_info","arguments":{"info_type":"os"},"id":1}'

# Use curl's built-in timing
curl -w "@curl-format.txt" -X POST http://localhost:8443/mcp \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"tools/list","id":1}'

# curl-format.txt content:
#      time_namelookup:  %{time_namelookup}\n
#         time_connect:  %{time_connect}\n
#      time_appconnect:  %{time_appconnect}\n
#     time_pretransfer:  %{time_pretransfer}\n
#        time_redirect:  %{time_redirect}\n
#   time_starttransfer:  %{time_starttransfer}\n
#                     ----------\n
#           time_total:  %{time_total}\n
```

This comprehensive examples documentation provides practical, working examples for all three phases of the MCP server implementation, making it easy for users to understand and integrate with the servers.