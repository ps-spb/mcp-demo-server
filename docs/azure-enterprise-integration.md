# Azure Enterprise Apps Integration Guide

## Overview

This document provides comprehensive guidance for integrating the OAuth 2.1 authenticated MCP server with Microsoft Azure Enterprise Applications (Azure AD/Entra ID). This integration enables enterprise-grade authentication, authorization, and monitoring for your MCP server deployment.

## Table of Contents

1. [Azure AD App Registration](#azure-ad-app-registration)
2. [OAuth 2.1 Configuration](#oauth-21-configuration)
3. [Client Authentication Methods](#client-authentication-methods)
4. [Required API Permissions](#required-api-permissions)
5. [MCP Server Configuration](#mcp-server-configuration)
6. [Multi-Tenant Considerations](#multi-tenant-considerations)
7. [Deployment Options](#deployment-options)
8. [Monitoring and Logging](#monitoring-and-logging)
9. [Security Best Practices](#security-best-practices)
10. [Troubleshooting](#troubleshooting)

## Azure AD App Registration

### Step 1: Create a New App Registration

1. Navigate to the [Azure Portal](https://portal.azure.com)
2. Go to **Azure Active Directory** > **App registrations** > **New registration**
3. Configure the following:
   - **Name**: `MCP Server - OAuth 2.1 Authentication`
   - **Supported account types**: Choose based on your organization's needs:
     - **Accounts in this organizational directory only**: Single-tenant
     - **Accounts in any organizational directory**: Multi-tenant
     - **Accounts in any organizational directory and personal Microsoft accounts**: Multi-tenant with consumer accounts
   - **Redirect URI**: Leave blank for client credentials flow
4. Click **Register**

### Step 2: Configure App Registration

#### Application (Client) ID
- Note the **Application (client) ID** from the **Overview** page
- This will be used as `client_id` in OAuth requests

#### Directory (Tenant) ID
- Note the **Directory (tenant) ID** from the **Overview** page
- This identifies your Azure AD tenant

#### Client Secrets
1. Go to **Certificates & secrets** > **Client secrets** > **New client secret**
2. Configure:
   - **Description**: `MCP Server Client Secret`
   - **Expires**: Choose appropriate expiration (recommended: 12-24 months)
3. **Important**: Copy the secret value immediately - it won't be shown again
4. Store securely in your deployment environment

## OAuth 2.1 Configuration

### Token Endpoint Configuration

Azure AD OAuth 2.1 endpoints follow this pattern:
```
Authorization Endpoint: https://login.microsoftonline.com/{tenant-id}/oauth2/v2.0/authorize
Token Endpoint: https://login.microsoftonline.com/{tenant-id}/oauth2/v2.0/token
```

### Supported Grant Types

For MCP server integration, use **Client Credentials** grant type:

#### Client Credentials Flow
```bash
curl -X POST https://login.microsoftonline.com/{tenant-id}/oauth2/v2.0/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials" \
  -d "client_id={client-id}" \
  -d "client_secret={client-secret}" \
  -d "scope=https://graph.microsoft.com/.default"
```

Response:
```json
{
    "token_type": "Bearer",
    "expires_in": 3599,
    "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIs..."
}
```

## Client Authentication Methods

### 1. Client Secret (Recommended for Development)

Configure in Azure AD:
- **Certificates & secrets** > **Client secrets**
- Use `client_secret_post` or `client_secret_basic` method

Example request:
```bash
curl -X POST https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token \
  -d "grant_type=client_credentials&client_id={id}&client_secret={secret}&scope=api://your-app/.default"
```

### 2. Certificate-based Authentication (Recommended for Production)

Configure in Azure AD:
1. **Certificates & secrets** > **Certificates** > **Upload certificate**
2. Upload your X.509 certificate (.cer, .pem, or .crt)

Generate certificate:
```bash
# Generate private key
openssl genrsa -out mcp-server.key 2048

# Generate certificate signing request
openssl req -new -key mcp-server.key -out mcp-server.csr

# Generate self-signed certificate (for development)
openssl x509 -req -days 365 -in mcp-server.csr -signkey mcp-server.key -out mcp-server.crt

# Convert to PEM format for Azure
openssl x509 -in mcp-server.crt -out mcp-server.pem -outform PEM
```

JWT assertion example:
```json
{
  "aud": "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token",
  "exp": 1234567890,
  "iss": "{client-id}",
  "jti": "unique-jwt-id",
  "nbf": 1234567890,
  "sub": "{client-id}"
}
```

## Required API Permissions

### For MCP Server Access

1. **Custom API Permissions**:
   - Define custom scopes in your app registration
   - Example scopes: `mcp.read`, `mcp.write`, `mcp.admin`

2. **Microsoft Graph API** (if needed):
   - `User.Read`: Read user profile
   - `Directory.Read.All`: Read directory data (for user validation)

### Configuring API Permissions

1. Go to **API permissions** > **Add a permission**
2. Choose **Microsoft Graph** or **APIs my organization uses**
3. Select **Application permissions** for service-to-service scenarios
4. Add required permissions
5. **Grant admin consent** for the organization

### Custom Scopes for MCP Server

Define in **Expose an API**:
```json
{
  "scopes": [
    {
      "adminConsentDescription": "Allow reading MCP server data",
      "adminConsentDisplayName": "Read MCP data",
      "id": "mcp.read",
      "isEnabled": true,
      "type": "Admin",
      "userConsentDescription": "Allow reading MCP server data",
      "userConsentDisplayName": "Read MCP data",
      "value": "mcp.read"
    }
  ]
}
```

## MCP Server Configuration

### Environment Variables

Update your MCP server configuration:

```bash
# Azure AD Configuration
export AZURE_TENANT_ID="your-tenant-id"
export AZURE_CLIENT_ID="your-client-id"
export AZURE_CLIENT_SECRET="your-client-secret"

# MCP Server Configuration  
export MCP_SERVER_PORT="8443"
export MCP_USE_TLS="true"
export OAUTH_ISSUER="https://login.microsoftonline.com/${AZURE_TENANT_ID}/v2.0"
export OAUTH_AUDIENCE="api://your-app-id"
```

### Token Validation Enhancement

Modify the MCP server to validate Azure AD tokens:

```go
import (
    "crypto/rsa"
    "encoding/json"
    "fmt"
    "net/http"
    "github.com/golang-jwt/jwt/v5"
)

// Azure AD public key endpoint
const azureJWKSEndpoint = "https://login.microsoftonline.com/{tenant}/discovery/v2.0/keys"

// Enhanced token validation for Azure AD
func validateAzureToken(tokenString string) (*jwt.Token, error) {
    // Get Azure AD public keys
    resp, err := http.Get(azureJWKSEndpoint)
    if err != nil {
        return nil, fmt.Errorf("failed to get Azure keys: %w", err)
    }
    defer resp.Body.Close()
    
    // Parse JWT token with Azure validation
    token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
        // Validate signing method
        if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
            return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
        }
        
        // Get public key from Azure JWKS
        return getPublicKeyFromJWKS(token.Header["kid"].(string))
    })
    
    if err != nil {
        return nil, fmt.Errorf("invalid token: %w", err)
    }
    
    // Validate claims
    if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
        // Validate audience
        if claims["aud"] != os.Getenv("OAUTH_AUDIENCE") {
            return nil, fmt.Errorf("invalid audience")
        }
        
        // Validate issuer
        expectedIssuer := fmt.Sprintf("https://login.microsoftonline.com/%s/v2.0", os.Getenv("AZURE_TENANT_ID"))
        if claims["iss"] != expectedIssuer {
            return nil, fmt.Errorf("invalid issuer")
        }
    }
    
    return token, nil
}
```

### Updated Authentication Middleware

```go
func azureAuthenticationMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        // Skip authentication for OAuth endpoints
        if r.URL.Path == "/.well-known/oauth-authorization-server" || r.URL.Path == "/oauth/token" {
            next.ServeHTTP(w, r)
            return
        }

        authHeader := r.Header.Get("Authorization")
        if authHeader == "" {
            http.Error(w, "Missing Authorization header", http.StatusUnauthorized)
            return
        }

        tokenString := strings.TrimPrefix(authHeader, "Bearer ")
        token, err := validateAzureToken(tokenString)
        if err != nil {
            http.Error(w, fmt.Sprintf("Invalid token: %v", err), http.StatusUnauthorized)
            return
        }

        // Add token claims to request context
        ctx := context.WithValue(r.Context(), "azure_token", token)
        next.ServeHTTP(w, r.WithContext(ctx))
    })
}
```

## Multi-Tenant Considerations

### Single-Tenant Configuration
- Simplest setup for organization-internal use
- Fixed tenant ID in all endpoints
- Easier permission management

### Multi-Tenant Configuration
- Supports users from multiple Azure AD tenants
- Use `common` or `organizations` in token endpoints:
  ```
  https://login.microsoftonline.com/common/oauth2/v2.0/token
  ```
- Additional validation required for tenant isolation
- Consider data residency and compliance requirements

### Cross-Tenant Access Settings

Configure in Azure AD:
1. **External Identities** > **Cross-tenant access settings**
2. Configure **Outbound access** and **Inbound access**
3. Define which external tenants can access your MCP server

## Deployment Options

### 1. Azure App Service

#### Deployment Steps
```bash
# Create App Service Plan
az appservice plan create --name mcp-server-plan --resource-group myRG --sku B1

# Create Web App
az webapp create --resource-group myRG --plan mcp-server-plan --name mcp-server-auth

# Configure environment variables
az webapp config appsettings set --resource-group myRG --name mcp-server-auth --settings \
  AZURE_TENANT_ID="your-tenant-id" \
  AZURE_CLIENT_ID="your-client-id" \
  AZURE_CLIENT_SECRET="@Microsoft.KeyVault(SecretUri=https://vault.vault.azure.net/secrets/clientsecret/)"

# Deploy application
az webapp deploy --resource-group myRG --name mcp-server-auth --src-path ./mcp-server-auth.zip
```

#### App Service Configuration
```json
{
  "name": "MCP Server OAuth 2.1",
  "location": "East US",
  "properties": {
    "serverFarmId": "/subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.Web/serverfarms/mcp-plan",
    "httpsOnly": true,
    "clientAffinityEnabled": false,
    "siteConfig": {
      "alwaysOn": true,
      "http20Enabled": true,
      "minTlsVersion": "1.2",
      "appSettings": [
        {
          "name": "MCP_SERVER_PORT",
          "value": "80"
        },
        {
          "name": "MCP_USE_TLS",
          "value": "false"
        }
      ]
    }
  }
}
```

### 2. Azure Container Instances (ACI)

#### Container Deployment
```yaml
apiVersion: 2019-12-01
location: eastus
name: mcp-server-container
properties:
  containers:
  - name: mcp-server-auth
    properties:
      image: mcp-server:latest
      resources:
        requests:
          cpu: 1
          memoryInGB: 1.5
      ports:
      - port: 8443
        protocol: TCP
      environmentVariables:
      - name: AZURE_TENANT_ID
        secureValue: your-tenant-id
      - name: AZURE_CLIENT_ID
        secureValue: your-client-id
      - name: AZURE_CLIENT_SECRET
        secureValue: your-client-secret
  osType: Linux
  restartPolicy: Always
  ipAddress:
    type: Public
    ports:
    - protocol: TCP
      port: 8443
```

Deploy:
```bash
az container create --resource-group myRG --file mcp-container.yaml
```

### 3. Azure Kubernetes Service (AKS)

#### Kubernetes Deployment
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: mcp-server-deployment
spec:
  replicas: 3
  selector:
    matchLabels:
      app: mcp-server
  template:
    metadata:
      labels:
        app: mcp-server
    spec:
      containers:
      - name: mcp-server
        image: mcp-server:latest
        ports:
        - containerPort: 8443
        env:
        - name: AZURE_TENANT_ID
          valueFrom:
            secretKeyRef:
              name: azure-credentials
              key: tenant-id
        - name: AZURE_CLIENT_ID
          valueFrom:
            secretKeyRef:
              name: azure-credentials
              key: client-id
        - name: AZURE_CLIENT_SECRET
          valueFrom:
            secretKeyRef:
              name: azure-credentials
              key: client-secret
        resources:
          requests:
            memory: "256Mi"
            cpu: "200m"
          limits:
            memory: "512Mi"
            cpu: "500m"
---
apiVersion: v1
kind: Service
metadata:
  name: mcp-server-service
spec:
  selector:
    app: mcp-server
  ports:
    - protocol: TCP
      port: 8443
      targetPort: 8443
  type: LoadBalancer
```

Create secret:
```bash
kubectl create secret generic azure-credentials \
  --from-literal=tenant-id="your-tenant-id" \
  --from-literal=client-id="your-client-id" \
  --from-literal=client-secret="your-client-secret"
```

## Monitoring and Logging

### Azure Application Insights Integration

#### 1. Create Application Insights Resource
```bash
az monitor app-insights component create \
  --app mcp-server-insights \
  --location eastus \
  --resource-group myRG
```

#### 2. Configure Application Insights in Go
```go
import (
    "github.com/microsoft/ApplicationInsights-Go/appinsights"
)

func initApplicationInsights() appinsights.TelemetryClient {
    client := appinsights.NewTelemetryClient(os.Getenv("APPINSIGHTS_INSTRUMENTATIONKEY"))
    
    // Configure telemetry
    client.Context().Tags.Cloud().SetRole("mcp-server")
    client.Context().Tags.Cloud().SetRoleInstance("mcp-server-instance")
    
    return client
}

// Enhanced authentication middleware with telemetry
func azureAuthWithTelemetry(client appinsights.TelemetryClient) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            startTime := time.Now()
            
            // Create request telemetry
            request := appinsights.NewRequestTelemetry(r.Method, r.URL.String(), time.Since(startTime), "200")
            request.MarkTime(startTime)
            
            defer func() {
                request.Duration = time.Since(startTime)
                client.Track(request)
            }()
            
            // Authentication logic here...
            
            next.ServeHTTP(w, r)
        })
    }
}
```

### Azure Monitor Integration

#### Log Analytics Workspace
```bash
az monitor log-analytics workspace create \
  --resource-group myRG \
  --workspace-name mcp-server-logs
```

#### Custom Metrics and Logs
```go
// Custom telemetry events
func trackAuthenticationEvent(client appinsights.TelemetryClient, success bool, userID string) {
    event := appinsights.NewEventTelemetry("authentication")
    event.Properties["success"] = fmt.Sprintf("%v", success)
    event.Properties["user_id"] = userID
    event.Properties["timestamp"] = time.Now().Format(time.RFC3339)
    
    client.Track(event)
}

// Performance counters
func trackPerformanceMetrics(client appinsights.TelemetryClient) {
    // Track request duration
    metric := appinsights.NewMetricTelemetry("request_duration", 150.0)
    metric.Properties["endpoint"] = "/mcp"
    client.Track(metric)
    
    // Track active connections
    metric = appinsights.NewMetricTelemetry("active_connections", 25.0)
    client.Track(metric)
}
```

### KQL Queries for Monitoring

#### Authentication Success Rate
```kusto
customEvents
| where name == "authentication"
| summarize 
    Total = count(),
    Successful = countif(tostring(customDimensions.success) == "true"),
    Failed = countif(tostring(customDimensions.success) == "false")
    by bin(timestamp, 1h)
| extend SuccessRate = (Successful * 100.0) / Total
| project timestamp, SuccessRate, Total, Successful, Failed
```

#### Performance Metrics
```kusto
customMetrics
| where name == "request_duration"
| summarize 
    avg(value),
    percentile(value, 50),
    percentile(value, 95),
    percentile(value, 99)
    by bin(timestamp, 5m)
```

#### Error Analysis
```kusto
exceptions
| where cloud_RoleName == "mcp-server"
| summarize count() by problemId, outerMessage
| order by count_ desc
```

## Security Best Practices

### 1. Token Security

#### Token Rotation
- Implement automatic token refresh
- Use short-lived access tokens (1 hour)
- Store refresh tokens securely

#### Token Storage
- Use Azure Key Vault for sensitive data
- Never log tokens or secrets
- Implement token encryption at rest

```go
import (
    "github.com/Azure/azure-sdk-for-go/services/keyvault/v7.0/keyvault"
)

func getClientSecret() (string, error) {
    vaultClient := keyvault.New()
    
    // Configure authentication for Key Vault
    authorizer, err := auth.NewAuthorizerFromEnvironment()
    if err != nil {
        return "", err
    }
    vaultClient.Authorizer = authorizer
    
    // Retrieve secret
    secret, err := vaultClient.GetSecret(context.Background(), 
        "https://your-vault.vault.azure.net/", 
        "client-secret", 
        "")
    if err != nil {
        return "", err
    }
    
    return *secret.Value, nil
}
```

### 2. Network Security

#### Network Restrictions
- Configure IP restrictions in Azure AD
- Use Private Endpoints for internal access
- Implement Web Application Firewall (WAF)

#### TLS Configuration
```go
func configureTLS() *tls.Config {
    return &tls.Config{
        MinVersion: tls.VersionTLS12,
        CipherSuites: []uint16{
            tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
            tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
            tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        },
        PreferServerCipherSuites: true,
        CurvePreferences: []tls.CurveID{
            tls.CurveP521,
            tls.CurveP384,
            tls.CurveP256,
        },
    }
}
```

### 3. Access Control

#### Conditional Access Policies
Configure in Azure AD:
1. **Security** > **Conditional Access** > **New policy**
2. Set conditions:
   - **Users and groups**: Specific service accounts
   - **Cloud apps**: Your MCP server application
   - **Conditions**: Location, device state, risk levels
3. Configure access controls:
   - **Grant**: Require MFA for elevated operations
   - **Session**: Sign-in frequency controls

#### Role-Based Access Control (RBAC)
```go
// Define roles and permissions
type MCPRole string

const (
    MCPRoleRead   MCPRole = "mcp.read"
    MCPRoleWrite  MCPRole = "mcp.write" 
    MCPRoleAdmin  MCPRole = "mcp.admin"
)

func validatePermissions(token *jwt.Token, requiredRole MCPRole) error {
    claims, ok := token.Claims.(jwt.MapClaims)
    if !ok {
        return fmt.Errorf("invalid token claims")
    }
    
    // Check for required scope in token
    scopes, ok := claims["scp"].(string)
    if !ok {
        return fmt.Errorf("missing scopes in token")
    }
    
    if !strings.Contains(scopes, string(requiredRole)) {
        return fmt.Errorf("insufficient permissions: required %s", requiredRole)
    }
    
    return nil
}
```

## Troubleshooting

### Common Issues

#### 1. Token Validation Errors

**Error**: `AADSTS70011: The provided value for the input parameter 'scope' is not valid`

**Solution**: Ensure scopes are properly formatted:
```
# Correct
scope=api://your-app-id/.default

# Incorrect  
scope=your-app-id
```

#### 2. Certificate Authentication Issues

**Error**: `AADSTS700027: Client assertion contains an invalid signature`

**Solution**: Verify certificate configuration:
```bash
# Check certificate details
openssl x509 -in certificate.pem -text -noout

# Verify certificate matches uploaded cert in Azure
openssl x509 -in certificate.pem -fingerprint -noout
```

#### 3. Multi-tenant Access Issues

**Error**: `AADSTS50020: User account from identity provider does not exist in tenant`

**Solution**: Configure cross-tenant access settings or use proper tenant endpoint.

### Debugging Steps

#### 1. Enable Debug Logging
```go
import "log"

func debugTokenValidation(tokenString string) {
    // Parse without validation first
    token, _ := jwt.Parse(tokenString, nil)
    
    if claims, ok := token.Claims.(jwt.MapClaims); ok {
        log.Printf("Token claims: %+v", claims)
        log.Printf("Issuer: %v", claims["iss"])
        log.Printf("Audience: %v", claims["aud"])
        log.Printf("Subject: %v", claims["sub"])
        log.Printf("Scopes: %v", claims["scp"])
    }
}
```

#### 2. Test Token Manually
```bash
# Get token
TOKEN=$(curl -s -X POST https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token \
  -d "grant_type=client_credentials&client_id={id}&client_secret={secret}&scope=api://your-app/.default" \
  | jq -r '.access_token')

# Decode token for inspection  
echo $TOKEN | cut -d. -f2 | base64 -D | jq .

# Test MCP server with token
curl -H "Authorization: Bearer $TOKEN" \
  -X POST http://localhost:8443/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc": "2.0", "method": "tools/list", "id": 1}'
```

#### 3. Monitor Azure AD Sign-in Logs
1. Go to **Azure AD** > **Monitoring** > **Sign-in logs**
2. Filter by your application
3. Look for authentication failures and error details

### Support Resources

- **Azure AD Documentation**: https://docs.microsoft.com/en-us/azure/active-directory/
- **OAuth 2.1 Specification**: https://tools.ietf.org/html/draft-ietf-oauth-v2-1
- **Microsoft Graph API**: https://docs.microsoft.com/en-us/graph/
- **Azure SDK for Go**: https://github.com/Azure/azure-sdk-for-go

## Conclusion

This integration guide provides a comprehensive approach to connecting your OAuth 2.1 authenticated MCP server with Azure Enterprise Applications. The combination provides enterprise-grade security, monitoring, and scalability for production deployments.

Key benefits of Azure integration:
- ✅ Enterprise-grade authentication and authorization
- ✅ Centralized identity management
- ✅ Comprehensive monitoring and logging
- ✅ Scalable deployment options
- ✅ Compliance with enterprise security policies
- ✅ Integration with existing Azure infrastructure

For production deployments, ensure you follow security best practices, implement proper monitoring, and regularly review access controls and permissions.