# Multi-stage build for Go OAuth 2.1 MCP Server
# This Dockerfile creates a production-ready container for the educational OAuth 2.1 MCP server

# Build stage: Use official Go image with all build tools
FROM golang:1.24.5-alpine AS builder

# Install build dependencies (git for Go modules, ca-certificates for HTTPS)
RUN apk add --no-cache git ca-certificates tzdata

# Set working directory inside the container
WORKDIR /app

# Copy go mod files first for better Docker layer caching
# This allows Docker to cache the dependency download layer
COPY go.mod go.sum ./

# Download dependencies (this layer will be cached if go.mod/go.sum don't change)
RUN go mod download && go mod verify

# Copy source code
COPY . .

# Build the application
# CGO_ENABLED=0: Build a static binary (no C dependencies)
# GOOS=linux: Target Linux OS
# -ldflags='-w -s': Strip debug information to reduce binary size
# -a: Force rebuild of all packages
# -installsuffix=cgo: Add suffix to package directory to avoid conflicts
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags='-w -s -extldflags "-static"' \
    -a -installsuffix cgo \
    -o mcp-demo-server \
    main.go

# Production stage: Use distroless image for minimal attack surface
FROM gcr.io/distroless/static-debian12:nonroot

# Copy timezone data for proper time handling
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo

# Copy CA certificates for HTTPS client functionality
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Copy the compiled binary from builder stage
COPY --from=builder /app/mcp-demo-server /usr/local/bin/mcp-demo-server

# Use non-root user (defined in distroless base image)
USER nonroot:nonroot

# Document that the container listens on port 8443
# The OAuth 2.1 server runs on this port by default
EXPOSE 8443

# Add labels for better image metadata
LABEL org.opencontainers.image.title="MCP Demo Server - OAuth 2.1"
LABEL org.opencontainers.image.description="Educational OAuth 2.1 authenticated MCP server"
LABEL org.opencontainers.image.source="https://github.com/your-org/mcp-demo"
LABEL org.opencontainers.image.licenses="MIT"

# Set the entrypoint to run our application
# Using exec form to ensure proper signal handling
ENTRYPOINT ["/usr/local/bin/mcp-demo-server"]