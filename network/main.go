// Package main implements a network-based MCP server using HTTP transport.
//
// This is Phase 2 of a three-phase educational MCP server implementation series:
// - Phase 1 (stdio): Basic MCP server with stdio transport
// - Phase 2 (network): HTTP-based MCP server without authentication (this implementation)
// - Phase 3 (auth): OAuth 2.1 authenticated MCP server with comprehensive security
//
// ARCHITECTURE OVERVIEW:
// This server demonstrates network-based MCP communication patterns and HTTP integration:
//
// 1. Network Transport Implementation:
//    - HTTP server with JSON-RPC 2.0 over HTTP POST
//    - Custom HTTP-to-MCP protocol bridging
//    - CORS support for browser-based MCP clients
//    - Environment-based configuration (port selection)
//
// 2. HTTP Server Architecture:
//    - Go HTTP server with multiple endpoint support
//    - JSON-RPC message parsing and validation
//    - Proper HTTP status code handling
//    - CORS headers for cross-origin requests
//
// 3. MCP Protocol Bridge:
//    - Manual JSON-RPC 2.0 request/response handling
//    - Tool logic duplication for educational purposes (shows HTTP implementation)
//    - Custom error handling and response formatting
//    - Multiple endpoint support (/mcp and / root)
//
// LEARNING OBJECTIVES:
// - HTTP server setup and configuration in Go
// - JSON-RPC over HTTP implementation patterns
// - CORS configuration for web clients
// - Environment variable configuration
// - Concurrent request handling
// - HTTP status code and error response patterns
//
// TOOLS IMPLEMENTED:
// - read_file: Read file contents from filesystem
// - list_directory: List directory contents  
// - get_system_info: Get system information (OS, arch, Go version, working dir)
//
// ENDPOINTS:
// - POST /mcp: Primary MCP protocol endpoint
// - POST /: Root endpoint (alias for /mcp)
// - OPTIONS /*: CORS preflight support
//
// USAGE EXAMPLES:
//   # Start server on default port
//   mcp-demo-server-network
//   
//   # Start on custom port
//   MCP_SERVER_PORT=9090 mcp-demo-server-network
//   
//   # Test with curl
//   curl -X POST http://localhost:8080/mcp \
//     -H "Content-Type: application/json" \
//     -d '{"jsonrpc":"2.0","method":"tools/list","id":1}'
//   
//   # Claude Code integration (add to mcp.json):
//   {
//     "mcpServers": {
//       "file-system-network": {
//         "url": "http://localhost:8080", 
//         "transport": "http"
//       }
//     }
//   }
//
// SECURITY MODEL:
// - No authentication (educational/development only)
// - Network exposure requires firewall configuration
// - Input validation and basic error handling
// - CORS enabled for development convenience
// - File system access limited to server process permissions
//
// ENVIRONMENT CONFIGURATION:
// - MCP_SERVER_PORT: Server port (default: 8080)
//
// This implementation demonstrates the transition from stdio to network transport
// while maintaining the same MCP tool functionality, preparing for the OAuth 2.1
// authentication layer in Phase 3.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"runtime"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/modelcontextprotocol/go-sdk/jsonschema"
)

// FileReadParams represents parameters for reading a file
type FileReadParams struct {
	FilePath string `json:"file_path" jsonschema:"description=Path to the file to read"`
}

// DirectoryListParams represents parameters for listing directory contents
type DirectoryListParams struct {
	DirectoryPath string `json:"directory_path" jsonschema:"description=Path to the directory to list"`
}

// SystemInfoParams represents parameters for getting system information
type SystemInfoParams struct {
	InfoType string `json:"info_type" jsonschema:"description=Type of system info to retrieve (os, arch, go_version, working_dir),enum=os,enum=arch,enum=go_version,enum=working_dir"`
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

// JSONRPCRequest represents a JSON-RPC 2.0 request
type JSONRPCRequest struct {
	JSONRpc string      `json:"jsonrpc"`
	Method  string      `json:"method"`
	Params  interface{} `json:"params,omitempty"`
	ID      interface{} `json:"id"`
}

// JSONRPCResponse represents a JSON-RPC 2.0 response
type JSONRPCResponse struct {
	JSONRpc string      `json:"jsonrpc"`
	Result  interface{} `json:"result,omitempty"`
	Error   interface{} `json:"error,omitempty"`
	ID      interface{} `json:"id"`
}

// createMCPHandler creates an HTTP handler that handles MCP protocol requests
func createMCPHandler(server *mcp.Server) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Set CORS headers for browser compatibility
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		
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
		// Return list of available tools
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
			Result:  map[string]interface{}{"tools": tools},
			ID:      req.ID,
		}
		
	case "tools/call":
		// Handle tool calls
		params, ok := req.Params.(map[string]interface{})
		if !ok {
			return JSONRPCResponse{
				JSONRpc: "2.0",
				Error:   map[string]string{"message": "Invalid parameters for tools/call"},
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
			Error:   map[string]string{"message": "Unknown method: " + req.Method},
			ID:      req.ID,
		}
	}
}

// callTool executes the specified tool with given arguments
func callTool(toolName string, args map[string]interface{}) (interface{}, error) {
	switch toolName {
	case "read_file":
		filePath, ok := args["file_path"].(string)
		if !ok {
			return nil, fmt.Errorf("file_path parameter is required and must be a string")
		}
		
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

func main() {
	// Initialize MCP server with descriptive metadata
	serverImplementation := &mcp.Implementation{
		Name:    "mcp-demo-server-network",
		Version: "2.0.0",
		Title:   "MCP server with HTTP network transport for educational purposes",
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
	
	// Configure server port (default to 8080)
	port := os.Getenv("MCP_SERVER_PORT")
	if port == "" {
		port = "8080"
	}
	
	// Log server startup
	log.Printf("Starting MCP Demo Server (v%s) - Network Transport", serverImplementation.Version)
	log.Printf("Server Name: %s", serverImplementation.Name)
	log.Printf("Title: %s", serverImplementation.Title)
	log.Printf("Tools registered: read_file, list_directory, get_system_info")
	log.Printf("Starting HTTP server on port %s", port)
	
	// Create HTTP-to-MCP bridge handler
	mcpHandler := createMCPHandler(server)
	
	// Create HTTP server with MCP handler
	httpServer := &http.Server{
		Addr:    ":" + port,
		Handler: mcpHandler,
	}
	
	// Start HTTP server
	log.Printf("HTTP server listening on http://localhost:%s", port)
	if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("HTTP server failed to start: %v", err)
	}
}