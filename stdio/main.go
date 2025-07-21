// Package main implements a basic MCP server using stdio transport.
//
// This is Phase 1 of a three-phase educational MCP server implementation series:
// - Phase 1 (stdio): Basic MCP server with stdio transport (this implementation)
// - Phase 2 (network): HTTP-based MCP server without authentication
// - Phase 3 (auth): OAuth 2.1 authenticated MCP server with comprehensive security
//
// ARCHITECTURE OVERVIEW:
// This server demonstrates the fundamental concepts of MCP (Model Context Protocol):
//
// 1. MCP Protocol Implementation:
//    - JSON-RPC 2.0 over stdio transport
//    - Tool registration and discovery
//    - Structured response formatting
//    - Error handling within MCP specification
//
// 2. Transport Layer:
//    - Standard input/output (stdio) communication
//    - Direct integration with MCP Go SDK transport layer
//    - Process-based isolation and security
//    - Suitable for local development and CLI integration
//
// 3. Tool Implementation:
//    - File system operations (read files, list directories)
//    - System information retrieval (OS, architecture, versions)
//    - Input validation and error handling
//    - Structured content responses
//
// LEARNING OBJECTIVES:
// - Understanding MCP protocol basics
// - JSON-RPC 2.0 communication patterns
// - Tool registration with SDK
// - Error handling and validation
// - Structured response formatting
//
// TOOLS IMPLEMENTED:
// - read_file: Read file contents from filesystem
// - list_directory: List directory contents
// - get_system_info: Get system information (OS, arch, Go version, working dir)
//
// USAGE EXAMPLE:
//   # Direct stdio communication
//   echo '{"jsonrpc":"2.0","method":"tools/list","id":1}' | mcp-demo-server-stdio
//   
//   # Claude Code integration (add to mcp.json):
//   {
//     "mcpServers": {
//       "file-system": {
//         "command": "mcp-demo-server-stdio",
//         "transport": "stdio"
//       }
//     }
//   }
//
// SECURITY MODEL:
// - Process-level isolation (no network exposure)
// - File system access limited to process permissions
// - Input validation prevents basic injection attacks
// - No authentication required (single-user, local process)
//
// This implementation serves as the foundation for understanding MCP concepts
// before progressing to network transport and authentication in subsequent phases.
package main

import (
	"context"
	"fmt"
	"log"
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

func main() {
	// Initialize MCP server with descriptive metadata
	serverImplementation := &mcp.Implementation{
		Name:    "mcp-demo-server",
		Version: "1.0.0",
		Title:   "A simple MCP server implementation in Go for educational purposes",
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
	
	// Log server startup
	log.Printf("Starting MCP Demo Server (v%s)", serverImplementation.Version)
	log.Printf("Server Name: %s", serverImplementation.Name)
	log.Printf("Title: %s", serverImplementation.Title)
	log.Printf("Tools registered: read_file, list_directory, get_system_info")
	
	// Run the server with stdio transport
	// This allows the server to communicate via standard input/output
	if err := server.Run(context.Background(), mcp.NewStdioTransport()); err != nil {
		log.Fatalf("Server failed to run: %v", err)
	}
}