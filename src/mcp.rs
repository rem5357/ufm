//! MCP (Model Context Protocol) Server Implementation
//!
//! A simple implementation of the MCP protocol over stdio using JSON-RPC 2.0.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::io::{self, BufRead, Write};

/// JSON-RPC 2.0 Request
#[derive(Debug, Clone, Deserialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    pub method: String,
    #[serde(default)]
    pub params: Option<Value>,
    pub id: Option<Value>,
}

/// JSON-RPC 2.0 Response
#[derive(Debug, Clone, Serialize)]
pub struct JsonRpcResponse {
    pub jsonrpc: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
    pub id: Value,
}

/// JSON-RPC 2.0 Error
#[derive(Debug, Clone, Serialize)]
pub struct JsonRpcError {
    pub code: i32,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

impl JsonRpcResponse {
    pub fn success(id: Value, result: Value) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            result: Some(result),
            error: None,
            id,
        }
    }

    pub fn error(id: Value, code: i32, message: &str) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            result: None,
            error: Some(JsonRpcError {
                code,
                message: message.to_string(),
                data: None,
            }),
            id,
        }
    }
}

/// MCP Tool definition
#[derive(Debug, Clone, Serialize)]
pub struct Tool {
    pub name: String,
    pub description: String,
    #[serde(rename = "inputSchema")]
    pub input_schema: Value,
}

impl Tool {
    pub fn new(name: &str, description: &str, input_schema: Value) -> Self {
        Self {
            name: name.to_string(),
            description: description.to_string(),
            input_schema,
        }
    }
}

/// Server capabilities
#[derive(Debug, Clone, Serialize, Default)]
pub struct ServerCapabilities {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tools: Option<ToolsCapability>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ToolsCapability {
    #[serde(rename = "listChanged", skip_serializing_if = "Option::is_none")]
    pub list_changed: Option<bool>,
}

/// Server implementation info
#[derive(Debug, Clone, Serialize)]
pub struct ServerInfo {
    pub name: String,
    pub version: String,
}

/// Tool call result content
#[derive(Debug, Clone, Serialize)]
pub struct TextContent {
    #[serde(rename = "type")]
    pub type_: String,
    pub text: String,
}

impl TextContent {
    pub fn new(text: String) -> Self {
        Self {
            type_: "text".to_string(),
            text,
        }
    }
}

/// Tool call result
#[derive(Debug, Clone, Serialize)]
pub struct CallToolResult {
    pub content: Vec<TextContent>,
    #[serde(rename = "isError", skip_serializing_if = "Option::is_none")]
    pub is_error: Option<bool>,
}

impl CallToolResult {
    pub fn success(text: String) -> Self {
        Self {
            content: vec![TextContent::new(text)],
            is_error: Some(false),
        }
    }

    pub fn error(text: String) -> Self {
        Self {
            content: vec![TextContent::new(text)],
            is_error: Some(true),
        }
    }
}

/// MCP Server trait
#[async_trait::async_trait]
pub trait McpServerHandler: Send + Sync {
    /// Get server info
    fn server_info(&self) -> ServerInfo;

    /// Get server capabilities
    fn capabilities(&self) -> ServerCapabilities;

    /// Get instructions for the client
    fn instructions(&self) -> Option<String> {
        None
    }

    /// List available tools
    fn list_tools(&self) -> Vec<Tool>;

    /// Call a tool
    async fn call_tool(&self, name: &str, arguments: Value) -> CallToolResult;
}

/// Run the MCP server on stdio
pub async fn run_stdio_server<H: McpServerHandler + 'static>(handler: H) -> io::Result<()> {
    let stdin = io::stdin();
    let stdout = io::stdout();

    let handler = std::sync::Arc::new(handler);

    for line in stdin.lock().lines() {
        let line = line?;
        if line.is_empty() {
            continue;
        }

        let request: JsonRpcRequest = match serde_json::from_str(&line) {
            Ok(r) => r,
            Err(e) => {
                let response = JsonRpcResponse::error(
                    Value::Null,
                    -32700,
                    &format!("Parse error: {}", e),
                );
                writeln!(stdout.lock(), "{}", serde_json::to_string(&response)?)?;
                stdout.lock().flush()?;
                continue;
            }
        };

        let id = request.id.clone().unwrap_or(Value::Null);

        // Handle notifications (no id) - just ignore for now
        if request.id.is_none() {
            continue;
        }

        let response = match request.method.as_str() {
            "initialize" => {
                let result = json!({
                    "protocolVersion": "2024-11-05",
                    "capabilities": handler.capabilities(),
                    "serverInfo": handler.server_info(),
                    "instructions": handler.instructions()
                });
                JsonRpcResponse::success(id, result)
            }
            "tools/list" => {
                let result = json!({
                    "tools": handler.list_tools()
                });
                JsonRpcResponse::success(id, result)
            }
            "tools/call" => {
                let params = request.params.unwrap_or(json!({}));
                let name = params["name"].as_str().unwrap_or("");
                let arguments = params["arguments"].clone();

                let result = handler.call_tool(name, arguments).await;
                JsonRpcResponse::success(id, serde_json::to_value(result).unwrap_or(json!({})))
            }
            "ping" => JsonRpcResponse::success(id, json!({})),
            _ => JsonRpcResponse::error(id, -32601, &format!("Method not found: {}", request.method)),
        };

        writeln!(stdout.lock(), "{}", serde_json::to_string(&response)?)?;
        stdout.lock().flush()?;
    }

    Ok(())
}
