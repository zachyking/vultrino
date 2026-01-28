//! MCP Server implementation
//!
//! Exposes Vultrino capabilities through the Model Context Protocol.

use super::types::*;
use crate::auth::{AuthManager, AuthResult, Permission};
use crate::plugins::PluginInstaller;
use crate::server::VultrinoServer;
use crate::{CredentialMetadata, ExecuteRequest};
use glob::Pattern;
use serde_json::json;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

/// MCP Server for Vultrino
pub struct McpServer {
    /// Vultrino server instance
    vultrino: Arc<RwLock<VultrinoServer>>,
    /// Whether initialized
    initialized: bool,
    /// Auth manager for validating API keys (required)
    auth_manager: Arc<RwLock<AuthManager>>,
}

impl McpServer {
    /// Create a new MCP server with auth manager (required)
    pub fn new(vultrino: Arc<RwLock<VultrinoServer>>, auth_manager: Arc<RwLock<AuthManager>>) -> Self {
        Self {
            vultrino,
            initialized: false,
            auth_manager,
        }
    }

    /// Validate an API key and return auth result
    async fn validate_api_key(&self, api_key: &str) -> Result<AuthResult, String> {
        let manager = self.auth_manager.read().await;
        let (key, role) = manager
            .validate_key(api_key)
            .map_err(|e| format!("Invalid API key: {}", e))?;

        Ok(AuthResult {
            api_key: key,
            role,
        })
    }

    /// Check permission for a validated auth
    fn check_permission(auth: &AuthResult, permission: Permission) -> Result<(), String> {
        if !auth.has_permission(permission) {
            return Err(format!("Permission denied: requires '{}' permission", permission));
        }
        Ok(())
    }

    /// Check credential access for a validated auth
    fn check_credential_access(auth: &AuthResult, alias: &str) -> Result<(), String> {
        if !auth.can_access_credential(alias) {
            return Err(format!("Access denied to credential: {}", alias));
        }
        Ok(())
    }

    /// Run the MCP server over stdio
    pub async fn run_stdio(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let stdin = tokio::io::stdin();
        let mut stdout = tokio::io::stdout();
        let mut reader = BufReader::new(stdin);
        let mut line = String::new();

        info!("MCP server starting on stdio");

        loop {
            line.clear();
            let bytes_read = reader.read_line(&mut line).await?;

            if bytes_read == 0 {
                // EOF
                break;
            }

            let line = line.trim();
            if line.is_empty() {
                continue;
            }

            debug!(request = %line, "Received MCP request");

            let response = self.handle_message(line).await;

            if let Some(response) = response {
                let response_str = serde_json::to_string(&response)?;
                debug!(response = %response_str, "Sending MCP response");
                stdout.write_all(response_str.as_bytes()).await?;
                stdout.write_all(b"\n").await?;
                stdout.flush().await?;
            }
        }

        info!("MCP server shutting down");
        Ok(())
    }

    /// Handle a single JSON-RPC message
    async fn handle_message(&mut self, message: &str) -> Option<JsonRpcResponse> {
        // Parse JSON-RPC request
        let request: JsonRpcRequest = match serde_json::from_str(message) {
            Ok(req) => req,
            Err(e) => {
                error!(error = %e, "Failed to parse JSON-RPC request");
                return Some(JsonRpcResponse::error(
                    JsonRpcId::Null,
                    PARSE_ERROR,
                    format!("Parse error: {}", e),
                ));
            }
        };

        // Route to handler
        let result = match request.method.as_str() {
            "initialize" => self.handle_initialize(&request).await,
            "initialized" => {
                // Notification, no response
                self.initialized = true;
                info!("MCP client initialized");
                return None;
            }
            "tools/list" => self.handle_tools_list(&request).await,
            "tools/call" => self.handle_tools_call(&request).await,
            "resources/list" => self.handle_resources_list(&request).await,
            "ping" => Ok(json!({})),
            method => {
                warn!(method = %method, "Unknown MCP method");
                Err((METHOD_NOT_FOUND, format!("Method not found: {}", method)))
            }
        };

        match result {
            Ok(value) => Some(JsonRpcResponse::success(request.id, value)),
            Err((code, message)) => Some(JsonRpcResponse::error(request.id, code, message)),
        }
    }

    /// Handle initialize request
    async fn handle_initialize(
        &mut self,
        _request: &JsonRpcRequest,
    ) -> Result<serde_json::Value, (i32, String)> {
        let result = InitializeResult {
            protocol_version: "2024-11-05".to_string(),
            capabilities: ServerCapabilities {
                tools: Some(ToolsCapability {
                    list_changed: Some(false),
                }),
                resources: Some(ResourcesCapability {
                    subscribe: Some(false),
                    list_changed: Some(false),
                }),
                prompts: None,
            },
            server_info: ServerInfo {
                name: "vultrino".to_string(),
                version: env!("CARGO_PKG_VERSION").to_string(),
            },
            instructions: Some(
                "Vultrino is a credential proxy for AI agents. Use the available tools to:\n\
                 - List available credentials (without seeing secrets)\n\
                 - Make authenticated HTTP requests to APIs\n\
                 - Get information about specific credentials\n\n\
                 The credentials themselves are never exposed - only their aliases and metadata."
                    .to_string(),
            ),
        };

        serde_json::to_value(result).map_err(|e| (INTERNAL_ERROR, e.to_string()))
    }

    /// Handle tools/list request
    async fn handle_tools_list(
        &self,
        _request: &JsonRpcRequest,
    ) -> Result<serde_json::Value, (i32, String)> {
        let mut tools = vec![
            Tool {
                name: "list_credentials".to_string(),
                description: "List available credential aliases. Returns metadata about stored \
                             credentials without exposing the actual secrets. Use this to discover \
                             what credentials are available for making authenticated requests."
                    .to_string(),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "api_key": {
                            "type": "string",
                            "description": "Your Vultrino API key (starts with 'vk_') for authentication"
                        },
                        "pattern": {
                            "type": "string",
                            "description": "Optional glob pattern to filter credentials (e.g., 'github-*')"
                        }
                    },
                    "required": ["api_key"]
                }),
            },
            Tool {
                name: "http_request".to_string(),
                description: "Make an authenticated HTTP request using stored credentials. \
                             Vultrino will inject the appropriate authentication headers \
                             without exposing the credential values."
                    .to_string(),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "api_key": {
                            "type": "string",
                            "description": "Your Vultrino API key (starts with 'vk_') for authentication"
                        },
                        "credential": {
                            "type": "string",
                            "description": "The credential alias to use for the request"
                        },
                        "method": {
                            "type": "string",
                            "description": "HTTP method (GET, POST, PUT, DELETE, PATCH, etc.)",
                            "enum": ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]
                        },
                        "url": {
                            "type": "string",
                            "description": "The target URL for the request"
                        },
                        "headers": {
                            "type": "object",
                            "description": "Additional HTTP headers to include",
                            "additionalProperties": { "type": "string" }
                        },
                        "body": {
                            "description": "Request body (for POST, PUT, PATCH requests)"
                        },
                        "query": {
                            "type": "object",
                            "description": "Query parameters to append to the URL",
                            "additionalProperties": { "type": "string" }
                        }
                    },
                    "required": ["api_key", "credential", "method", "url"]
                }),
            },
            Tool {
                name: "get_credential_info".to_string(),
                description: "Get detailed information about a specific credential, including \
                             its type and metadata. Does not expose the actual secret values."
                    .to_string(),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "api_key": {
                            "type": "string",
                            "description": "Your Vultrino API key (starts with 'vk_') for authentication"
                        },
                        "credential": {
                            "type": "string",
                            "description": "The credential alias or ID"
                        }
                    },
                    "required": ["api_key", "credential"]
                }),
            },
        ];

        // Add tools from installed plugins
        if let Ok(plugin_tools) = self.get_plugin_tools().await {
            tools.extend(plugin_tools);
        }

        let result = ToolsListResult { tools };
        serde_json::to_value(result).map_err(|e| (INTERNAL_ERROR, e.to_string()))
    }

    /// Get tools from installed plugins
    async fn get_plugin_tools(&self) -> Result<Vec<Tool>, Box<dyn std::error::Error + Send + Sync>> {
        let installer = PluginInstaller::default();
        let installed = installer.list().await?;

        let mut tools = Vec::new();

        for info in installed {
            if !info.enabled {
                continue;
            }

            for mcp_tool in &info.manifest.mcp_tools {
                // Find the corresponding action to generate schema
                let action = info
                    .manifest
                    .actions
                    .iter()
                    .find(|a| a.name == mcp_tool.action);

                let mut input_schema = if let Some(action) = action {
                    mcp_tool.generate_input_schema(action)
                } else {
                    // Default schema with just credential
                    json!({
                        "type": "object",
                        "properties": {
                            "credential": {
                                "type": "string",
                                "description": "Credential alias to use"
                            }
                        },
                        "required": ["credential"]
                    })
                };

                // Add api_key to all plugin tools
                if let Some(props) = input_schema.get_mut("properties") {
                    props["api_key"] = json!({
                        "type": "string",
                        "description": "Your Vultrino API key (starts with 'vk_') for authentication"
                    });
                }
                if let Some(required) = input_schema.get_mut("required") {
                    if let Some(arr) = required.as_array_mut() {
                        arr.insert(0, json!("api_key"));
                    }
                }

                let tool_name = format!("{}_{}", info.manifest.plugin.name.replace('-', "_"), mcp_tool.name);
                let description = mcp_tool
                    .description
                    .clone()
                    .unwrap_or_else(|| format!("{} from {} plugin", mcp_tool.action, info.manifest.plugin.name));

                tools.push(Tool {
                    name: tool_name,
                    description,
                    input_schema,
                });
            }
        }

        Ok(tools)
    }

    /// Handle tools/call request
    async fn handle_tools_call(
        &self,
        request: &JsonRpcRequest,
    ) -> Result<serde_json::Value, (i32, String)> {
        let params: ToolCallParams = request
            .params
            .as_ref()
            .and_then(|p| serde_json::from_value(p.clone()).ok())
            .ok_or_else(|| (INVALID_PARAMS, "Missing or invalid params".to_string()))?;

        let result = match params.name.as_str() {
            "list_credentials" => self.tool_list_credentials(params.arguments).await,
            "http_request" => self.tool_http_request(params.arguments).await,
            "get_credential_info" => self.tool_get_credential_info(params.arguments).await,
            tool => {
                // Check if it's a plugin tool (format: plugin_name_tool_name)
                if let Some(result) = self.try_plugin_tool(tool, params.arguments).await {
                    result
                } else {
                    return Err((INVALID_PARAMS, format!("Unknown tool: {}", tool)));
                }
            }
        };

        match result {
            Ok(content) => {
                let result = ToolCallResult {
                    content,
                    is_error: None,
                };
                serde_json::to_value(result).map_err(|e| (INTERNAL_ERROR, e.to_string()))
            }
            Err(e) => {
                let result = ToolCallResult {
                    content: vec![ToolContent::Text { text: e }],
                    is_error: Some(true),
                };
                serde_json::to_value(result).map_err(|e| (INTERNAL_ERROR, e.to_string()))
            }
        }
    }

    /// Try to execute a plugin tool
    async fn try_plugin_tool(
        &self,
        tool_name: &str,
        args: serde_json::Value,
    ) -> Option<Result<Vec<ToolContent>, String>> {
        // Extract and validate API key
        let api_key = match args.get("api_key").and_then(|v| v.as_str()) {
            Some(k) => k,
            None => return Some(Err("Missing 'api_key' argument".to_string())),
        };

        let auth = match self.validate_api_key(api_key).await {
            Ok(a) => a,
            Err(e) => return Some(Err(e)),
        };

        // Check execute permission
        if let Err(msg) = Self::check_permission(&auth, Permission::Execute) {
            return Some(Err(msg));
        }

        // Find the plugin and tool
        let installer = PluginInstaller::default();
        let installed = match installer.list().await {
            Ok(list) => list,
            Err(e) => return Some(Err(format!("Failed to list plugins: {}", e))),
        };

        for info in installed {
            if !info.enabled {
                continue;
            }

            let plugin_prefix = format!("{}_", info.manifest.plugin.name.replace('-', "_"));
            if !tool_name.starts_with(&plugin_prefix) {
                continue;
            }

            let short_name = &tool_name[plugin_prefix.len()..];

            // Find the MCP tool definition
            let mcp_tool = match info
                .manifest
                .mcp_tools
                .iter()
                .find(|t| t.name == short_name)
            {
                Some(t) => t,
                None => continue,
            };

            // Get the credential from args
            let credential = match args.get("credential").and_then(|v| v.as_str()) {
                Some(c) => c.to_string(),
                None => return Some(Err("Missing 'credential' argument".to_string())),
            };

            // Check credential access
            if let Err(msg) = Self::check_credential_access(&auth, &credential) {
                return Some(Err(msg));
            }

            // Build execute request for the plugin action
            let request = ExecuteRequest {
                credential: credential.clone(),
                action: format!("{}.{}", info.manifest.plugin.name, mcp_tool.action),
                params: args.clone(),
            };

            // Execute through Vultrino
            let vultrino = self.vultrino.read().await;
            let response = match vultrino
                .execute_with_auth(request, Some(&auth))
                .await
            {
                Ok(r) => r,
                Err(e) => return Some(Err(format!("Plugin execution failed: {}", e))),
            };

            // Format response
            let body_text = String::from_utf8_lossy(&response.body);
            let output = format!(
                "Plugin: {} | Action: {}\nStatus: {}\n\nResult:\n{}",
                info.manifest.plugin.name, mcp_tool.action, response.status, body_text
            );

            return Some(Ok(vec![ToolContent::Text { text: output }]));
        }

        None
    }

    /// Handle resources/list request
    async fn handle_resources_list(
        &self,
        _request: &JsonRpcRequest,
    ) -> Result<serde_json::Value, (i32, String)> {
        // List credentials as resources
        let vultrino = self.vultrino.read().await;
        let credentials = vultrino
            .storage()
            .list()
            .await
            .map_err(|e| (INTERNAL_ERROR, e.to_string()))?;

        let resources: Vec<Resource> = credentials
            .iter()
            .map(|c| Resource {
                uri: format!("vultrino://credential/{}", c.alias),
                name: c.alias.clone(),
                description: c.metadata.get("description").cloned(),
                mime_type: Some("application/json".to_string()),
            })
            .collect();

        let result = ResourcesListResult { resources };
        serde_json::to_value(result).map_err(|e| (INTERNAL_ERROR, e.to_string()))
    }

    /// Tool: list_credentials
    async fn tool_list_credentials(
        &self,
        args: serde_json::Value,
    ) -> Result<Vec<ToolContent>, String> {
        #[derive(serde::Deserialize)]
        struct Args {
            api_key: String,
            pattern: Option<String>,
        }

        let args: Args = serde_json::from_value(args)
            .map_err(|e| format!("Invalid arguments: {}. api_key is required.", e))?;

        // Validate API key and check permission
        let auth = self.validate_api_key(&args.api_key).await?;
        Self::check_permission(&auth, Permission::Read)?;

        let vultrino = self.vultrino.read().await;
        let credentials = vultrino
            .storage()
            .list()
            .await
            .map_err(|e| format!("Failed to list credentials: {}", e))?;

        // Filter by pattern if provided
        let filtered: Vec<&CredentialMetadata> = if let Some(pattern) = &args.pattern {
            let glob = Pattern::new(pattern).map_err(|e| format!("Invalid pattern: {}", e))?;
            credentials.iter().filter(|c| glob.matches(&c.alias)).collect()
        } else {
            credentials.iter().collect()
        };

        // Filter by credential scopes based on role
        let filtered: Vec<&CredentialMetadata> = filtered
            .into_iter()
            .filter(|c| auth.can_access_credential(&c.alias))
            .collect();

        // Format output
        let output = if filtered.is_empty() {
            "No credentials found (or none accessible with your API key).".to_string()
        } else {
            let mut lines = vec!["Available credentials:".to_string()];
            for cred in filtered {
                let desc = cred
                    .metadata
                    .get("description")
                    .map(|d| format!(" - {}", d))
                    .unwrap_or_default();
                lines.push(format!(
                    "- {} (type: {}){}",
                    cred.alias, cred.credential_type, desc
                ));
            }
            lines.join("\n")
        };

        Ok(vec![ToolContent::Text { text: output }])
    }

    /// Tool: http_request
    async fn tool_http_request(
        &self,
        args: serde_json::Value,
    ) -> Result<Vec<ToolContent>, String> {
        let args: HttpRequestArgs =
            serde_json::from_value(args).map_err(|e| format!("Invalid arguments: {}. api_key is required.", e))?;

        // Validate API key and check permissions
        let auth = self.validate_api_key(&args.api_key).await?;
        Self::check_permission(&auth, Permission::Execute)?;
        Self::check_credential_access(&auth, &args.credential)?;

        // Build execute request
        let request = ExecuteRequest {
            credential: args.credential.clone(),
            action: "http.request".to_string(),
            params: json!({
                "method": args.method,
                "url": args.url,
                "headers": args.headers,
                "body": args.body,
                "query": args.query,
            }),
        };

        // Execute through Vultrino with auth context
        let vultrino = self.vultrino.read().await;
        let response = vultrino
            .execute_with_auth(request, Some(&auth))
            .await
            .map_err(|e| format!("Request failed: {}", e))?;

        // Format response
        let body_text = String::from_utf8_lossy(&response.body);

        // Try to pretty-print JSON
        let formatted_body = if let Ok(json) = serde_json::from_str::<serde_json::Value>(&body_text)
        {
            serde_json::to_string_pretty(&json).unwrap_or_else(|_| body_text.to_string())
        } else {
            body_text.to_string()
        };

        let output = format!(
            "HTTP {} {}\nStatus: {}\n\nResponse:\n{}",
            args.method, args.url, response.status, formatted_body
        );

        Ok(vec![ToolContent::Text { text: output }])
    }

    /// Tool: get_credential_info
    async fn tool_get_credential_info(
        &self,
        args: serde_json::Value,
    ) -> Result<Vec<ToolContent>, String> {
        let args: GetCredentialInfoArgs =
            serde_json::from_value(args).map_err(|e| format!("Invalid arguments: {}. api_key is required.", e))?;

        // Validate API key and check permissions
        let auth = self.validate_api_key(&args.api_key).await?;
        Self::check_permission(&auth, Permission::Read)?;
        Self::check_credential_access(&auth, &args.credential)?;

        let vultrino = self.vultrino.read().await;

        // Try to get by alias first, then by ID
        let storage = vultrino.storage();
        let credential = storage
            .get_by_alias(&args.credential)
            .await
            .map_err(|e| format!("Storage error: {}", e))?
            .or(storage
                .get(&args.credential)
                .await
                .map_err(|e| format!("Storage error: {}", e))?);

        match credential {
            Some(cred) => {
                let mut info = vec![
                    format!("Alias: {}", cred.alias),
                    format!("ID: {}", cred.id),
                    format!("Type: {}", cred.credential_type),
                    format!("Created: {}", cred.created_at.format("%Y-%m-%d %H:%M:%S UTC")),
                    format!("Updated: {}", cred.updated_at.format("%Y-%m-%d %H:%M:%S UTC")),
                ];

                if !cred.metadata.is_empty() {
                    info.push("\nMetadata:".to_string());
                    for (key, value) in &cred.metadata {
                        info.push(format!("  {}: {}", key, value));
                    }
                }

                Ok(vec![ToolContent::Text {
                    text: info.join("\n"),
                }])
            }
            None => Err(format!("Credential not found: {}", args.credential)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tool_definitions() {
        // Verify tool schemas are valid JSON
        let tools = vec![
            json!({
                "type": "object",
                "properties": {
                    "pattern": { "type": "string" }
                }
            }),
            json!({
                "type": "object",
                "properties": {
                    "credential": { "type": "string" },
                    "method": { "type": "string" },
                    "url": { "type": "string" }
                },
                "required": ["credential", "method", "url"]
            }),
        ];

        for tool in tools {
            assert!(tool.is_object());
        }
    }
}
