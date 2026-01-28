//! Model Context Protocol (MCP) interface for LLM integration
//!
//! Exposes Vultrino capabilities as MCP tools that LLMs can discover and use.
//! This allows AI agents to:
//! - List available credentials (without seeing secrets)
//! - Make authenticated HTTP requests
//! - Understand what actions are available
//!
//! The MCP server communicates over stdio or Unix sockets.

mod server;
mod types;

pub use server::McpServer;
pub use types::*;
