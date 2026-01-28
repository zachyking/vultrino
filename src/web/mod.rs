//! Web UI for Vultrino administration
//!
//! Provides a server-side rendered web interface for managing:
//! - Credentials
//! - Roles and API keys
//! - Audit logs and statistics

mod auth;
mod routes;
mod server;
mod templates;

pub use auth::{AdminAuth, WebSession};
pub use server::{WebConfig, WebServer};
