//! Request routing and credential resolution
//!
//! Handles:
//! - Resolving credential aliases to actual credentials
//! - URL pattern matching for auto-detection
//! - Route-based credential selection

mod matcher;
mod resolver;

pub use matcher::UrlMatcher;
pub use resolver::CredentialResolver;
