//! Admin authentication for the web UI

use axum::{
    extract::{FromRef, FromRequestParts},
    http::{request::Parts, StatusCode},
    response::{IntoResponse, Redirect, Response},
};
use bcrypt::{hash, verify, DEFAULT_COST};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tower_sessions::Session;

/// Session key for storing authentication state
const SESSION_KEY: &str = "vultrino_admin";

/// Admin authentication manager
#[derive(Debug, Clone)]
pub struct AdminAuth {
    /// Bcrypt hash of the admin password
    password_hash: String,
    /// Admin username
    username: String,
}

impl AdminAuth {
    /// Create a new admin auth from username and password
    pub fn new(username: &str, password: &str) -> Result<Self, bcrypt::BcryptError> {
        let password_hash = hash(password, DEFAULT_COST)?;
        Ok(Self {
            password_hash,
            username: username.to_string(),
        })
    }

    /// Create from existing password hash (loaded from storage)
    pub fn from_hash(username: String, password_hash: String) -> Self {
        Self {
            password_hash,
            username,
        }
    }

    /// Verify a password against the stored hash
    pub fn verify_password(&self, password: &str) -> bool {
        verify(password, &self.password_hash).unwrap_or(false)
    }

    /// Get the username
    pub fn username(&self) -> &str {
        &self.username
    }

    /// Get the password hash (for storage)
    pub fn password_hash(&self) -> &str {
        &self.password_hash
    }

    /// Hash a password (utility function)
    pub fn hash_password(password: &str) -> Result<String, bcrypt::BcryptError> {
        hash(password, DEFAULT_COST)
    }
}

/// Session data stored in the cookie
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebSession {
    pub username: String,
    pub authenticated: bool,
    pub authenticated_at: i64,
}

impl WebSession {
    /// Create a new authenticated session
    pub fn authenticated(username: &str) -> Self {
        Self {
            username: username.to_string(),
            authenticated: true,
            authenticated_at: chrono::Utc::now().timestamp(),
        }
    }

    /// Check if the session is valid (not too old)
    pub fn is_valid(&self) -> bool {
        if !self.authenticated {
            return false;
        }

        // Sessions expire after 24 hours
        let now = chrono::Utc::now().timestamp();
        let max_age = 24 * 60 * 60; // 24 hours in seconds

        now - self.authenticated_at < max_age
    }
}

/// Extractor for requiring authentication
///
/// Use this in route handlers to require an authenticated admin session:
/// ```ignore
/// async fn protected_route(auth: RequireAuth, ...) -> impl IntoResponse {
///     // This handler only runs if the user is authenticated
/// }
/// ```
pub struct RequireAuth {
    pub session: WebSession,
}

impl<S> FromRequestParts<S> for RequireAuth
where
    Arc<AdminAuth>: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        // Get the session
        let session = Session::from_request_parts(parts, state)
            .await
            .map_err(|_| {
                Redirect::to("/login").into_response()
            })?;

        // Check for valid session data
        let web_session: Option<WebSession> = session
            .get(SESSION_KEY)
            .await
            .ok()
            .flatten();

        match web_session {
            Some(ws) if ws.is_valid() => Ok(RequireAuth { session: ws }),
            _ => {
                // Not authenticated or session expired
                Err(Redirect::to("/login").into_response())
            }
        }
    }
}

/// Helper to set the session after successful login
pub async fn set_authenticated_session(
    session: &Session,
    username: &str,
) -> Result<(), StatusCode> {
    let web_session = WebSession::authenticated(username);
    session
        .insert(SESSION_KEY, web_session)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(())
}

/// Helper to clear the session on logout
pub async fn clear_session(session: &Session) -> Result<(), StatusCode> {
    session.flush().await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_admin_auth_creation() {
        let auth = AdminAuth::new("admin", "secret123").unwrap();
        assert!(auth.verify_password("secret123"));
        assert!(!auth.verify_password("wrong"));
    }

    #[test]
    fn test_web_session_validity() {
        let session = WebSession::authenticated("admin");
        assert!(session.is_valid());

        // Test expired session
        let expired = WebSession {
            username: "admin".to_string(),
            authenticated: true,
            authenticated_at: chrono::Utc::now().timestamp() - (25 * 60 * 60), // 25 hours ago
        };
        assert!(!expired.is_valid());
    }
}
