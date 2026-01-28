//! Web server implementation using Axum

use crate::auth::AuthManager;
use crate::config::Config;
use crate::storage::StorageBackend;
use axum::{
    extract::FromRef,
    routing::{get, post},
    Router,
};
use std::sync::Arc;
use tokio::sync::RwLock;
use tower_http::services::ServeDir;
use tower_http::trace::TraceLayer;
use tower_sessions::{MemoryStore, SessionManagerLayer};

use super::auth::AdminAuth;
use super::routes;

/// Web server configuration
#[derive(Debug, Clone)]
pub struct WebConfig {
    /// Address to bind the web server
    pub bind: String,
    /// Whether to enable the web UI
    pub enabled: bool,
}

impl Default for WebConfig {
    fn default() -> Self {
        Self {
            bind: "127.0.0.1:7879".to_string(),
            enabled: true,
        }
    }
}

/// Application state shared across handlers
#[derive(Clone)]
pub struct AppState {
    pub storage: Arc<dyn StorageBackend>,
    pub auth_manager: Arc<RwLock<AuthManager>>,
    pub admin_auth: Arc<AdminAuth>,
    pub config: Config,
}

impl FromRef<AppState> for Arc<dyn StorageBackend> {
    fn from_ref(state: &AppState) -> Self {
        state.storage.clone()
    }
}

impl FromRef<AppState> for Arc<RwLock<AuthManager>> {
    fn from_ref(state: &AppState) -> Self {
        state.auth_manager.clone()
    }
}

impl FromRef<AppState> for Arc<AdminAuth> {
    fn from_ref(state: &AppState) -> Self {
        state.admin_auth.clone()
    }
}

/// Web server for Vultrino admin UI
pub struct WebServer {
    config: WebConfig,
    app_state: AppState,
}

impl WebServer {
    /// Create a new web server
    pub fn new(
        config: WebConfig,
        vultrino_config: Config,
        storage: Arc<dyn StorageBackend>,
        auth_manager: AuthManager,
        admin_auth: AdminAuth,
    ) -> Self {
        let app_state = AppState {
            storage,
            auth_manager: Arc::new(RwLock::new(auth_manager)),
            admin_auth: Arc::new(admin_auth),
            config: vultrino_config,
        };

        Self { config, app_state }
    }

    /// Build the router with all routes
    fn build_router(&self) -> Router {
        // Session store for login sessions
        let session_store = MemoryStore::default();
        let session_layer = SessionManagerLayer::new(session_store)
            .with_secure(false) // Set to true in production with HTTPS
            .with_same_site(tower_sessions::cookie::SameSite::Lax);

        // Static files (CSS, JS, images)
        let static_dir = ServeDir::new("static");

        // Build routes
        Router::new()
            // Public routes
            .route("/login", get(routes::login_page))
            .route("/login", post(routes::login_submit))
            .route("/logout", post(routes::logout))
            // Protected routes (require auth)
            .route("/", get(routes::dashboard))
            .route("/dashboard", get(routes::dashboard))
            .route("/credentials", get(routes::credentials_list))
            .route("/credentials/new", get(routes::credential_new))
            .route("/credentials/new", post(routes::credential_create))
            .route("/credentials/{id}/delete", post(routes::credential_delete))
            .route("/roles", get(routes::roles_list))
            .route("/roles/new", get(routes::role_new))
            .route("/roles/new", post(routes::role_create))
            .route("/roles/{id}/delete", post(routes::role_delete))
            .route("/keys", get(routes::keys_list))
            .route("/keys/new", get(routes::key_new))
            .route("/keys/new", post(routes::key_create))
            .route("/keys/{id}/revoke", post(routes::key_revoke))
            .route("/audit", get(routes::audit_log))
            // API endpoints for HTMX
            .route("/api/stats", get(routes::api_stats))
            // Static files
            .nest_service("/static", static_dir)
            // Layers
            .layer(session_layer)
            .layer(TraceLayer::new_for_http())
            .with_state(self.app_state.clone())
    }

    /// Run the web server
    pub async fn run(self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let router = self.build_router();
        let listener = tokio::net::TcpListener::bind(&self.config.bind).await?;

        tracing::info!(bind = %self.config.bind, "Starting Vultrino Web UI");

        axum::serve(listener, router).await?;

        Ok(())
    }

    /// Get the bind address
    pub fn bind_address(&self) -> &str {
        &self.config.bind
    }
}
