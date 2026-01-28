//! Route handlers for the web UI

use askama::Template;
use axum::{
    extract::{Path, State},
    response::{Html, IntoResponse, Redirect, Response},
    Form,
};
use serde::Deserialize;
use std::collections::HashMap;
use tower_sessions::Session;

use crate::auth::Permission;
use crate::plugins::PluginInstaller;
use crate::{Credential, CredentialData, Secret};

use super::auth::{clear_session, set_authenticated_session, RequireAuth};
use super::server::AppState;
use super::templates::{
    AuditLogTemplate, ApiKeyDisplay, CredentialDisplay, CredentialNewTemplate,
    CredentialsListTemplate, DashboardStats, DashboardTemplate, FlashKind, FlashMessage,
    KeyNewTemplate, KeysListTemplate, LoginTemplate, PluginCredentialType, RoleDisplay,
    RoleNewTemplate, RoleOption, RolesListTemplate,
};

// ============== Login/Logout ==============

pub async fn login_page() -> impl IntoResponse {
    let template = LoginTemplate { error: None };
    Html(template.render().unwrap_or_else(|e| format!("Template error: {}", e)))
}

#[derive(Deserialize)]
pub struct LoginForm {
    username: String,
    password: String,
}

pub async fn login_submit(
    State(state): State<AppState>,
    session: Session,
    Form(form): Form<LoginForm>,
) -> Response {
    let admin_auth = &state.admin_auth;

    // Verify credentials
    if form.username == admin_auth.username() && admin_auth.verify_password(&form.password) {
        // Set session
        if set_authenticated_session(&session, &form.username).await.is_ok() {
            return Redirect::to("/dashboard").into_response();
        }
    }

    // Failed login
    let template = LoginTemplate {
        error: Some("Invalid username or password".to_string()),
    };
    Html(template.render().unwrap_or_else(|e| format!("Template error: {}", e))).into_response()
}

pub async fn logout(session: Session) -> impl IntoResponse {
    let _ = clear_session(&session).await;
    Redirect::to("/login")
}

// ============== Dashboard ==============

pub async fn dashboard(
    State(state): State<AppState>,
    auth: RequireAuth,
) -> impl IntoResponse {
    let storage = &state.storage;

    // Get stats
    let credentials = storage.list().await.unwrap_or_default();
    let roles = storage.list_roles().await.unwrap_or_default();
    let api_keys = storage.list_api_keys().await.unwrap_or_default();

    let stats = DashboardStats {
        total_credentials: credentials.len(),
        total_roles: roles.len() + 3, // Include built-in roles
        total_api_keys: api_keys.len(),
        recent_requests: 0, // TODO: Implement audit logging
    };

    let template = DashboardTemplate {
        username: auth.session.username,
        stats,
        flash: None,
    };

    Html(template.render().unwrap_or_else(|e| format!("Template error: {}", e)))
}

// ============== Credentials ==============

pub async fn credentials_list(
    State(state): State<AppState>,
    auth: RequireAuth,
) -> impl IntoResponse {
    let credentials = state.storage.list().await.unwrap_or_default();
    let credential_displays: Vec<CredentialDisplay> = credentials.iter().map(|c| c.into()).collect();

    let template = CredentialsListTemplate {
        username: auth.session.username,
        credentials: credential_displays,
        flash: None,
    };

    Html(template.render().unwrap_or_else(|e| format!("Template error: {}", e)))
}

pub async fn credential_new(auth: RequireAuth) -> impl IntoResponse {
    // Load plugin credential types
    let plugin_types = get_plugin_credential_types().await;

    let template = CredentialNewTemplate {
        username: auth.session.username,
        error: None,
        plugin_types,
    };

    Html(template.render().unwrap_or_else(|e| format!("Template error: {}", e)))
}

/// Get all credential types defined by installed plugins
async fn get_plugin_credential_types() -> Vec<PluginCredentialType> {
    let installer = PluginInstaller::default();
    let installed = installer.list().await.unwrap_or_default();

    let mut plugin_types = Vec::new();
    for info in installed {
        if !info.enabled {
            continue;
        }
        for cred_type in &info.manifest.credential_types {
            plugin_types.push(PluginCredentialType::from_plugin_type(
                &info.manifest.plugin.name,
                cred_type,
            ));
        }
    }
    plugin_types
}

#[derive(Deserialize)]
pub struct CredentialForm {
    alias: String,
    credential_type: String,
    description: Option<String>,
    // API Key fields
    api_key: Option<String>,
    header_name: Option<String>,
    header_prefix: Option<String>,
    // Basic Auth fields
    username: Option<String>,
    password: Option<String>,
    // Plugin credential fields (dynamic)
    #[serde(flatten)]
    plugin_fields: HashMap<String, String>,
}

pub async fn credential_create(
    State(state): State<AppState>,
    auth: RequireAuth,
    Form(form): Form<CredentialForm>,
) -> Response {
    // Build credential data based on type
    let data = match form.credential_type.as_str() {
        "api_key" => {
            let key = match form.api_key {
                Some(k) if !k.is_empty() => k,
                _ => {
                    return render_credential_new_error(auth, "API key is required")
                        .await
                        .into_response();
                }
            };
            CredentialData::ApiKey {
                key: Secret::new(key),
                header_name: form.header_name.unwrap_or_else(|| "Authorization".to_string()),
                header_prefix: form.header_prefix.unwrap_or_else(|| "Bearer ".to_string()),
            }
        }
        "basic_auth" => {
            let username = match form.username {
                Some(u) if !u.is_empty() => u,
                _ => {
                    return render_credential_new_error(auth, "Username is required")
                        .await
                        .into_response();
                }
            };
            let password = match form.password {
                Some(p) if !p.is_empty() => p,
                _ => {
                    return render_credential_new_error(auth, "Password is required")
                        .await
                        .into_response();
                }
            };
            CredentialData::BasicAuth {
                username,
                password: Secret::new(password),
            }
        }
        cred_type if cred_type.starts_with("plugin:") => {
            // Handle plugin credential types
            match parse_plugin_credential(&form).await {
                Ok(data) => data,
                Err(e) => {
                    return render_credential_new_error(auth, &e).await.into_response();
                }
            }
        }
        _ => {
            return render_credential_new_error(auth, "Invalid credential type")
                .await
                .into_response();
        }
    };

    // Create and store credential
    let mut credential = Credential::new(form.alias, data);
    if let Some(desc) = form.description {
        if !desc.is_empty() {
            credential = credential.with_metadata("description", desc);
        }
    }

    // Store plugin type in metadata for plugin credentials
    if form.credential_type.starts_with("plugin:") {
        credential = credential.with_metadata("plugin_type", form.credential_type);
    }

    if let Err(e) = state.storage.store(&credential).await {
        return render_credential_new_error(auth, &format!("Failed to save: {}", e))
            .await
            .into_response();
    }

    Redirect::to("/credentials").into_response()
}

/// Parse plugin credential form data
async fn parse_plugin_credential(form: &CredentialForm) -> Result<CredentialData, String> {
    // Parse plugin:plugin_name:type_name format
    let parts: Vec<&str> = form.credential_type.splitn(3, ':').collect();
    if parts.len() != 3 {
        return Err("Invalid plugin credential type format".to_string());
    }

    let plugin_name = parts[1];
    let type_name = parts[2];

    // Load the plugin
    let installer = PluginInstaller::default();
    let plugin_info = installer
        .get(plugin_name)
        .await
        .map_err(|e| format!("Failed to load plugin: {}", e))?
        .ok_or_else(|| format!("Plugin '{}' not found", plugin_name))?;

    // Find the credential type definition
    let cred_type = plugin_info
        .manifest
        .credential_types
        .iter()
        .find(|ct| ct.name == type_name)
        .ok_or_else(|| format!("Credential type '{}' not found in plugin", type_name))?;

    // Build form data from the CredentialForm
    // Note: Plugin fields are expected to be in form.plugin_fields
    let plugin_fields = &form.plugin_fields;

    // Validate required fields
    for field in cred_type.required_fields() {
        if !plugin_fields.contains_key(&field.name)
            || plugin_fields.get(&field.name).map(|v| v.is_empty()).unwrap_or(true)
        {
            return Err(format!("Missing required field: {}", field.label));
        }
    }

    // Build credential data as Custom HashMap
    let mut data = std::collections::HashMap::new();
    for field in &cred_type.fields {
        if let Some(value) = plugin_fields.get(&field.name) {
            if !value.is_empty() {
                data.insert(field.name.clone(), Secret::new(value.clone()));
            }
        }
    }

    Ok(CredentialData::Custom(data))
}

async fn render_credential_new_error(auth: RequireAuth, error: &str) -> impl IntoResponse {
    let plugin_types = get_plugin_credential_types().await;
    let template = CredentialNewTemplate {
        username: auth.session.username,
        error: Some(error.to_string()),
        plugin_types,
    };
    Html(template.render().unwrap_or_else(|e| format!("Template error: {}", e)))
}

pub async fn credential_delete(
    State(state): State<AppState>,
    _auth: RequireAuth,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let _ = state.storage.delete(&id).await;
    Redirect::to("/credentials")
}

// ============== Roles ==============

pub async fn roles_list(
    State(state): State<AppState>,
    auth: RequireAuth,
) -> impl IntoResponse {
    let auth_manager = state.auth_manager.read().await;
    let mut roles = auth_manager.list_roles();

    // Add stored custom roles
    if let Ok(stored_roles) = state.storage.list_roles().await {
        for role in stored_roles {
            if !roles.iter().any(|r| r.name == role.name) {
                roles.push(role);
            }
        }
    }

    let role_displays: Vec<RoleDisplay> = roles.iter().map(|r| r.into()).collect();

    let template = RolesListTemplate {
        username: auth.session.username,
        roles: role_displays,
        flash: None,
    };

    Html(template.render().unwrap_or_else(|e| format!("Template error: {}", e)))
}

pub async fn role_new(auth: RequireAuth) -> impl IntoResponse {
    let template = RoleNewTemplate {
        username: auth.session.username,
        error: None,
    };

    Html(template.render().unwrap_or_else(|e| format!("Template error: {}", e)))
}

#[derive(Deserialize)]
pub struct RoleForm {
    name: String,
    description: Option<String>,
    permissions: Vec<String>,
    scopes: Option<String>,
}

pub async fn role_create(
    State(state): State<AppState>,
    auth: RequireAuth,
    Form(form): Form<RoleForm>,
) -> Response {
    // Parse permissions
    let permissions: std::collections::HashSet<Permission> = form
        .permissions
        .iter()
        .filter_map(|p| match p.as_str() {
            "read" => Some(Permission::Read),
            "write" => Some(Permission::Write),
            "update" => Some(Permission::Update),
            "delete" => Some(Permission::Delete),
            "execute" => Some(Permission::Execute),
            _ => None,
        })
        .collect();

    if permissions.is_empty() {
        return render_role_new_error(auth, "At least one permission is required").into_response();
    }

    // Parse scopes
    let credential_scopes: Vec<String> = form
        .scopes
        .map(|s| s.split(',').map(|p| p.trim().to_string()).filter(|s| !s.is_empty()).collect())
        .unwrap_or_default();

    // Create the role
    let auth_manager = state.auth_manager.write().await;
    let role = match auth_manager.create_role(&form.name, permissions, credential_scopes, form.description) {
        Ok(r) => r,
        Err(e) => {
            return render_role_new_error(auth, &format!("Failed to create role: {}", e)).into_response();
        }
    };

    // Store the role
    if let Err(e) = state.storage.store_role(&role).await {
        return render_role_new_error(auth, &format!("Failed to save: {}", e)).into_response();
    }

    Redirect::to("/roles").into_response()
}

fn render_role_new_error(auth: RequireAuth, error: &str) -> impl IntoResponse {
    let template = RoleNewTemplate {
        username: auth.session.username,
        error: Some(error.to_string()),
    };
    Html(template.render().unwrap_or_else(|e| format!("Template error: {}", e)))
}

pub async fn role_delete(
    State(state): State<AppState>,
    _auth: RequireAuth,
    Path(id): Path<String>,
) -> impl IntoResponse {
    // Don't allow deleting built-in roles
    let auth_manager = state.auth_manager.read().await;
    if let Some(role) = auth_manager.get_role(&id) {
        if matches!(role.name.as_str(), "admin" | "read-only" | "executor") {
            return Redirect::to("/roles");
        }
    }
    drop(auth_manager);

    let _ = state.storage.delete_role(&id).await;
    Redirect::to("/roles")
}

// ============== API Keys ==============

pub async fn keys_list(
    State(state): State<AppState>,
    auth: RequireAuth,
) -> impl IntoResponse {
    let keys = state.storage.list_api_keys().await.unwrap_or_default();
    let auth_manager = state.auth_manager.read().await;

    let key_displays: Vec<ApiKeyDisplay> = keys
        .iter()
        .map(|k| {
            let role = auth_manager.get_role(&k.role_id);
            ApiKeyDisplay::from_key_and_role(k, role.as_ref())
        })
        .collect();

    let template = KeysListTemplate {
        username: auth.session.username,
        keys: key_displays,
        flash: None,
        new_key: None,
    };

    Html(template.render().unwrap_or_else(|e| format!("Template error: {}", e)))
}

pub async fn key_new(
    State(state): State<AppState>,
    auth: RequireAuth,
) -> impl IntoResponse {
    let auth_manager = state.auth_manager.read().await;
    let mut roles = auth_manager.list_roles();

    // Add stored custom roles
    if let Ok(stored_roles) = state.storage.list_roles().await {
        for role in stored_roles {
            if !roles.iter().any(|r| r.name == role.name) {
                roles.push(role);
            }
        }
    }

    let role_options: Vec<RoleOption> = roles.iter().map(|r| r.into()).collect();

    let template = KeyNewTemplate {
        username: auth.session.username,
        roles: role_options,
        error: None,
    };

    Html(template.render().unwrap_or_else(|e| format!("Template error: {}", e)))
}

#[derive(Deserialize)]
pub struct KeyForm {
    name: String,
    role: String,
    expires: Option<String>,
}

pub async fn key_create(
    State(state): State<AppState>,
    auth: RequireAuth,
    Form(form): Form<KeyForm>,
) -> Response {
    // Parse expiration
    let expires_in = match form.expires.as_deref() {
        Some("never") | Some("") | None => None,
        Some(s) => {
            match parse_duration(s) {
                Ok(d) => d,
                Err(e) => {
                    return render_key_new_error(state.clone(), auth, &e).await.into_response();
                }
            }
        }
    };

    let auth_manager = state.auth_manager.write().await;

    // Verify role exists
    if auth_manager.get_role_by_name(&form.role).is_none() {
        return render_key_new_error(state.clone(), auth, &format!("Role '{}' not found", form.role))
            .await
            .into_response();
    }

    // Create the key
    let (full_key, api_key) = match auth_manager.create_api_key(&form.name, &form.role, expires_in) {
        Ok(k) => k,
        Err(e) => {
            return render_key_new_error(state.clone(), auth, &format!("Failed to create key: {}", e))
                .await
                .into_response();
        }
    };

    // Store the key
    if let Err(e) = state.storage.store_api_key(&api_key).await {
        return render_key_new_error(state.clone(), auth, &format!("Failed to save: {}", e))
            .await
            .into_response();
    }

    // Show the key list with the new key displayed once
    let keys = state.storage.list_api_keys().await.unwrap_or_default();
    let key_displays: Vec<ApiKeyDisplay> = keys
        .iter()
        .map(|k| {
            let role = auth_manager.get_role(&k.role_id);
            ApiKeyDisplay::from_key_and_role(k, role.as_ref())
        })
        .collect();

    let template = KeysListTemplate {
        username: auth.session.username,
        keys: key_displays,
        flash: Some(FlashMessage {
            kind: FlashKind::Success,
            message: "API key created successfully".to_string(),
        }),
        new_key: Some(full_key),
    };

    Html(template.render().unwrap_or_else(|e| format!("Template error: {}", e))).into_response()
}

async fn render_key_new_error(state: AppState, auth: RequireAuth, error: &str) -> impl IntoResponse {
    let auth_manager = state.auth_manager.read().await;
    let mut roles = auth_manager.list_roles();

    if let Ok(stored_roles) = state.storage.list_roles().await {
        for role in stored_roles {
            if !roles.iter().any(|r| r.name == role.name) {
                roles.push(role);
            }
        }
    }

    let role_options: Vec<RoleOption> = roles.iter().map(|r| r.into()).collect();

    let template = KeyNewTemplate {
        username: auth.session.username,
        roles: role_options,
        error: Some(error.to_string()),
    };
    Html(template.render().unwrap_or_else(|e| format!("Template error: {}", e)))
}

pub async fn key_revoke(
    State(state): State<AppState>,
    _auth: RequireAuth,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let _ = state.storage.delete_api_key(&id).await;
    Redirect::to("/keys")
}

// ============== Audit Log ==============

pub async fn audit_log(auth: RequireAuth) -> impl IntoResponse {
    // TODO: Implement audit logging
    let template = AuditLogTemplate {
        username: auth.session.username,
        entries: vec![],
        flash: None,
    };

    Html(template.render().unwrap_or_else(|e| format!("Template error: {}", e)))
}

// ============== API Endpoints ==============

pub async fn api_stats(
    State(state): State<AppState>,
    _auth: RequireAuth,
) -> impl IntoResponse {
    let credentials = state.storage.list().await.unwrap_or_default();
    let roles = state.storage.list_roles().await.unwrap_or_default();
    let api_keys = state.storage.list_api_keys().await.unwrap_or_default();

    axum::Json(serde_json::json!({
        "credentials": credentials.len(),
        "roles": roles.len() + 3,
        "api_keys": api_keys.len(),
        "recent_requests": 0
    }))
}

// ============== Helpers ==============

fn parse_duration(s: &str) -> Result<Option<chrono::Duration>, String> {
    let s = s.trim().to_lowercase();
    if s == "never" || s.is_empty() {
        return Ok(None);
    }

    let (num_str, unit) = if s.ends_with('d') {
        (&s[..s.len() - 1], "d")
    } else if s.ends_with('h') {
        (&s[..s.len() - 1], "h")
    } else if s.ends_with('w') {
        (&s[..s.len() - 1], "w")
    } else if s.ends_with('m') {
        (&s[..s.len() - 1], "m")
    } else if s.ends_with('y') {
        (&s[..s.len() - 1], "y")
    } else {
        return Err(format!("Invalid duration format: {}. Use '30d', '24h', '1w'", s));
    };

    let num: i64 = num_str
        .parse()
        .map_err(|_| format!("Invalid number: {}", num_str))?;

    let duration = match unit {
        "h" => chrono::Duration::hours(num),
        "d" => chrono::Duration::days(num),
        "w" => chrono::Duration::weeks(num),
        "m" => chrono::Duration::days(num * 30),
        "y" => chrono::Duration::days(num * 365),
        _ => unreachable!(),
    };

    Ok(Some(duration))
}
