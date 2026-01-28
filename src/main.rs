//! Vultrino CLI - A credential proxy for the AI era
//!
//! Run `vultrino --help` for usage information.

use chrono::Duration;
use clap::{Parser, Subcommand};
use secrecy::SecretString;
use std::io::{self, Write};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn, Level};
use tracing_subscriber::{fmt, prelude::*, EnvFilter};
use vultrino::auth::{AuthManager, Permission, ROLE_ADMIN, ROLE_EXECUTOR, ROLE_READ_ONLY};
use vultrino::config::{Config, StorageBackendType};
use vultrino::mcp::McpServer;
use vultrino::plugins::PluginInstaller;
use vultrino::router::CredentialResolver;
use vultrino::server::VultrinoServer;
use vultrino::storage::{FileStorage, StorageBackend};
use vultrino::web::{AdminAuth, WebConfig, WebServer};
use vultrino::{Credential, CredentialData, ExecuteRequest, Secret};

#[derive(Parser)]
#[command(
    name = "vultrino",
    about = "A credential proxy for the AI era - enabling AI agents to use credentials without seeing them",
    version
)]
struct Cli {
    /// Configuration file path
    #[arg(short, long, global = true)]
    config: Option<PathBuf>,

    /// Increase verbosity (-v, -vv, -vvv)
    #[arg(short, long, action = clap::ArgAction::Count, global = true)]
    verbose: u8,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the Vultrino server
    Serve {
        /// Address to bind to
        #[arg(short, long, default_value = "127.0.0.1:7878")]
        bind: String,

        /// Run in MCP mode (stdio communication for LLM integration)
        #[arg(long)]
        mcp: bool,
    },

    /// Add a new credential
    Add {
        /// Credential alias (human-readable name)
        #[arg(short, long)]
        alias: String,

        /// Credential type (api_key, basic_auth, oauth2)
        #[arg(short = 't', long, default_value = "api_key")]
        r#type: String,

        /// Description of the credential
        #[arg(short, long)]
        description: Option<String>,

        /// API key value (for api_key type)
        #[arg(long)]
        key: Option<String>,

        /// Username (for basic_auth type)
        #[arg(long)]
        username: Option<String>,

        /// Password (for basic_auth type, will prompt if not provided)
        #[arg(long)]
        password: Option<String>,

        /// Custom header name (for api_key type)
        #[arg(long, default_value = "Authorization")]
        header_name: String,

        /// Custom header prefix (for api_key type)
        #[arg(long, default_value = "Bearer ")]
        header_prefix: String,
    },

    /// List stored credentials
    List {
        /// Output format (table, json)
        #[arg(short, long, default_value = "table")]
        format: String,
    },

    /// Remove a credential
    Remove {
        /// Credential alias or ID
        alias: String,
    },

    /// Show credential info (without secrets)
    Info {
        /// Credential alias or ID
        alias: String,
    },

    /// Initialize configuration
    Init {
        /// Force overwrite existing configuration
        #[arg(short, long)]
        force: bool,
    },

    /// Run the MCP server (for LLM integration)
    Mcp,

    /// Manage roles (RBAC)
    Role {
        #[command(subcommand)]
        command: RoleCommands,
    },

    /// Manage API keys (RBAC)
    Key {
        #[command(subcommand)]
        command: KeyCommands,
    },

    /// Start the web UI server
    Web {
        /// Address to bind to
        #[arg(short, long, default_value = "127.0.0.1:7879")]
        bind: String,
    },

    /// Manage plugins
    Plugin {
        #[command(subcommand)]
        command: PluginCommands,
    },

    /// Make an authenticated HTTP request (alias: req)
    #[command(alias = "req")]
    Request {
        /// Credential alias to use for authentication
        credential: String,

        /// Target URL
        url: String,

        /// HTTP method (GET, POST, PUT, DELETE, PATCH)
        #[arg(short = 'X', long, default_value = "GET")]
        method: String,

        /// Request body (JSON string, or @filename to read from file)
        #[arg(short, long)]
        data: Option<String>,

        /// Additional headers (can be repeated: -H "Content-Type: application/json")
        #[arg(short = 'H', long = "header")]
        headers: Vec<String>,

        /// Output only the response body (no status info)
        #[arg(short, long)]
        quiet: bool,
    },

    /// Execute a plugin action
    #[command(alias = "exec")]
    Action {
        /// Credential alias to use
        credential: String,

        /// Plugin action (format: plugin.action, e.g., pgp-signing.sign_cleartext)
        action: String,

        /// Action parameters as JSON
        #[arg(short, long)]
        params: Option<String>,

        /// Output only the result (no status info)
        #[arg(short, long)]
        quiet: bool,
    },
}

#[derive(Subcommand)]
enum RoleCommands {
    /// Create a new role
    Create {
        /// Role name
        name: String,

        /// Permissions (comma-separated: read,write,update,delete,execute)
        #[arg(short, long)]
        permissions: String,

        /// Credential scopes (comma-separated glob patterns, e.g., "github-*,aws-*")
        #[arg(short, long)]
        scopes: Option<String>,

        /// Role description
        #[arg(short, long)]
        description: Option<String>,
    },

    /// List all roles
    List {
        /// Output format (table, json)
        #[arg(short, long, default_value = "table")]
        format: String,
    },

    /// Delete a role
    Delete {
        /// Role name or ID
        name: String,
    },

    /// Show role info
    Info {
        /// Role name or ID
        name: String,
    },
}

#[derive(Subcommand)]
enum KeyCommands {
    /// Create a new API key
    Create {
        /// Key name (for identification)
        name: String,

        /// Role to assign to this key
        #[arg(short, long)]
        role: String,

        /// Expiration duration (e.g., "30d", "24h", "never")
        #[arg(short, long, default_value = "never")]
        expires: String,
    },

    /// List all API keys
    List {
        /// Output format (table, json)
        #[arg(short, long, default_value = "table")]
        format: String,
    },

    /// Revoke (delete) an API key
    Revoke {
        /// Key ID or prefix
        id: String,
    },
}

#[derive(Subcommand)]
enum PluginCommands {
    /// Install a plugin from a local path, git URL, or archive URL
    Install {
        /// Plugin source (local path, git URL with optional #ref, or archive URL)
        source: String,
    },

    /// List installed plugins
    List {
        /// Output format (table, json)
        #[arg(short, long, default_value = "table")]
        format: String,
    },

    /// Remove an installed plugin
    Remove {
        /// Plugin name
        name: String,
    },

    /// Show plugin info
    Info {
        /// Plugin name
        name: String,
    },

    /// Reload a plugin (hot-reload without restart)
    Reload {
        /// Plugin name
        name: String,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    // Setup logging
    let log_level = match cli.verbose {
        0 => Level::INFO,
        1 => Level::DEBUG,
        _ => Level::TRACE,
    };

    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(
            EnvFilter::from_default_env()
                .add_directive(log_level.into()),
        )
        .init();

    // Load configuration
    let config = if let Some(config_path) = &cli.config {
        Config::load(config_path).await?
    } else {
        let default_path = Config::default_path();
        if default_path.exists() {
            Config::load(&default_path).await.unwrap_or_default()
        } else {
            Config::default()
        }
    };

    // Execute command
    match cli.command {
        Commands::Serve { bind, mcp } => {
            if mcp {
                run_mcp_server(config).await?;
            } else {
                run_server(config, bind).await?;
            }
        }
        Commands::Add {
            alias,
            r#type,
            description,
            key,
            username,
            password,
            header_name,
            header_prefix,
        } => {
            add_credential(
                config,
                alias,
                r#type,
                description,
                key,
                username,
                password,
                header_name,
                header_prefix,
            )
            .await?;
        }
        Commands::List { format } => {
            list_credentials(config, format).await?;
        }
        Commands::Remove { alias } => {
            remove_credential(config, alias).await?;
        }
        Commands::Info { alias } => {
            show_credential_info(config, alias).await?;
        }
        Commands::Init { force } => {
            init_config(force).await?;
        }
        Commands::Mcp => {
            run_mcp_server(config).await?;
        }
        Commands::Role { command } => match command {
            RoleCommands::Create {
                name,
                permissions,
                scopes,
                description,
            } => {
                create_role(config, name, permissions, scopes, description).await?;
            }
            RoleCommands::List { format } => {
                list_roles(config, format).await?;
            }
            RoleCommands::Delete { name } => {
                delete_role(config, name).await?;
            }
            RoleCommands::Info { name } => {
                show_role_info(config, name).await?;
            }
        },
        Commands::Key { command } => match command {
            KeyCommands::Create { name, role, expires } => {
                create_api_key(config, name, role, expires).await?;
            }
            KeyCommands::List { format } => {
                list_api_keys(config, format).await?;
            }
            KeyCommands::Revoke { id } => {
                revoke_api_key(config, id).await?;
            }
        },
        Commands::Request {
            credential,
            url,
            method,
            data,
            headers,
            quiet,
        } => {
            make_request(config, credential, url, method, data, headers, quiet).await?;
        }
        Commands::Action {
            credential,
            action,
            params,
            quiet,
        } => {
            execute_action(config, credential, action, params, quiet).await?;
        }
        Commands::Web { bind } => {
            run_web_server(config, bind).await?;
        }
        Commands::Plugin { command } => match command {
            PluginCommands::Install { source } => {
                install_plugin(source).await?;
            }
            PluginCommands::List { format } => {
                list_plugins(format).await?;
            }
            PluginCommands::Remove { name } => {
                remove_plugin(name).await?;
            }
            PluginCommands::Info { name } => {
                show_plugin_info(name).await?;
            }
            PluginCommands::Reload { name } => {
                reload_plugin(name).await?;
            }
        },
    }

    Ok(())
}

/// Get the storage password from environment or prompt
fn get_storage_password() -> Result<SecretString, Box<dyn std::error::Error>> {
    // Check environment variable first
    if let Ok(password) = std::env::var("VULTRINO_PASSWORD") {
        return Ok(SecretString::from(password));
    }

    // Prompt for password
    eprint!("Enter storage password: ");
    io::stderr().flush()?;

    let password = rpassword::read_password()?;
    Ok(SecretString::from(password))
}

/// Initialize storage backend
async fn init_storage(config: &Config) -> Result<Arc<dyn StorageBackend>, Box<dyn std::error::Error>> {
    let password = get_storage_password()?;

    match config.storage.backend {
        StorageBackendType::File => {
            let path = config
                .storage
                .file_path
                .clone()
                .unwrap_or_else(Config::default_storage_path);

            let storage = FileStorage::new(&path, &password).await?;
            Ok(Arc::new(storage))
        }
        StorageBackendType::Keychain => {
            // TODO: Implement keychain storage
            Err("Keychain storage not yet implemented".into())
        }
        StorageBackendType::Vault => {
            // TODO: Implement Vault storage
            Err("Vault storage not yet implemented".into())
        }
    }
}

/// Run the HTTP proxy server
async fn run_server(config: Config, bind: String) -> Result<(), Box<dyn std::error::Error>> {
    info!(bind = %bind, "Starting Vultrino server");

    let storage = init_storage(&config).await?;
    let resolver = CredentialResolver::new(storage.clone());
    let server = VultrinoServer::new(config, storage, resolver);

    // Load installed plugins
    if let Err(e) = server.load_plugins().await {
        warn!("Failed to load plugins: {}", e);
    }

    // TODO: Implement JSON API server
    // For now, just print info and wait
    println!("Vultrino server running on {}", bind);
    println!("Press Ctrl+C to stop");

    tokio::signal::ctrl_c().await?;
    info!("Shutting down");

    Ok(())
}

/// Run the MCP server for LLM integration
async fn run_mcp_server(config: Config) -> Result<(), Box<dyn std::error::Error>> {
    // Disable normal logging for MCP mode (we communicate via stdio)
    let storage = init_storage(&config).await?;
    let resolver = CredentialResolver::new(storage.clone());
    let server = VultrinoServer::new(config, storage, resolver);

    // Load installed plugins
    if let Err(e) = server.load_plugins().await {
        eprintln!("Warning: Failed to load plugins: {}", e);
    }

    let vultrino = Arc::new(RwLock::new(server));
    let mut mcp = McpServer::new(vultrino);

    mcp.run_stdio().await?;

    Ok(())
}

/// Run the web UI server
async fn run_web_server(config: Config, bind: String) -> Result<(), Box<dyn std::error::Error>> {
    // Load admin credentials
    let admin_auth = load_admin_auth(&config).await?;

    let storage = init_storage(&config).await?;

    // Load existing roles and keys for auth manager
    let stored_roles = storage.list_roles().await?;
    let stored_keys = storage.list_api_keys().await?;
    let auth_manager = AuthManager::from_data(stored_roles, stored_keys);

    let web_config = WebConfig {
        bind,
        enabled: true,
    };

    let web_server = WebServer::new(
        web_config,
        config,
        storage,
        auth_manager,
        admin_auth,
    );

    info!(bind = %web_server.bind_address(), "Starting Vultrino Web UI");
    println!("Vultrino Web UI running at http://{}", web_server.bind_address());
    println!("Press Ctrl+C to stop");

    web_server.run().await.map_err(|e| -> Box<dyn std::error::Error> { e.to_string().into() })
}

/// Load admin auth from storage or prompt for setup
async fn load_admin_auth(_config: &Config) -> Result<AdminAuth, Box<dyn std::error::Error>> {
    // Try to load from config directory
    let auth_path = Config::default_path()
        .parent()
        .map(|p| p.join("admin.json"))
        .ok_or("Could not determine auth path")?;

    if auth_path.exists() {
        let content = tokio::fs::read_to_string(&auth_path).await?;
        let data: serde_json::Value = serde_json::from_str(&content)?;

        let username = data["username"]
            .as_str()
            .ok_or("Missing username in admin.json")?
            .to_string();
        let password_hash = data["password_hash"]
            .as_str()
            .ok_or("Missing password_hash in admin.json")?
            .to_string();

        Ok(AdminAuth::from_hash(username, password_hash))
    } else {
        Err("Admin credentials not configured. Run 'vultrino init' first.".into())
    }
}

/// Save admin auth to storage
async fn save_admin_auth(admin_auth: &AdminAuth) -> Result<(), Box<dyn std::error::Error>> {
    let auth_path = Config::default_path()
        .parent()
        .map(|p| p.join("admin.json"))
        .ok_or("Could not determine auth path")?;

    let data = serde_json::json!({
        "username": admin_auth.username(),
        "password_hash": admin_auth.password_hash()
    });

    tokio::fs::write(&auth_path, serde_json::to_string_pretty(&data)?).await?;
    Ok(())
}

/// Add a new credential
async fn add_credential(
    config: Config,
    alias: String,
    cred_type: String,
    description: Option<String>,
    key: Option<String>,
    username: Option<String>,
    password: Option<String>,
    header_name: String,
    header_prefix: String,
) -> Result<(), Box<dyn std::error::Error>> {
    let storage = init_storage(&config).await?;

    // Build credential data based on type
    let data = match cred_type.as_str() {
        "api_key" => {
            let key = key.ok_or("API key is required (--key)")?;
            CredentialData::ApiKey {
                key: Secret::new(key),
                header_name,
                header_prefix,
            }
        }
        "basic_auth" => {
            let username = username.ok_or("Username is required (--username)")?;
            let password = if let Some(p) = password {
                p
            } else {
                eprint!("Enter password: ");
                io::stderr().flush()?;
                rpassword::read_password()?
            };
            CredentialData::BasicAuth {
                username,
                password: Secret::new(password),
            }
        }
        other => {
            return Err(format!("Unknown credential type: {}", other).into());
        }
    };

    // Create and store credential
    let mut credential = Credential::new(alias.clone(), data);
    if let Some(desc) = description {
        credential = credential.with_metadata("description", desc);
    }

    storage.store(&credential).await?;

    println!("Credential '{}' added successfully", alias);
    println!("ID: {}", credential.id);

    Ok(())
}

/// List stored credentials
async fn list_credentials(config: Config, format: String) -> Result<(), Box<dyn std::error::Error>> {
    let storage = init_storage(&config).await?;
    let credentials = storage.list().await?;

    if credentials.is_empty() {
        println!("No credentials stored");
        return Ok(());
    }

    match format.as_str() {
        "json" => {
            let json = serde_json::to_string_pretty(&credentials)?;
            println!("{}", json);
        }
        _ => {
            // Table format
            println!("{:<20} {:<15} {:<36} {}", "ALIAS", "TYPE", "ID", "DESCRIPTION");
            println!("{}", "-".repeat(80));
            for cred in credentials {
                let desc = cred
                    .metadata
                    .get("description")
                    .map(|s| s.as_str())
                    .unwrap_or("-");
                println!(
                    "{:<20} {:<15} {:<36} {}",
                    cred.alias,
                    cred.credential_type,
                    cred.id,
                    desc
                );
            }
        }
    }

    Ok(())
}

/// Remove a credential
async fn remove_credential(config: Config, alias: String) -> Result<(), Box<dyn std::error::Error>> {
    let storage = init_storage(&config).await?;

    // Try to find by alias first
    let credential = storage.get_by_alias(&alias).await?;

    let id = if let Some(cred) = credential {
        cred.id
    } else {
        // Assume it's an ID
        alias.clone()
    };

    storage.delete(&id).await?;
    println!("Credential '{}' removed", alias);

    Ok(())
}

/// Show credential info (without secrets)
async fn show_credential_info(config: Config, alias: String) -> Result<(), Box<dyn std::error::Error>> {
    let storage = init_storage(&config).await?;

    // Try to find by alias first
    let credential = storage
        .get_by_alias(&alias)
        .await?
        .or(storage.get(&alias).await?);

    match credential {
        Some(cred) => {
            println!("Alias:      {}", cred.alias);
            println!("ID:         {}", cred.id);
            println!("Type:       {}", cred.credential_type);
            println!("Created:    {}", cred.created_at.format("%Y-%m-%d %H:%M:%S UTC"));
            println!("Updated:    {}", cred.updated_at.format("%Y-%m-%d %H:%M:%S UTC"));

            if !cred.metadata.is_empty() {
                println!("\nMetadata:");
                for (key, value) in &cred.metadata {
                    println!("  {}: {}", key, value);
                }
            }
        }
        None => {
            println!("Credential '{}' not found", alias);
        }
    }

    Ok(())
}

/// Initialize configuration
async fn init_config(force: bool) -> Result<(), Box<dyn std::error::Error>> {
    let config_path = Config::default_path();

    if config_path.exists() && !force {
        return Err(format!(
            "Configuration already exists at {}. Use --force to overwrite.",
            config_path.display()
        )
        .into());
    }

    // Create config directory
    if let Some(parent) = config_path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }

    // Write default configuration
    let default_config = r#"# Vultrino Configuration

[server]
bind = "127.0.0.1:7878"
mode = "local"

[storage]
backend = "file"

[storage.file]
path = "~/.local/share/vultrino/credentials.enc"

[logging]
level = "info"
# audit_file = "~/.local/share/vultrino/audit.log"

[mcp]
enabled = true
transport = "stdio"

# Example policies (uncomment to enable)
# [[policies]]
# name = "github-readonly"
# credential_pattern = "github-*"
# default_action = "deny"
#
# [[policies.rules]]
# condition = { url_match = "https://api.github.com/*" }
# action = "allow"
#
# [[policies.rules]]
# condition = { method_match = ["POST", "PUT", "DELETE"] }
# action = "deny"
"#;

    tokio::fs::write(&config_path, default_config).await?;

    println!("Configuration initialized at {}", config_path.display());

    // Setup admin credentials for web UI
    println!("\n--- Web UI Admin Setup ---");
    println!("Create an admin account for the web interface.\n");

    // Get username
    eprint!("Admin username [admin]: ");
    io::stderr().flush()?;
    let mut username = String::new();
    io::stdin().read_line(&mut username)?;
    let username = username.trim();
    let username = if username.is_empty() { "admin" } else { username };

    // Get password
    eprint!("Admin password: ");
    io::stderr().flush()?;
    let password = rpassword::read_password()?;

    if password.len() < 4 {
        return Err("Password must be at least 4 characters".into());
    }

    // Confirm password
    eprint!("Confirm password: ");
    io::stderr().flush()?;
    let confirm = rpassword::read_password()?;

    if password != confirm {
        return Err("Passwords do not match".into());
    }

    // Create and save admin auth
    let admin_auth = AdminAuth::new(username, &password)?;
    save_admin_auth(&admin_auth).await?;

    println!("\nAdmin account '{}' created.", username);
    println!("\nNext steps:");
    println!("1. Set VULTRINO_PASSWORD environment variable or you'll be prompted");
    println!("2. Add credentials: vultrino add --alias my-api --key <your-key>");
    println!("3. Start server: vultrino serve");
    println!("4. Start web UI: vultrino web");
    println!("5. For LLM integration: vultrino mcp");

    Ok(())
}

// ==================== Role Management ====================

/// Create a new role
async fn create_role(
    config: Config,
    name: String,
    permissions_str: String,
    scopes: Option<String>,
    description: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let storage = init_storage(&config).await?;

    // Parse permissions
    let permissions = Permission::parse_many(&permissions_str)
        .map_err(|e| format!("Invalid permissions: {}", e))?;

    if permissions.is_empty() {
        return Err("At least one permission is required".into());
    }

    // Parse scopes
    let credential_scopes: Vec<String> = scopes
        .map(|s| s.split(',').map(|p| p.trim().to_string()).collect())
        .unwrap_or_default();

    // Create the role
    let auth_manager = AuthManager::new();
    let role = auth_manager
        .create_role(&name, permissions, credential_scopes, description)
        .map_err(|e| format!("Failed to create role: {}", e))?;

    // Store the role
    storage.store_role(&role).await?;

    println!("Role '{}' created successfully", name);
    println!("ID: {}", role.id);
    println!(
        "Permissions: {}",
        role.permissions
            .iter()
            .map(|p| p.to_string())
            .collect::<Vec<_>>()
            .join(", ")
    );
    if !role.credential_scopes.is_empty() {
        println!("Scopes: {}", role.credential_scopes.join(", "));
    }

    Ok(())
}

/// List all roles
async fn list_roles(config: Config, format: String) -> Result<(), Box<dyn std::error::Error>> {
    let storage = init_storage(&config).await?;

    // Load custom roles from storage
    let stored_roles = storage.list_roles().await?;

    // Get predefined roles
    let auth_manager = AuthManager::new();
    let mut all_roles = auth_manager.list_roles();

    // Add stored custom roles
    for role in stored_roles {
        if !all_roles.iter().any(|r| r.name == role.name) {
            all_roles.push(role);
        }
    }

    if all_roles.is_empty() {
        println!("No roles found");
        return Ok(());
    }

    match format.as_str() {
        "json" => {
            let json = serde_json::to_string_pretty(&all_roles)?;
            println!("{}", json);
        }
        _ => {
            println!(
                "{:<20} {:<36} {:<30} {}",
                "NAME", "ID", "PERMISSIONS", "SCOPES"
            );
            println!("{}", "-".repeat(100));
            for role in all_roles {
                let perms: String = role
                    .permissions
                    .iter()
                    .map(|p| p.to_string())
                    .collect::<Vec<_>>()
                    .join(",");
                let scopes = if role.credential_scopes.is_empty() {
                    "(all)".to_string()
                } else {
                    role.credential_scopes.join(",")
                };
                let predefined = if matches!(role.name.as_str(), ROLE_ADMIN | ROLE_READ_ONLY | ROLE_EXECUTOR) {
                    " (built-in)"
                } else {
                    ""
                };
                println!(
                    "{:<20} {:<36} {:<30} {}{}",
                    role.name, role.id, perms, scopes, predefined
                );
            }
        }
    }

    Ok(())
}

/// Delete a role
async fn delete_role(config: Config, name: String) -> Result<(), Box<dyn std::error::Error>> {
    // Check if it's a predefined role
    if matches!(name.as_str(), ROLE_ADMIN | ROLE_READ_ONLY | ROLE_EXECUTOR) {
        return Err(format!("Cannot delete built-in role: {}", name).into());
    }

    let storage = init_storage(&config).await?;

    // Find the role
    let role = storage
        .get_role_by_name(&name)
        .await?
        .ok_or_else(|| format!("Role '{}' not found", name))?;

    storage.delete_role(&role.id).await?;
    println!("Role '{}' deleted", name);

    Ok(())
}

/// Show role info
async fn show_role_info(config: Config, name: String) -> Result<(), Box<dyn std::error::Error>> {
    // Check predefined roles first
    let auth_manager = AuthManager::new();
    let role = if let Some(r) = auth_manager.get_role_by_name(&name) {
        r
    } else {
        // Check storage
        let storage = init_storage(&config).await?;
        storage
            .get_role_by_name(&name)
            .await?
            .ok_or_else(|| format!("Role '{}' not found", name))?
    };

    println!("Name:        {}", role.name);
    println!("ID:          {}", role.id);
    if let Some(desc) = &role.description {
        println!("Description: {}", desc);
    }
    println!(
        "Permissions: {}",
        role.permissions
            .iter()
            .map(|p| p.to_string())
            .collect::<Vec<_>>()
            .join(", ")
    );
    if role.credential_scopes.is_empty() {
        println!("Scopes:      (all credentials)");
    } else {
        println!("Scopes:      {}", role.credential_scopes.join(", "));
    }
    println!(
        "Created:     {}",
        role.created_at.format("%Y-%m-%d %H:%M:%S UTC")
    );

    let is_builtin = matches!(role.name.as_str(), ROLE_ADMIN | ROLE_READ_ONLY | ROLE_EXECUTOR);
    if is_builtin {
        println!("Type:        Built-in (cannot be deleted)");
    }

    Ok(())
}

// ==================== API Key Management ====================

/// Parse expiration duration
fn parse_expiration(s: &str) -> Result<Option<Duration>, String> {
    let s = s.trim().to_lowercase();
    if s == "never" || s.is_empty() {
        return Ok(None);
    }

    // Parse formats like "30d", "24h", "1w"
    let (num_str, unit) = if s.ends_with('d') {
        (&s[..s.len() - 1], "d")
    } else if s.ends_with('h') {
        (&s[..s.len() - 1], "h")
    } else if s.ends_with('w') {
        (&s[..s.len() - 1], "w")
    } else if s.ends_with('m') {
        (&s[..s.len() - 1], "m")
    } else {
        return Err(format!("Invalid duration format: {}. Use format like '30d', '24h', '1w'", s));
    };

    let num: i64 = num_str
        .parse()
        .map_err(|_| format!("Invalid number: {}", num_str))?;

    let duration = match unit {
        "h" => Duration::hours(num),
        "d" => Duration::days(num),
        "w" => Duration::weeks(num),
        "m" => Duration::days(num * 30), // Approximate month
        _ => unreachable!(),
    };

    Ok(Some(duration))
}

/// Create a new API key
async fn create_api_key(
    config: Config,
    name: String,
    role: String,
    expires: String,
) -> Result<(), Box<dyn std::error::Error>> {
    let storage = init_storage(&config).await?;

    // Parse expiration
    let expires_in = parse_expiration(&expires)?;

    // Load existing data and create auth manager
    let stored_roles = storage.list_roles().await?;
    let stored_keys = storage.list_api_keys().await?;
    let auth_manager = AuthManager::from_data(stored_roles, stored_keys);

    // Verify role exists
    if auth_manager.get_role_by_name(&role).is_none() {
        return Err(format!(
            "Role '{}' not found. Use 'vultrino role list' to see available roles.",
            role
        )
        .into());
    }

    // Create the key
    let (full_key, api_key) = auth_manager
        .create_api_key(&name, &role, expires_in)
        .map_err(|e| format!("Failed to create API key: {}", e))?;

    // Store the key
    storage.store_api_key(&api_key).await?;

    println!("API key created successfully!\n");
    println!("Key: {}", full_key);
    println!("\n*** SAVE THIS KEY - IT WILL NOT BE SHOWN AGAIN ***\n");
    println!("Name:    {}", api_key.name);
    println!("ID:      {}", api_key.id);
    println!("Role:    {}", role);
    if let Some(expires_at) = api_key.expires_at {
        println!("Expires: {}", expires_at.format("%Y-%m-%d %H:%M:%S UTC"));
    } else {
        println!("Expires: Never");
    }

    println!("\nUsage:");
    println!("  curl -H \"Authorization: Bearer {}\" ...", full_key);

    Ok(())
}

/// List all API keys
async fn list_api_keys(config: Config, format: String) -> Result<(), Box<dyn std::error::Error>> {
    let storage = init_storage(&config).await?;
    let keys = storage.list_api_keys().await?;

    if keys.is_empty() {
        println!("No API keys found");
        return Ok(());
    }

    // Load roles to show names
    let stored_roles = storage.list_roles().await?;
    let auth_manager = AuthManager::from_data(stored_roles, vec![]);

    match format.as_str() {
        "json" => {
            let metadata: Vec<vultrino::auth::ApiKeyMetadata> =
                keys.iter().map(|k| k.into()).collect();
            let json = serde_json::to_string_pretty(&metadata)?;
            println!("{}", json);
        }
        _ => {
            println!(
                "{:<20} {:<12} {:<20} {:<20} {}",
                "NAME", "KEY PREFIX", "ROLE", "EXPIRES", "LAST USED"
            );
            println!("{}", "-".repeat(90));
            for key in keys {
                let role_name = auth_manager
                    .get_role(&key.role_id)
                    .map(|r| r.name)
                    .unwrap_or_else(|| key.role_id.clone());
                let expires = key
                    .expires_at
                    .map(|e| e.format("%Y-%m-%d").to_string())
                    .unwrap_or_else(|| "Never".to_string());
                let last_used = key
                    .last_used_at
                    .map(|t| t.format("%Y-%m-%d %H:%M").to_string())
                    .unwrap_or_else(|| "Never".to_string());

                println!(
                    "{:<20} {:<12} {:<20} {:<20} {}",
                    key.name,
                    format!("{}...", key.key_prefix),
                    role_name,
                    expires,
                    last_used
                );
            }
        }
    }

    Ok(())
}

/// Revoke an API key
async fn revoke_api_key(config: Config, id: String) -> Result<(), Box<dyn std::error::Error>> {
    let storage = init_storage(&config).await?;
    let keys = storage.list_api_keys().await?;

    // Find key by ID or prefix
    let key = keys
        .iter()
        .find(|k| k.id == id || k.key_prefix.contains(&id))
        .ok_or_else(|| format!("API key '{}' not found", id))?;

    let key_name = key.name.clone();
    let key_id = key.id.clone();

    storage.delete_api_key(&key_id).await?;
    println!("API key '{}' (ID: {}) revoked", key_name, key_id);

    Ok(())
}

// ==================== HTTP Request ====================

/// Make an authenticated HTTP request
async fn make_request(
    config: Config,
    credential: String,
    url: String,
    method: String,
    data: Option<String>,
    headers: Vec<String>,
    quiet: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let storage = init_storage(&config).await?;
    let resolver = CredentialResolver::new(storage.clone());
    let server = VultrinoServer::new(config, storage, resolver);

    // Load installed plugins
    server.load_plugins().await?;

    // Parse headers
    let mut headers_map = std::collections::HashMap::new();
    for header in headers {
        if let Some((key, value)) = header.split_once(':') {
            headers_map.insert(key.trim().to_string(), value.trim().to_string());
        }
    }

    // Parse body - support @filename syntax
    let body: Option<serde_json::Value> = if let Some(data_str) = data {
        if data_str.starts_with('@') {
            // Read from file
            let filename = &data_str[1..];
            let content = tokio::fs::read_to_string(filename).await?;
            Some(serde_json::from_str(&content)?)
        } else {
            // Parse as JSON
            Some(serde_json::from_str(&data_str)?)
        }
    } else {
        None
    };

    // Build request
    let request = ExecuteRequest {
        credential: credential.clone(),
        action: "http.request".to_string(),
        params: serde_json::json!({
            "method": method.to_uppercase(),
            "url": url,
            "headers": headers_map,
            "body": body,
        }),
    };

    // Execute
    let response = server.execute(request).await?;

    // Output
    if quiet {
        // Just the body
        let body_text = String::from_utf8_lossy(&response.body);
        print!("{}", body_text);
    } else {
        // Status and body
        let status_emoji = if response.status >= 200 && response.status < 300 {
            "+"
        } else if response.status >= 400 {
            "!"
        } else {
            ">"
        };

        eprintln!("[{}] {} {} -> {}", status_emoji, method.to_uppercase(), url, response.status);

        // Pretty print JSON if possible
        let body_text = String::from_utf8_lossy(&response.body);
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&body_text) {
            println!("{}", serde_json::to_string_pretty(&json)?);
        } else {
            println!("{}", body_text);
        }
    }

    Ok(())
}

// ==================== Plugin Actions ====================

/// Execute a plugin action
async fn execute_action(
    config: Config,
    credential: String,
    action: String,
    params: Option<String>,
    quiet: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let storage = init_storage(&config).await?;
    let resolver = CredentialResolver::new(storage.clone());
    let server = VultrinoServer::new(config, storage, resolver);

    // Load installed plugins
    server.load_plugins().await?;

    // Parse params
    let params_json: serde_json::Value = if let Some(p) = params {
        serde_json::from_str(&p)?
    } else {
        serde_json::json!({})
    };

    // Build request
    let request = ExecuteRequest {
        credential: credential.clone(),
        action: action.clone(),
        params: params_json,
    };

    // Execute
    let response = server.execute(request).await?;

    // Output
    if quiet {
        let body_text = String::from_utf8_lossy(&response.body);
        print!("{}", body_text);
    } else {
        let status_emoji = if response.status >= 200 && response.status < 300 {
            "+"
        } else {
            "!"
        };

        eprintln!("[{}] {} -> {}", status_emoji, action, response.status);

        // Pretty print JSON if possible
        let body_text = String::from_utf8_lossy(&response.body);
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&body_text) {
            println!("{}", serde_json::to_string_pretty(&json)?);
        } else {
            println!("{}", body_text);
        }
    }

    Ok(())
}

// ==================== Plugin Management ====================

/// Install a plugin
async fn install_plugin(source: String) -> Result<(), Box<dyn std::error::Error>> {
    let installer = PluginInstaller::default();

    println!("Installing plugin from: {}", source);

    let info = installer.install(&source).await?;

    println!("\nPlugin installed successfully!");
    println!("Name:    {}", info.manifest.plugin.name);
    println!("Version: {}", info.manifest.plugin.version);
    if let Some(desc) = &info.manifest.plugin.description {
        println!("Description: {}", desc);
    }
    println!("Location: {}", info.directory.display());

    if !info.manifest.credential_types.is_empty() {
        println!("\nCredential types:");
        for ct in &info.manifest.credential_types {
            println!("  - {} ({})", ct.display_name, ct.name);
        }
    }

    if !info.manifest.actions.is_empty() {
        println!("\nActions:");
        for action in &info.manifest.actions {
            let desc = action.description.as_deref().unwrap_or("-");
            println!("  - {}: {}", action.name, desc);
        }
    }

    if !info.manifest.mcp_tools.is_empty() {
        println!("\nMCP tools:");
        for tool in &info.manifest.mcp_tools {
            let desc = tool.description.as_deref().unwrap_or("-");
            println!("  - {}: {}", tool.name, desc);
        }
    }

    Ok(())
}

/// List installed plugins
async fn list_plugins(format: String) -> Result<(), Box<dyn std::error::Error>> {
    let installer = PluginInstaller::default();
    let plugins = installer.list().await?;

    if plugins.is_empty() {
        println!("No plugins installed");
        println!("\nTo install a plugin:");
        println!("  vultrino plugin install <path-or-url>");
        return Ok(());
    }

    match format.as_str() {
        "json" => {
            let json = serde_json::to_string_pretty(&plugins)?;
            println!("{}", json);
        }
        _ => {
            println!(
                "{:<20} {:<10} {:<30} {}",
                "NAME", "VERSION", "SOURCE", "CREDENTIAL TYPES"
            );
            println!("{}", "-".repeat(90));
            for plugin in plugins {
                let cred_types: String = plugin
                    .manifest
                    .credential_types
                    .iter()
                    .map(|ct| ct.name.clone())
                    .collect::<Vec<_>>()
                    .join(", ");
                let cred_types = if cred_types.is_empty() {
                    "-".to_string()
                } else {
                    cred_types
                };
                let source = if plugin.source.len() > 28 {
                    format!("{}...", &plugin.source[..25])
                } else {
                    plugin.source.clone()
                };
                println!(
                    "{:<20} {:<10} {:<30} {}",
                    plugin.manifest.plugin.name,
                    plugin.manifest.plugin.version,
                    source,
                    cred_types
                );
            }
        }
    }

    Ok(())
}

/// Remove a plugin
async fn remove_plugin(name: String) -> Result<(), Box<dyn std::error::Error>> {
    let installer = PluginInstaller::default();

    // Confirm removal
    eprint!("Remove plugin '{}'? [y/N] ", name);
    io::stderr().flush()?;
    let mut confirm = String::new();
    io::stdin().read_line(&mut confirm)?;

    if confirm.trim().to_lowercase() != "y" {
        println!("Cancelled");
        return Ok(());
    }

    installer.remove(&name).await?;
    println!("Plugin '{}' removed", name);

    Ok(())
}

/// Show plugin info
async fn show_plugin_info(name: String) -> Result<(), Box<dyn std::error::Error>> {
    let installer = PluginInstaller::default();

    let info = installer
        .get(&name)
        .await?
        .ok_or_else(|| format!("Plugin '{}' not found", name))?;

    println!("Name:        {}", info.manifest.plugin.name);
    println!("Version:     {}", info.manifest.plugin.version);
    if let Some(desc) = &info.manifest.plugin.description {
        println!("Description: {}", desc);
    }
    if let Some(author) = &info.manifest.plugin.author {
        println!("Author:      {}", author);
    }
    if let Some(license) = &info.manifest.plugin.license {
        println!("License:     {}", license);
    }
    if let Some(homepage) = &info.manifest.plugin.homepage {
        println!("Homepage:    {}", homepage);
    }
    println!("Source:      {}", info.source);
    println!("Installed:   {}", info.installed_at.format("%Y-%m-%d %H:%M:%S UTC"));
    println!("Enabled:     {}", if info.enabled { "yes" } else { "no" });
    println!("Location:    {}", info.directory.display());

    if !info.manifest.credential_types.is_empty() {
        println!("\nCredential Types:");
        for ct in &info.manifest.credential_types {
            println!("  {} ({})", ct.display_name, ct.name);
            if let Some(desc) = &ct.description {
                println!("    {}", desc);
            }
            println!("    Fields:");
            for field in &ct.fields {
                let req = if field.required { "*" } else { "" };
                let secret = if field.secret { " [secret]" } else { "" };
                println!("      - {}{}: {:?}{}", field.name, req, field.field_type, secret);
            }
        }
    }

    if !info.manifest.actions.is_empty() {
        println!("\nActions:");
        for action in &info.manifest.actions {
            let desc = action.description.as_deref().unwrap_or("");
            println!("  - {}: {}", action.name, desc);
        }
    }

    if !info.manifest.mcp_tools.is_empty() {
        println!("\nMCP Tools:");
        for tool in &info.manifest.mcp_tools {
            let desc = tool.description.as_deref().unwrap_or("");
            println!("  - {} -> {} : {}", tool.name, tool.action, desc);
        }
    }

    Ok(())
}

/// Reload a plugin
async fn reload_plugin(name: String) -> Result<(), Box<dyn std::error::Error>> {
    // Note: This would require access to the running server's plugin registry
    // For now, we just verify the plugin exists and can be loaded
    let installer = PluginInstaller::default();

    let info = installer
        .get(&name)
        .await?
        .ok_or_else(|| format!("Plugin '{}' not found", name))?;

    // Try to load the plugin to verify it works
    let loader = vultrino::plugins::PluginLoader::default();
    loader.load_plugin(&info.directory).await?;

    println!("Plugin '{}' validated successfully", name);
    println!("Note: Hot-reload is only effective for running servers");

    Ok(())
}
