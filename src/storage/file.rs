//! Encrypted file-based storage backend
//!
//! Stores credentials in an encrypted JSON file on disk.

use super::{StorageBackend, StorageError};
use crate::auth::{ApiKey, Role};
use crate::crypto::{decrypt, derive_key, encrypt, generate_salt, EncryptedData, MasterKey};
use crate::{Credential, CredentialMetadata};
use async_trait::async_trait;
use chrono::Utc;
use parking_lot::RwLock;
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use tokio::fs;

/// File-based storage with AES-256-GCM encryption
pub struct FileStorage {
    /// Path to the storage file
    path: PathBuf,
    /// Master encryption key
    master_key: MasterKey,
    /// In-memory cache of credentials
    cache: RwLock<StorageCache>,
    /// Salt used for key derivation (stored in file)
    salt: Vec<u8>,
}

/// In-memory cache of all storage data
#[derive(Debug, Default, Serialize, Deserialize)]
struct StorageCache {
    /// Credentials by ID
    credentials: HashMap<String, Credential>,
    /// Roles by ID
    #[serde(default)]
    roles: HashMap<String, Role>,
    /// API keys by ID
    #[serde(default)]
    api_keys: HashMap<String, ApiKey>,

    // Secondary indexes for O(1) lookups (not serialized, rebuilt on load)
    /// Index: credential alias -> credential ID
    #[serde(skip)]
    alias_index: HashMap<String, String>,
    /// Index: role name -> role ID
    #[serde(skip)]
    role_name_index: HashMap<String, String>,
    /// Index: API key hash -> API key ID
    #[serde(skip)]
    api_key_hash_index: HashMap<String, String>,
}

impl StorageCache {
    /// Rebuild all secondary indexes from primary data
    fn rebuild_indexes(&mut self) {
        // Clear existing indexes
        self.alias_index.clear();
        self.role_name_index.clear();
        self.api_key_hash_index.clear();

        // Rebuild credential alias index
        for (id, cred) in &self.credentials {
            self.alias_index.insert(cred.alias.clone(), id.clone());
        }

        // Rebuild role name index
        for (id, role) in &self.roles {
            self.role_name_index.insert(role.name.clone(), id.clone());
        }

        // Rebuild API key hash index
        for (id, key) in &self.api_keys {
            self.api_key_hash_index.insert(key.key_hash.clone(), id.clone());
        }
    }
}

/// On-disk format for the storage file
#[derive(Debug, Serialize, Deserialize)]
struct StorageFile {
    /// Version for future migrations
    version: u32,
    /// Salt for key derivation
    salt: String,
    /// Encrypted data (credentials, roles, api_keys)
    #[serde(alias = "credentials")]
    data: EncryptedData,
}

impl FileStorage {
    /// Create a new file storage, loading existing data if present
    pub async fn new(path: impl AsRef<Path>, password: &SecretString) -> Result<Self, StorageError> {
        let path = path.as_ref().to_path_buf();

        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).await?;
        }

        // Check if file exists
        if path.exists() {
            // Load existing storage
            Self::load(path, password).await
        } else {
            // Create new storage
            Self::create(path, password).await
        }
    }

    /// Create a new storage file
    async fn create(path: PathBuf, password: &SecretString) -> Result<Self, StorageError> {
        let salt = generate_salt();
        let master_key = derive_key(password, &salt)?;

        let storage = Self {
            path,
            master_key,
            cache: RwLock::new(StorageCache::default()),
            salt,
        };

        // Write initial empty storage
        storage.save().await?;

        Ok(storage)
    }

    /// Load an existing storage file
    async fn load(path: PathBuf, password: &SecretString) -> Result<Self, StorageError> {
        let content = fs::read_to_string(&path).await?;
        let storage_file: StorageFile = serde_json::from_str(&content)
            .map_err(|e| StorageError::Serialization(e.to_string()))?;

        // Decode salt
        let salt = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            &storage_file.salt,
        )
        .map_err(|e| StorageError::Serialization(format!("Invalid salt: {}", e)))?;

        // Derive key from password
        let master_key = derive_key(password, &salt)?;

        // Decrypt data
        let decrypted = decrypt(&storage_file.data, &master_key)?;

        // Try to parse as new format (StorageCache), fall back to old format (just credentials)
        let mut cache: StorageCache = serde_json::from_slice(&decrypted)
            .or_else(|_| {
                // Try old format: just a HashMap of credentials
                let credentials: HashMap<String, Credential> = serde_json::from_slice(&decrypted)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                Ok::<_, StorageError>(StorageCache {
                    credentials,
                    roles: HashMap::new(),
                    api_keys: HashMap::new(),
                    alias_index: HashMap::new(),
                    role_name_index: HashMap::new(),
                    api_key_hash_index: HashMap::new(),
                })
            })?;

        // Rebuild secondary indexes from loaded data
        cache.rebuild_indexes();

        Ok(Self {
            path,
            master_key,
            cache: RwLock::new(cache),
            salt,
        })
    }

    /// Reload data from disk (for picking up external changes)
    pub async fn reload(&self) -> Result<(), StorageError> {
        let content = fs::read_to_string(&self.path).await?;
        let storage_file: StorageFile = serde_json::from_str(&content)
            .map_err(|e| StorageError::Serialization(e.to_string()))?;

        // Decrypt data
        let decrypted = decrypt(&storage_file.data, &self.master_key)?;

        // Parse as StorageCache
        let mut cache: StorageCache = serde_json::from_slice(&decrypted)
            .or_else(|_| {
                // Try old format: just a HashMap of credentials
                let credentials: HashMap<String, Credential> = serde_json::from_slice(&decrypted)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                Ok::<_, StorageError>(StorageCache {
                    credentials,
                    roles: HashMap::new(),
                    api_keys: HashMap::new(),
                    alias_index: HashMap::new(),
                    role_name_index: HashMap::new(),
                    api_key_hash_index: HashMap::new(),
                })
            })?;

        // Rebuild secondary indexes from loaded data
        cache.rebuild_indexes();

        // Update cache
        *self.cache.write() = cache;

        Ok(())
    }

    /// Save the current state to disk
    async fn save(&self) -> Result<(), StorageError> {
        let data = {
            let cache = self.cache.read();
            serde_json::to_vec(&*cache)
                .map_err(|e| StorageError::Serialization(e.to_string()))?
        };

        // Encrypt data
        let encrypted = encrypt(&data, &self.master_key)?;

        let storage_file = StorageFile {
            version: 2, // Bump version for new format
            salt: base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                &self.salt,
            ),
            data: encrypted,
        };

        let content = serde_json::to_string_pretty(&storage_file)
            .map_err(|e| StorageError::Serialization(e.to_string()))?;

        // Write atomically by writing to temp file first
        let temp_path = self.path.with_extension("tmp");
        fs::write(&temp_path, &content).await?;
        fs::rename(&temp_path, &self.path).await?;

        Ok(())
    }
}

#[async_trait]
impl StorageBackend for FileStorage {
    async fn store(&self, credential: &Credential) -> Result<(), StorageError> {
        {
            let mut cache = self.cache.write();

            // Check for duplicate alias using index (O(1) lookup)
            if let Some(existing_id) = cache.alias_index.get(&credential.alias) {
                if existing_id != &credential.id {
                    return Err(StorageError::AlreadyExists(credential.alias.clone()));
                }
            }

            // Update index
            cache.alias_index.insert(credential.alias.clone(), credential.id.clone());
            cache.credentials.insert(credential.id.clone(), credential.clone());
        }

        self.save().await
    }

    async fn get(&self, id: &str) -> Result<Option<Credential>, StorageError> {
        let cache = self.cache.read();
        Ok(cache.credentials.get(id).cloned())
    }

    async fn get_by_alias(&self, alias: &str) -> Result<Option<Credential>, StorageError> {
        let cache = self.cache.read();
        // O(1) lookup using index
        if let Some(id) = cache.alias_index.get(alias) {
            Ok(cache.credentials.get(id).cloned())
        } else {
            Ok(None)
        }
    }

    async fn list(&self) -> Result<Vec<CredentialMetadata>, StorageError> {
        let cache = self.cache.read();
        Ok(cache.credentials.values().map(CredentialMetadata::from).collect())
    }

    async fn delete(&self, id: &str) -> Result<(), StorageError> {
        {
            let mut cache = self.cache.write();
            if let Some(cred) = cache.credentials.remove(id) {
                // Remove from alias index
                cache.alias_index.remove(&cred.alias);
            } else {
                return Err(StorageError::NotFound(id.to_string()));
            }
        }

        self.save().await
    }

    async fn update(&self, credential: &Credential) -> Result<(), StorageError> {
        {
            let mut cache = self.cache.write();
            let old_cred = cache.credentials.get(&credential.id)
                .ok_or_else(|| StorageError::NotFound(credential.id.clone()))?
                .clone();

            // Check for duplicate alias using index (O(1) lookup)
            if let Some(existing_id) = cache.alias_index.get(&credential.alias) {
                if existing_id != &credential.id {
                    return Err(StorageError::AlreadyExists(credential.alias.clone()));
                }
            }

            // Update alias index if alias changed
            if old_cred.alias != credential.alias {
                cache.alias_index.remove(&old_cred.alias);
                cache.alias_index.insert(credential.alias.clone(), credential.id.clone());
            }

            cache.credentials.insert(credential.id.clone(), credential.clone());
        }

        self.save().await
    }

    async fn health_check(&self) -> Result<(), StorageError> {
        // Check if we can read the storage file
        if !self.path.exists() {
            return Err(StorageError::Unavailable(
                "Storage file does not exist".to_string(),
            ));
        }

        // Try to read the file
        fs::metadata(&self.path).await?;

        Ok(())
    }

    // ==================== Auth Storage ====================

    async fn store_role(&self, role: &Role) -> Result<(), StorageError> {
        {
            let mut cache = self.cache.write();

            // Check for duplicate name using index (O(1) lookup)
            if let Some(existing_id) = cache.role_name_index.get(&role.name) {
                if existing_id != &role.id {
                    return Err(StorageError::RoleAlreadyExists(role.name.clone()));
                }
            }

            // Update index
            cache.role_name_index.insert(role.name.clone(), role.id.clone());
            cache.roles.insert(role.id.clone(), role.clone());
        }

        self.save().await
    }

    async fn get_role(&self, id: &str) -> Result<Option<Role>, StorageError> {
        let cache = self.cache.read();
        Ok(cache.roles.get(id).cloned())
    }

    async fn get_role_by_name(&self, name: &str) -> Result<Option<Role>, StorageError> {
        let cache = self.cache.read();
        // O(1) lookup using index
        if let Some(id) = cache.role_name_index.get(name) {
            Ok(cache.roles.get(id).cloned())
        } else {
            Ok(None)
        }
    }

    async fn list_roles(&self) -> Result<Vec<Role>, StorageError> {
        let cache = self.cache.read();
        Ok(cache.roles.values().cloned().collect())
    }

    async fn delete_role(&self, id: &str) -> Result<(), StorageError> {
        {
            let mut cache = self.cache.write();
            if let Some(role) = cache.roles.remove(id) {
                // Remove from name index
                cache.role_name_index.remove(&role.name);
            } else {
                return Err(StorageError::RoleNotFound(id.to_string()));
            }
        }

        self.save().await
    }

    async fn store_api_key(&self, key: &ApiKey) -> Result<(), StorageError> {
        {
            let mut cache = self.cache.write();
            // Update index
            cache.api_key_hash_index.insert(key.key_hash.clone(), key.id.clone());
            cache.api_keys.insert(key.id.clone(), key.clone());
        }

        self.save().await
    }

    async fn get_api_key_by_hash(&self, hash: &str) -> Result<Option<ApiKey>, StorageError> {
        let cache = self.cache.read();
        // O(1) lookup using index
        if let Some(id) = cache.api_key_hash_index.get(hash) {
            Ok(cache.api_keys.get(id).cloned())
        } else {
            Ok(None)
        }
    }

    async fn list_api_keys(&self) -> Result<Vec<ApiKey>, StorageError> {
        let cache = self.cache.read();
        Ok(cache.api_keys.values().cloned().collect())
    }

    async fn delete_api_key(&self, id: &str) -> Result<(), StorageError> {
        {
            let mut cache = self.cache.write();
            if let Some(key) = cache.api_keys.remove(id) {
                // Remove from hash index
                cache.api_key_hash_index.remove(&key.key_hash);
            } else {
                return Err(StorageError::ApiKeyNotFound(id.to_string()));
            }
        }

        self.save().await
    }

    async fn update_api_key_last_used(&self, id: &str) -> Result<(), StorageError> {
        {
            let mut cache = self.cache.write();
            if let Some(key) = cache.api_keys.get_mut(id) {
                key.last_used_at = Some(Utc::now());
            } else {
                return Err(StorageError::ApiKeyNotFound(id.to_string()));
            }
        }

        self.save().await
    }

    async fn reload(&self) -> Result<(), StorageError> {
        // Call the inherent reload method
        FileStorage::reload(self).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::Permission;
    use crate::{CredentialData, Secret};
    use std::collections::HashSet;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_file_storage_roundtrip() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.enc");
        let password = SecretString::from("test-password");

        // Create storage and add credential
        {
            let storage = FileStorage::new(&path, &password).await.unwrap();

            let cred = Credential::new(
                "test-api".to_string(),
                CredentialData::ApiKey {
                    key: Secret::new("secret-key-123"),
                    header_name: "Authorization".to_string(),
                    header_prefix: "Bearer ".to_string(),
                },
            );

            storage.store(&cred).await.unwrap();
        }

        // Reload and verify
        {
            let storage = FileStorage::new(&path, &password).await.unwrap();

            let cred = storage.get_by_alias("test-api").await.unwrap();
            assert!(cred.is_some());

            let cred = cred.unwrap();
            assert_eq!(cred.alias, "test-api");
        }
    }

    #[tokio::test]
    async fn test_wrong_password_fails() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.enc");

        // Create with one password
        {
            let password = SecretString::from("password1");
            let storage = FileStorage::new(&path, &password).await.unwrap();

            let cred = Credential::new(
                "test".to_string(),
                CredentialData::BasicAuth {
                    username: "user".to_string(),
                    password: Secret::new("pass"),
                },
            );
            storage.store(&cred).await.unwrap();
        }

        // Try to load with wrong password
        let password = SecretString::from("password2");
        let result = FileStorage::new(&path, &password).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_duplicate_alias_rejected() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.enc");
        let password = SecretString::from("test");

        let storage = FileStorage::new(&path, &password).await.unwrap();

        let cred1 = Credential::new(
            "my-api".to_string(),
            CredentialData::ApiKey {
                key: Secret::new("key1"),
                header_name: "Authorization".to_string(),
                header_prefix: "Bearer ".to_string(),
            },
        );

        let cred2 = Credential::new(
            "my-api".to_string(),
            CredentialData::ApiKey {
                key: Secret::new("key2"),
                header_name: "Authorization".to_string(),
                header_prefix: "Bearer ".to_string(),
            },
        );

        storage.store(&cred1).await.unwrap();
        let result = storage.store(&cred2).await;
        assert!(matches!(result, Err(StorageError::AlreadyExists(_))));
    }

    #[tokio::test]
    async fn test_list_credentials() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.enc");
        let password = SecretString::from("test");

        let storage = FileStorage::new(&path, &password).await.unwrap();

        for i in 0..3 {
            let cred = Credential::new(
                format!("api-{}", i),
                CredentialData::ApiKey {
                    key: Secret::new(format!("key-{}", i)),
                    header_name: "Authorization".to_string(),
                    header_prefix: "Bearer ".to_string(),
                },
            );
            storage.store(&cred).await.unwrap();
        }

        let list = storage.list().await.unwrap();
        assert_eq!(list.len(), 3);
    }

    #[tokio::test]
    async fn test_role_storage() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.enc");
        let password = SecretString::from("test");

        let storage = FileStorage::new(&path, &password).await.unwrap();

        let mut permissions = HashSet::new();
        permissions.insert(Permission::Read);
        permissions.insert(Permission::Execute);

        let role = Role {
            id: "role-1".to_string(),
            name: "test-role".to_string(),
            description: Some("Test role".to_string()),
            permissions,
            credential_scopes: vec!["github-*".to_string()],
            created_at: Utc::now(),
        };

        storage.store_role(&role).await.unwrap();

        let loaded = storage.get_role_by_name("test-role").await.unwrap();
        assert!(loaded.is_some());
        assert_eq!(loaded.unwrap().name, "test-role");
    }

    #[tokio::test]
    async fn test_api_key_storage() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.enc");
        let password = SecretString::from("test");

        let storage = FileStorage::new(&path, &password).await.unwrap();

        let key = ApiKey {
            id: "key-1".to_string(),
            key_prefix: "vk_abc12".to_string(),
            key_hash: "hash123".to_string(),
            name: "test-key".to_string(),
            role_id: "role-1".to_string(),
            expires_at: None,
            created_at: Utc::now(),
            last_used_at: None,
        };

        storage.store_api_key(&key).await.unwrap();

        let loaded = storage.get_api_key_by_hash("hash123").await.unwrap();
        assert!(loaded.is_some());
        assert_eq!(loaded.unwrap().name, "test-key");

        // Test update last used
        storage.update_api_key_last_used("key-1").await.unwrap();
        let updated = storage.get_api_key_by_hash("hash123").await.unwrap().unwrap();
        assert!(updated.last_used_at.is_some());
    }
}
