//! HTTP authentication plugin
//!
//! Handles HTTP requests with credential injection:
//! - API Key authentication (Bearer tokens, custom headers)
//! - Basic Authentication
//! - OAuth2 (token refresh, etc.)

use super::{Plugin, PluginError, PluginRequest};
use crate::{CredentialData, CredentialType, ExecuteResponse};
use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD, Engine};
use reqwest::{Client, Method};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::str::FromStr;

/// HTTP plugin for API authentication
pub struct HttpPlugin {
    client: Client,
}

/// Parameters for HTTP request action
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpRequestParams {
    /// HTTP method (GET, POST, PUT, DELETE, etc.)
    pub method: String,
    /// Target URL
    pub url: String,
    /// Request headers (optional)
    #[serde(default)]
    pub headers: HashMap<String, String>,
    /// Request body (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body: Option<serde_json::Value>,
    /// Query parameters (optional)
    #[serde(default)]
    pub query: HashMap<String, String>,
}

impl HttpPlugin {
    /// Create a new HTTP plugin
    pub fn new() -> Self {
        let client = Client::builder()
            .user_agent("vultrino/0.1.0")
            .build()
            .expect("Failed to create HTTP client");

        Self { client }
    }

    /// Inject credentials into request headers
    fn inject_credentials(
        &self,
        headers: &mut HashMap<String, String>,
        cred_data: &CredentialData,
    ) -> Result<(), PluginError> {
        match cred_data {
            CredentialData::ApiKey {
                key,
                header_name,
                header_prefix,
            } => {
                let value = format!("{}{}", header_prefix, key.expose());
                headers.insert(header_name.clone(), value);
            }

            CredentialData::BasicAuth { username, password } => {
                let credentials = format!("{}:{}", username, password.expose());
                let encoded = STANDARD.encode(credentials.as_bytes());
                headers.insert("Authorization".to_string(), format!("Basic {}", encoded));
            }

            CredentialData::OAuth2 { access_token, .. } => {
                if let Some(token) = access_token {
                    headers.insert(
                        "Authorization".to_string(),
                        format!("Bearer {}", token.expose()),
                    );
                } else {
                    return Err(PluginError::ExecutionFailed(
                        "OAuth2 credential has no access token".to_string(),
                    ));
                }
            }

            _ => {
                return Err(PluginError::UnsupportedCredentialType(
                    "HTTP plugin only supports ApiKey, BasicAuth, and OAuth2".to_string(),
                ));
            }
        }

        Ok(())
    }

    /// Execute an HTTP request
    async fn execute_request(
        &self,
        params: HttpRequestParams,
        cred_data: &CredentialData,
    ) -> Result<ExecuteResponse, PluginError> {
        // Parse method
        let method = Method::from_str(&params.method.to_uppercase())
            .map_err(|_| PluginError::InvalidParams(format!("Invalid HTTP method: {}", params.method)))?;

        // Build headers with credential injection
        let mut headers = params.headers;
        self.inject_credentials(&mut headers, cred_data)?;

        // Build request
        let mut request = self.client.request(method, &params.url);

        // Add headers
        for (key, value) in &headers {
            request = request.header(key, value);
        }

        // Add query parameters
        if !params.query.is_empty() {
            request = request.query(&params.query);
        }

        // Add body
        if let Some(body) = params.body {
            request = request.json(&body);
        }

        // Execute request
        let response = request
            .send()
            .await
            .map_err(|e| PluginError::Http(e.to_string()))?;

        // Extract response details
        let status = response.status().as_u16();
        let response_headers: HashMap<String, String> = response
            .headers()
            .iter()
            .filter_map(|(k, v)| {
                v.to_str()
                    .ok()
                    .map(|v| (k.as_str().to_string(), v.to_string()))
            })
            .collect();

        let body = response
            .bytes()
            .await
            .map_err(|e| PluginError::Http(e.to_string()))?
            .to_vec();

        Ok(ExecuteResponse {
            status,
            headers: response_headers,
            body,
        })
    }
}

impl Default for HttpPlugin {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Plugin for HttpPlugin {
    fn name(&self) -> &str {
        "http"
    }

    fn supported_credential_types(&self) -> Vec<CredentialType> {
        vec![
            CredentialType::ApiKey,
            CredentialType::BasicAuth,
            CredentialType::OAuth2,
        ]
    }

    fn supported_actions(&self) -> Vec<&str> {
        vec!["request"]
    }

    async fn execute(&self, request: PluginRequest) -> Result<ExecuteResponse, PluginError> {
        match request.action.as_str() {
            "request" => {
                let params: HttpRequestParams = serde_json::from_value(request.params)
                    .map_err(|e| PluginError::InvalidParams(e.to_string()))?;

                self.execute_request(params, &request.credential.data).await
            }
            _ => Err(PluginError::UnsupportedAction(request.action)),
        }
    }

    fn validate_params(
        &self,
        action: &str,
        params: &serde_json::Value,
    ) -> Result<(), PluginError> {
        match action {
            "request" => {
                // Validate required fields
                let obj = params
                    .as_object()
                    .ok_or_else(|| PluginError::InvalidParams("Expected object".to_string()))?;

                if !obj.contains_key("method") {
                    return Err(PluginError::InvalidParams("Missing 'method' field".to_string()));
                }

                if !obj.contains_key("url") {
                    return Err(PluginError::InvalidParams("Missing 'url' field".to_string()));
                }

                // Validate method is valid
                let method = obj["method"]
                    .as_str()
                    .ok_or_else(|| PluginError::InvalidParams("'method' must be a string".to_string()))?;

                Method::from_str(&method.to_uppercase())
                    .map_err(|_| PluginError::InvalidParams(format!("Invalid HTTP method: {}", method)))?;

                // Validate URL
                let url = obj["url"]
                    .as_str()
                    .ok_or_else(|| PluginError::InvalidParams("'url' must be a string".to_string()))?;

                url::Url::parse(url)
                    .map_err(|e| PluginError::InvalidParams(format!("Invalid URL: {}", e)))?;

                Ok(())
            }
            _ => Err(PluginError::UnsupportedAction(action.to_string())),
        }
    }

    fn url_patterns(&self) -> Vec<&str> {
        // HTTP plugin is the default, so it matches all HTTP URLs
        vec!["http://*", "https://*"]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Secret;

    #[test]
    fn test_validate_params_valid() {
        let plugin = HttpPlugin::new();
        let params = serde_json::json!({
            "method": "GET",
            "url": "https://api.example.com/users"
        });

        assert!(plugin.validate_params("request", &params).is_ok());
    }

    #[test]
    fn test_validate_params_missing_method() {
        let plugin = HttpPlugin::new();
        let params = serde_json::json!({
            "url": "https://api.example.com/users"
        });

        assert!(plugin.validate_params("request", &params).is_err());
    }

    #[test]
    fn test_validate_params_invalid_url() {
        let plugin = HttpPlugin::new();
        let params = serde_json::json!({
            "method": "GET",
            "url": "not-a-valid-url"
        });

        assert!(plugin.validate_params("request", &params).is_err());
    }

    #[test]
    fn test_inject_api_key() {
        let plugin = HttpPlugin::new();
        let mut headers = HashMap::new();

        let cred_data = CredentialData::ApiKey {
            key: Secret::new("test-key-123"),
            header_name: "Authorization".to_string(),
            header_prefix: "Bearer ".to_string(),
        };

        plugin.inject_credentials(&mut headers, &cred_data).unwrap();

        assert_eq!(
            headers.get("Authorization"),
            Some(&"Bearer test-key-123".to_string())
        );
    }

    #[test]
    fn test_inject_basic_auth() {
        let plugin = HttpPlugin::new();
        let mut headers = HashMap::new();

        let cred_data = CredentialData::BasicAuth {
            username: "user".to_string(),
            password: Secret::new("pass"),
        };

        plugin.inject_credentials(&mut headers, &cred_data).unwrap();

        // user:pass base64 encoded
        let expected = format!("Basic {}", STANDARD.encode("user:pass"));
        assert_eq!(headers.get("Authorization"), Some(&expected));
    }
}
