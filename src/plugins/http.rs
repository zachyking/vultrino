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
use std::net::{IpAddr, Ipv6Addr, ToSocketAddrs};
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

    /// Check if an IP address is private/internal (SSRF protection)
    fn is_private_ip(ip: &IpAddr) -> bool {
        match ip {
            IpAddr::V4(ipv4) => {
                // Loopback (127.0.0.0/8)
                ipv4.is_loopback()
                // Private ranges
                || ipv4.is_private()
                // Link-local (169.254.0.0/16)
                || ipv4.is_link_local()
                // Broadcast
                || ipv4.is_broadcast()
                // Documentation (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24)
                || ipv4.is_documentation()
                // Unspecified (0.0.0.0)
                || ipv4.is_unspecified()
                // Shared address space (100.64.0.0/10 - CGNAT)
                || (ipv4.octets()[0] == 100 && (ipv4.octets()[1] & 0xC0) == 64)
                // Loopback extended (127.0.0.0/8 - already covered by is_loopback)
                // Reserved for future use (240.0.0.0/4)
                || ipv4.octets()[0] >= 240
                // Local network control block (224.0.0.0/24)
                || (ipv4.octets()[0] == 224 && ipv4.octets()[1] == 0 && ipv4.octets()[2] == 0)
            }
            IpAddr::V6(ipv6) => {
                // Loopback (::1)
                ipv6.is_loopback()
                // Unspecified (::)
                || ipv6.is_unspecified()
                // Unique local (fc00::/7)
                || ((ipv6.segments()[0] & 0xfe00) == 0xfc00)
                // Link-local (fe80::/10)
                || ((ipv6.segments()[0] & 0xffc0) == 0xfe80)
                // IPv4-mapped addresses - check the IPv4 portion
                || Self::is_ipv4_mapped_private(ipv6)
            }
        }
    }

    /// Check if an IPv6 address is an IPv4-mapped address pointing to a private IPv4
    fn is_ipv4_mapped_private(ipv6: &Ipv6Addr) -> bool {
        // IPv4-mapped IPv6 addresses are ::ffff:x.x.x.x
        if let Some(ipv4) = ipv6.to_ipv4_mapped() {
            Self::is_private_ip(&IpAddr::V4(ipv4))
        } else {
            false
        }
    }

    /// Validate URL for SSRF protection
    fn validate_url_ssrf(url_str: &str) -> Result<url::Url, PluginError> {
        let url = url::Url::parse(url_str)
            .map_err(|e| PluginError::InvalidParams(format!("Invalid URL: {}", e)))?;

        // Only allow http and https schemes
        match url.scheme() {
            "http" | "https" => {}
            scheme => {
                return Err(PluginError::InvalidParams(format!(
                    "URL scheme '{}' not allowed. Only http and https are permitted.",
                    scheme
                )));
            }
        }

        // Get the host
        let host = url.host_str().ok_or_else(|| {
            PluginError::InvalidParams("URL must have a host".to_string())
        })?;

        // Check for IP address literals
        if let Ok(ip) = host.parse::<IpAddr>() {
            if Self::is_private_ip(&ip) {
                return Err(PluginError::InvalidParams(
                    "Requests to private/internal IP addresses are not allowed".to_string(),
                ));
            }
        }

        // Resolve hostname and check all resolved IPs
        let port = url.port_or_known_default().unwrap_or(80);
        let socket_addr = format!("{}:{}", host, port);

        if let Ok(addrs) = socket_addr.to_socket_addrs() {
            for addr in addrs {
                if Self::is_private_ip(&addr.ip()) {
                    return Err(PluginError::InvalidParams(format!(
                        "Host '{}' resolves to private/internal IP address, which is not allowed",
                        host
                    )));
                }
            }
        }
        // If DNS resolution fails, we'll let the request proceed and fail naturally
        // This handles cases where DNS might be temporarily unavailable

        Ok(url)
    }

    /// Execute an HTTP request
    async fn execute_request(
        &self,
        params: HttpRequestParams,
        cred_data: &CredentialData,
    ) -> Result<ExecuteResponse, PluginError> {
        // Validate URL for SSRF before proceeding
        let validated_url = Self::validate_url_ssrf(&params.url)?;

        // Parse method
        let method = Method::from_str(&params.method.to_uppercase())
            .map_err(|_| PluginError::InvalidParams(format!("Invalid HTTP method: {}", params.method)))?;

        // Build headers with credential injection
        let mut headers = params.headers;
        self.inject_credentials(&mut headers, cred_data)?;

        // Build request using the validated URL
        let mut request = self.client.request(method, validated_url);

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

                // Validate URL with SSRF protection
                let url = obj["url"]
                    .as_str()
                    .ok_or_else(|| PluginError::InvalidParams("'url' must be a string".to_string()))?;

                Self::validate_url_ssrf(url)?;

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

    // SSRF Protection Tests

    #[test]
    fn test_ssrf_blocks_localhost() {
        let result = HttpPlugin::validate_url_ssrf("http://127.0.0.1/api");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("private"));
    }

    #[test]
    fn test_ssrf_blocks_localhost_ipv6() {
        let result = HttpPlugin::validate_url_ssrf("http://[::1]/api");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("private"));
    }

    #[test]
    fn test_ssrf_blocks_private_10_network() {
        let result = HttpPlugin::validate_url_ssrf("http://10.0.0.1/api");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("private"));
    }

    #[test]
    fn test_ssrf_blocks_private_172_network() {
        let result = HttpPlugin::validate_url_ssrf("http://172.16.0.1/api");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("private"));
    }

    #[test]
    fn test_ssrf_blocks_private_192_network() {
        let result = HttpPlugin::validate_url_ssrf("http://192.168.1.1/api");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("private"));
    }

    #[test]
    fn test_ssrf_blocks_link_local() {
        let result = HttpPlugin::validate_url_ssrf("http://169.254.0.1/api");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("private"));
    }

    #[test]
    fn test_ssrf_blocks_cgnat_range() {
        let result = HttpPlugin::validate_url_ssrf("http://100.64.0.1/api");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("private"));
    }

    #[test]
    fn test_ssrf_blocks_unspecified() {
        let result = HttpPlugin::validate_url_ssrf("http://0.0.0.0/api");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("private"));
    }

    #[test]
    fn test_ssrf_blocks_file_scheme() {
        let result = HttpPlugin::validate_url_ssrf("file:///etc/passwd");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("scheme"));
    }

    #[test]
    fn test_ssrf_blocks_ftp_scheme() {
        let result = HttpPlugin::validate_url_ssrf("ftp://ftp.example.com/file");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("scheme"));
    }

    #[test]
    fn test_ssrf_blocks_data_scheme() {
        let result = HttpPlugin::validate_url_ssrf("data:text/html,<h1>test</h1>");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("scheme"));
    }

    #[test]
    fn test_ssrf_allows_https() {
        let result = HttpPlugin::validate_url_ssrf("https://api.example.com/v1");
        assert!(result.is_ok());
    }

    #[test]
    fn test_ssrf_allows_http() {
        let result = HttpPlugin::validate_url_ssrf("http://api.example.com/v1");
        assert!(result.is_ok());
    }

    #[test]
    fn test_is_private_ip_ipv4() {
        use std::net::IpAddr;

        // Private IPs
        assert!(HttpPlugin::is_private_ip(&"127.0.0.1".parse::<IpAddr>().unwrap()));
        assert!(HttpPlugin::is_private_ip(&"10.0.0.1".parse::<IpAddr>().unwrap()));
        assert!(HttpPlugin::is_private_ip(&"172.16.0.1".parse::<IpAddr>().unwrap()));
        assert!(HttpPlugin::is_private_ip(&"192.168.1.1".parse::<IpAddr>().unwrap()));
        assert!(HttpPlugin::is_private_ip(&"169.254.0.1".parse::<IpAddr>().unwrap()));

        // Public IPs should not be blocked
        assert!(!HttpPlugin::is_private_ip(&"8.8.8.8".parse::<IpAddr>().unwrap()));
        assert!(!HttpPlugin::is_private_ip(&"1.1.1.1".parse::<IpAddr>().unwrap()));
    }

    #[test]
    fn test_is_private_ip_ipv6() {
        use std::net::IpAddr;

        // Private IPv6
        assert!(HttpPlugin::is_private_ip(&"::1".parse::<IpAddr>().unwrap()));
        assert!(HttpPlugin::is_private_ip(&"fe80::1".parse::<IpAddr>().unwrap()));
        assert!(HttpPlugin::is_private_ip(&"fc00::1".parse::<IpAddr>().unwrap()));

        // Public IPv6
        assert!(!HttpPlugin::is_private_ip(&"2001:4860:4860::8888".parse::<IpAddr>().unwrap()));
    }

    #[test]
    fn test_validate_params_blocks_ssrf() {
        let plugin = HttpPlugin::new();

        // Should block private IP
        let params = serde_json::json!({
            "method": "GET",
            "url": "http://192.168.1.1/admin"
        });
        assert!(plugin.validate_params("request", &params).is_err());

        // Should block file:// scheme
        let params = serde_json::json!({
            "method": "GET",
            "url": "file:///etc/passwd"
        });
        assert!(plugin.validate_params("request", &params).is_err());
    }
}
