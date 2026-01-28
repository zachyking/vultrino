//! PGP Signing Plugin for Vultrino
//!
//! This plugin provides PGP/GPG signing and verification capabilities.

use pgp::cleartext::CleartextSignedMessage;
use pgp::crypto::hash::HashAlgorithm;
use pgp::ser::Serialize;
use pgp::types::{SecretKeyTrait, SignatureBytes};
use pgp::Deserializable;
use serde::{Deserialize, Serialize as SerdeSerialize};
use std::alloc::{alloc, dealloc, Layout};

/// ABI version this plugin implements
const ABI_VERSION: u32 = 1;

/// Result codes
const RESULT_OK: i32 = 0;
const RESULT_ERROR: i32 = -1;
const RESULT_INVALID_ACTION: i32 = -2;
const RESULT_INVALID_PARAMS: i32 = -3;

/// Request from host
#[derive(Debug, Deserialize)]
struct ExecuteRequest {
    action: String,
    credential: CredentialData,
    parameters: serde_json::Value,
}

/// Credential data passed from host
#[derive(Debug, Deserialize)]
struct CredentialData {
    private_key: String,
    passphrase: Option<String>,
    #[allow(dead_code)]
    key_id: Option<String>,
}

/// Response to host
#[derive(Debug, SerdeSerialize)]
struct ExecuteResponse {
    code: i32,
    data: Option<String>,
    error: Option<String>,
}

/// Parameters for sign action
#[derive(Debug, Deserialize)]
struct SignParams {
    data: String,
    #[serde(default = "default_true")]
    armor: bool,
}

/// Parameters for sign_cleartext action
#[derive(Debug, Deserialize)]
struct SignCleartextParams {
    message: String,
}

/// Parameters for verify action
#[derive(Debug, Deserialize)]
struct VerifyParams {
    data: String,
    signature: String,
}

/// Parameters for get_public_key action
#[derive(Debug, Deserialize)]
struct GetPublicKeyParams {
    #[serde(default = "default_true")]
    armor: bool,
}

fn default_true() -> bool {
    true
}

// ============== WASM ABI Exports ==============

/// Return the ABI version
#[no_mangle]
pub extern "C" fn vultrino_plugin_version() -> u32 {
    ABI_VERSION
}

/// Allocate memory for host to write data
#[no_mangle]
pub extern "C" fn vultrino_alloc(size: u32) -> *mut u8 {
    if size == 0 {
        return std::ptr::null_mut();
    }

    let layout = Layout::from_size_align(size as usize, 1).unwrap();
    unsafe { alloc(layout) }
}

/// Free memory allocated by plugin
#[no_mangle]
pub extern "C" fn vultrino_free(ptr: *mut u8, len: u32) {
    if ptr.is_null() || len == 0 {
        return;
    }

    let layout = Layout::from_size_align(len as usize, 1).unwrap();
    unsafe { dealloc(ptr, layout) }
}

/// Execute an action
///
/// Takes a pointer to JSON request, returns pointer to JSON response.
/// The response memory is allocated by the plugin and must be freed by the host.
#[no_mangle]
pub extern "C" fn vultrino_execute(request_ptr: *const u8, request_len: u32) -> u64 {
    let response = execute_internal(request_ptr, request_len);

    // Serialize response
    let json = match serde_json::to_string(&response) {
        Ok(j) => j,
        Err(e) => {
            let err_response = ExecuteResponse {
                code: RESULT_ERROR,
                data: None,
                error: Some(format!("Failed to serialize response: {}", e)),
            };
            serde_json::to_string(&err_response).unwrap_or_default()
        }
    };

    let bytes = json.into_bytes();
    let len = bytes.len() as u32;
    let ptr = vultrino_alloc(len);

    if !ptr.is_null() {
        unsafe {
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), ptr, len as usize);
        }
    }

    // Pack pointer and length into u64
    ((ptr as u64) << 32) | (len as u64)
}

/// Validate action parameters
#[no_mangle]
pub extern "C" fn vultrino_validate_params(
    action_ptr: *const u8,
    action_len: u32,
    params_ptr: *const u8,
    params_len: u32,
) -> i32 {
    let action = match read_string(action_ptr, action_len) {
        Some(s) => s,
        None => return RESULT_INVALID_PARAMS,
    };

    let params = match read_string(params_ptr, params_len) {
        Some(s) => s,
        None => return RESULT_INVALID_PARAMS,
    };

    let params_value: serde_json::Value = match serde_json::from_str(&params) {
        Ok(v) => v,
        Err(_) => return RESULT_INVALID_PARAMS,
    };

    match action.as_str() {
        "sign" => {
            if serde_json::from_value::<SignParams>(params_value).is_ok() {
                RESULT_OK
            } else {
                RESULT_INVALID_PARAMS
            }
        }
        "sign_cleartext" => {
            if serde_json::from_value::<SignCleartextParams>(params_value).is_ok() {
                RESULT_OK
            } else {
                RESULT_INVALID_PARAMS
            }
        }
        "verify" => {
            if serde_json::from_value::<VerifyParams>(params_value).is_ok() {
                RESULT_OK
            } else {
                RESULT_INVALID_PARAMS
            }
        }
        "get_public_key" => RESULT_OK,
        _ => RESULT_INVALID_ACTION,
    }
}

// ============== Internal Implementation ==============

fn read_string(ptr: *const u8, len: u32) -> Option<String> {
    if ptr.is_null() || len == 0 {
        return None;
    }

    let slice = unsafe { std::slice::from_raw_parts(ptr, len as usize) };
    String::from_utf8(slice.to_vec()).ok()
}

fn execute_internal(request_ptr: *const u8, request_len: u32) -> ExecuteResponse {
    // Parse request
    let request_str = match read_string(request_ptr, request_len) {
        Some(s) => s,
        None => {
            return ExecuteResponse {
                code: RESULT_ERROR,
                data: None,
                error: Some("Failed to read request".to_string()),
            };
        }
    };

    let request: ExecuteRequest = match serde_json::from_str(&request_str) {
        Ok(r) => r,
        Err(e) => {
            return ExecuteResponse {
                code: RESULT_ERROR,
                data: None,
                error: Some(format!("Failed to parse request: {}", e)),
            };
        }
    };

    // Dispatch to action handler
    match request.action.as_str() {
        "sign" => handle_sign(&request.credential, &request.parameters),
        "sign_cleartext" => handle_sign_cleartext(&request.credential, &request.parameters),
        "verify" => handle_verify(&request.credential, &request.parameters),
        "get_public_key" => handle_get_public_key(&request.credential, &request.parameters),
        _ => ExecuteResponse {
            code: RESULT_INVALID_ACTION,
            data: None,
            error: Some(format!("Unknown action: {}", request.action)),
        },
    }
}

fn handle_sign(credential: &CredentialData, params: &serde_json::Value) -> ExecuteResponse {
    let params: SignParams = match serde_json::from_value(params.clone()) {
        Ok(p) => p,
        Err(e) => {
            return ExecuteResponse {
                code: RESULT_INVALID_PARAMS,
                data: None,
                error: Some(format!("Invalid parameters: {}", e)),
            };
        }
    };

    match sign_data(
        &credential.private_key,
        credential.passphrase.as_deref(),
        &params.data,
        params.armor,
    ) {
        Ok(signature) => ExecuteResponse {
            code: RESULT_OK,
            data: Some(signature),
            error: None,
        },
        Err(e) => ExecuteResponse {
            code: RESULT_ERROR,
            data: None,
            error: Some(e),
        },
    }
}

fn handle_sign_cleartext(credential: &CredentialData, params: &serde_json::Value) -> ExecuteResponse {
    let params: SignCleartextParams = match serde_json::from_value(params.clone()) {
        Ok(p) => p,
        Err(e) => {
            return ExecuteResponse {
                code: RESULT_INVALID_PARAMS,
                data: None,
                error: Some(format!("Invalid parameters: {}", e)),
            };
        }
    };

    match sign_cleartext(
        &credential.private_key,
        credential.passphrase.as_deref(),
        &params.message,
    ) {
        Ok(signed_message) => ExecuteResponse {
            code: RESULT_OK,
            data: Some(signed_message),
            error: None,
        },
        Err(e) => ExecuteResponse {
            code: RESULT_ERROR,
            data: None,
            error: Some(e),
        },
    }
}

fn handle_verify(credential: &CredentialData, params: &serde_json::Value) -> ExecuteResponse {
    let params: VerifyParams = match serde_json::from_value(params.clone()) {
        Ok(p) => p,
        Err(e) => {
            return ExecuteResponse {
                code: RESULT_INVALID_PARAMS,
                data: None,
                error: Some(format!("Invalid parameters: {}", e)),
            };
        }
    };

    match verify_cleartext(&credential.private_key, &params.signature) {
        Ok((valid, message)) => {
            if valid && message.as_deref() == Some(params.data.as_str()) {
                ExecuteResponse {
                    code: RESULT_OK,
                    data: Some("true".to_string()),
                    error: None,
                }
            } else {
                ExecuteResponse {
                    code: RESULT_OK,
                    data: Some("false".to_string()),
                    error: None,
                }
            }
        }
        Err(e) => ExecuteResponse {
            code: RESULT_ERROR,
            data: None,
            error: Some(e),
        },
    }
}

fn handle_get_public_key(credential: &CredentialData, params: &serde_json::Value) -> ExecuteResponse {
    let params: GetPublicKeyParams =
        serde_json::from_value(params.clone()).unwrap_or(GetPublicKeyParams { armor: true });

    match extract_public_key(&credential.private_key, params.armor) {
        Ok(public_key) => ExecuteResponse {
            code: RESULT_OK,
            data: Some(public_key),
            error: None,
        },
        Err(e) => ExecuteResponse {
            code: RESULT_ERROR,
            data: None,
            error: Some(e),
        },
    }
}

// ============== PGP Operations ==============

/// Sign data and return a base64-encoded signature
fn sign_data(
    private_key_armor: &str,
    passphrase: Option<&str>,
    data: &str,
    _armor: bool,
) -> Result<String, String> {
    // Parse the private key
    let (secret_key, _) = pgp::SignedSecretKey::from_string(private_key_armor)
        .map_err(|e| format!("Failed to parse private key: {}", e))?;

    // Create password closure
    let pw = passphrase.unwrap_or("").to_string();
    let pw_fn = || pw.clone();

    // Create signature using the secret key
    let sig_bytes = secret_key
        .create_signature(pw_fn, HashAlgorithm::SHA2_256, data.as_bytes())
        .map_err(|e| format!("Failed to create signature: {}", e))?;

    // Convert SignatureBytes to bytes
    use base64::Engine;
    let bytes = signature_bytes_to_vec(&sig_bytes);
    Ok(base64::engine::general_purpose::STANDARD.encode(bytes))
}

/// Convert SignatureBytes to a Vec<u8>
fn signature_bytes_to_vec(sig: &SignatureBytes) -> Vec<u8> {
    match sig {
        SignatureBytes::Mpis(mpis) => {
            // Concatenate all MPI bytes
            let mut result = Vec::new();
            for mpi in mpis {
                result.extend_from_slice(mpi.as_bytes());
            }
            result
        }
        SignatureBytes::Native(bytes) => bytes.clone(),
    }
}

/// Sign a message as cleartext (PGP cleartext signed message)
fn sign_cleartext(
    private_key_armor: &str,
    passphrase: Option<&str>,
    message: &str,
) -> Result<String, String> {
    // Parse the private key
    let (secret_key, _) = pgp::SignedSecretKey::from_string(private_key_armor)
        .map_err(|e| format!("Failed to parse private key: {}", e))?;

    // Create password closure
    let pw = passphrase.unwrap_or("").to_string();
    let pw_fn = || pw.clone();

    // Create cleartext signed message
    let mut rng = rand::thread_rng();
    let signed_message = CleartextSignedMessage::sign(&mut rng, message, &secret_key, pw_fn)
        .map_err(|e| format!("Failed to create cleartext signature: {}", e))?;

    // Return the armored message
    signed_message
        .to_armored_string(Default::default())
        .map_err(|e| format!("Failed to armor message: {}", e))
}

/// Verify a cleartext signed message
fn verify_cleartext(
    private_key_armor: &str,
    signed_message_armor: &str,
) -> Result<(bool, Option<String>), String> {
    // Parse the private key to get public key
    let (secret_key, _) = pgp::SignedSecretKey::from_string(private_key_armor)
        .map_err(|e| format!("Failed to parse private key: {}", e))?;

    let public_key = secret_key.public_key();

    // Parse the cleartext signed message
    let (signed_message, _) = CleartextSignedMessage::from_string(signed_message_armor)
        .map_err(|e| format!("Failed to parse signed message: {}", e))?;

    // Verify the signature
    match signed_message.verify(&public_key) {
        Ok(_) => {
            let text = signed_message.signed_text().to_string();
            Ok((true, Some(text)))
        }
        Err(_) => Ok((false, None)),
    }
}

/// Extract the public key from a private key
fn extract_public_key(private_key_armor: &str, armor: bool) -> Result<String, String> {
    // Parse the private key
    let (secret_key, _) = pgp::SignedSecretKey::from_string(private_key_armor)
        .map_err(|e| format!("Failed to parse private key: {}", e))?;

    // Get the public key
    let public_key = secret_key.public_key();

    // Sign the public key with the secret key to create a signed public key
    let mut rng = rand::thread_rng();
    let pw_fn = || String::new();
    let signed_public_key = public_key
        .sign(&mut rng, &secret_key, pw_fn)
        .map_err(|e| format!("Failed to sign public key: {}", e))?;

    if armor {
        signed_public_key
            .to_armored_string(Default::default())
            .map_err(|e| format!("Failed to armor public key: {}", e))
    } else {
        use base64::Engine;
        let bytes = signed_public_key
            .to_bytes()
            .map_err(|e| format!("Failed to serialize public key: {}", e))?;
        Ok(base64::engine::general_purpose::STANDARD.encode(bytes))
    }
}
