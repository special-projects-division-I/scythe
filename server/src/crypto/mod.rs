use aes_gcm::{
    Aes256Gcm, Key, Nonce,
    aead::{Aead, KeyInit, OsRng},
};
use base64::{Engine as _, engine::general_purpose};
use chrono::{DateTime, Utc};
use rand::RngCore;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use crate::features::data_structs::EncryptedMessage;

pub mod config;
pub mod monitoring;
pub mod tests;

pub use config::*;
pub use monitoring::*;

pub struct C2Crypto {
    cipher: Aes256Gcm,
    key_id: String,
    created_at: DateTime<Utc>,
    rotation_threshold: u64, // seconds
    usage_count: Arc<RwLock<u64>>,
    max_usage_count: u64,
}

impl C2Crypto {
    /// Create a new C2Crypto instance with a random 256-bit key
    pub fn new() -> (Self, String) {
        let mut key_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut key_bytes);
        let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
        let cipher = Aes256Gcm::new(key);
        let key_b64 = general_purpose::STANDARD.encode(key_bytes);
        let key_id = generate_secure_id(16);

        // Clear key bytes from memory
        key_bytes.fill(0);

        (
            Self {
                cipher,
                key_id,
                created_at: Utc::now(),
                rotation_threshold: 86400, // 24 hours
                usage_count: Arc::new(RwLock::new(0)),
                max_usage_count: 100000,
            },
            key_b64,
        )
    }

    /// Create a new C2Crypto instance with enterprise settings
    pub fn new_enterprise(rotation_threshold: u64, max_usage_count: u64) -> (Self, String) {
        let mut key_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut key_bytes);
        let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
        let cipher = Aes256Gcm::new(key);
        let key_b64 = general_purpose::STANDARD.encode(key_bytes);
        let key_id = generate_secure_id(16);

        // Clear key bytes from memory
        key_bytes.fill(0);

        (
            Self {
                cipher,
                key_id,
                created_at: Utc::now(),
                rotation_threshold,
                usage_count: Arc::new(RwLock::new(0)),
                max_usage_count,
            },
            key_b64,
        )
    }

    /// Create C2Crypto instance from existing base64 key
    pub fn from_key(key_b64: &str) -> Result<Self, CryptoError> {
        let key_bytes = general_purpose::STANDARD
            .decode(key_b64)
            .map_err(|_| CryptoError::InvalidKey)?;

        if key_bytes.len() != 32 {
            return Err(CryptoError::InvalidKey);
        }

        let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
        let cipher = Aes256Gcm::new(key);
        let key_id = generate_secure_id(16);

        Ok(Self {
            cipher,
            key_id,
            created_at: Utc::now(),
            rotation_threshold: 86400,
            usage_count: Arc::new(RwLock::new(0)),
            max_usage_count: 100000,
        })
    }

    /// Check if key needs rotation based on age or usage
    pub fn needs_rotation(&self) -> bool {
        let age = Utc::now()
            .signed_duration_since(self.created_at)
            .num_seconds() as u64;
        let usage = *self.usage_count.read().unwrap();

        age >= self.rotation_threshold || usage >= self.max_usage_count
    }

    /// Get key metadata for rotation tracking
    pub fn get_key_metadata(&self) -> KeyMetadata {
        KeyMetadata {
            key_id: self.key_id.clone(),
            created_at: self.created_at,
            age_seconds: Utc::now()
                .signed_duration_since(self.created_at)
                .num_seconds() as u64,
            usage_count: *self.usage_count.read().unwrap(),
            needs_rotation: self.needs_rotation(),
        }
    }

    /// Encrypt plaintext data and return EncryptedMessage
    pub fn encrypt(&self, plaintext: &str) -> Result<EncryptedMessage, CryptoError> {
        // Increment usage counter
        {
            let mut count = self
                .usage_count
                .write()
                .map_err(|_| CryptoError::InternalError)?;
            *count += 1;
        }

        // Check if rotation is needed
        if self.needs_rotation() {
            return Err(CryptoError::KeyRotationRequired);
        }

        // Validate input size (prevent DoS)
        if plaintext.len() > 1024 * 1024 {
            // 1MB limit
            return Err(CryptoError::PayloadTooLarge);
        }

        // Generate random 96-bit nonce
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        // Encrypt the data
        let ciphertext = self
            .cipher
            .encrypt(nonce, plaintext.as_bytes())
            .map_err(|_| CryptoError::EncryptionFailed)?;

        Ok(EncryptedMessage {
            nonce: general_purpose::STANDARD.encode(nonce_bytes),
            ciphertext: general_purpose::STANDARD.encode(ciphertext),
        })
    }

    /// Decrypt EncryptedMessage and return plaintext
    pub fn decrypt(&self, encrypted: &EncryptedMessage) -> Result<String, CryptoError> {
        // Increment usage counter
        {
            let mut count = self
                .usage_count
                .write()
                .map_err(|_| CryptoError::InternalError)?;
            *count += 1;
        }

        // Validate input sizes (prevent DoS)
        if encrypted.ciphertext.len() > 2 * 1024 * 1024 {
            // 2MB limit for base64
            return Err(CryptoError::PayloadTooLarge);
        }

        // Decode nonce and ciphertext from base64
        let nonce_bytes = general_purpose::STANDARD
            .decode(&encrypted.nonce)
            .map_err(|_| CryptoError::InvalidNonce)?;

        let ciphertext_bytes = general_purpose::STANDARD
            .decode(&encrypted.ciphertext)
            .map_err(|_| CryptoError::InvalidCiphertext)?;

        if nonce_bytes.len() != 12 {
            return Err(CryptoError::InvalidNonce);
        }

        let nonce = Nonce::from_slice(&nonce_bytes);

        // Decrypt the data
        let plaintext_bytes = self
            .cipher
            .decrypt(nonce, ciphertext_bytes.as_ref())
            .map_err(|_| CryptoError::DecryptionFailed)?;

        String::from_utf8(plaintext_bytes).map_err(|_| CryptoError::InvalidUtf8)
    }

    /// Encrypt JSON data (for structured payloads)
    pub fn encrypt_json<T: serde::Serialize>(
        &self,
        data: &T,
    ) -> Result<EncryptedMessage, CryptoError> {
        let json_str = serde_json::to_string(data).map_err(|_| CryptoError::SerializationFailed)?;
        self.encrypt(&json_str)
    }

    /// Decrypt JSON data (for structured payloads)
    pub fn decrypt_json<T: serde::de::DeserializeOwned>(
        &self,
        encrypted: &EncryptedMessage,
    ) -> Result<T, CryptoError> {
        let json_str = self.decrypt(encrypted)?;
        serde_json::from_str(&json_str).map_err(|_| CryptoError::DeserializationFailed)
    }

    /// Decode advanced obfuscated data (case-alternating reverse base64)
    pub fn decode_advanced_obfuscated(&self, encoded: &str) -> Result<String, CryptoError> {
        // Step 1: Normalize case (restore original base64 case pattern)
        let normalized = normalize_case_pattern(encoded);

        // Step 2: Reverse the string back to original order
        let unreversed: String = normalized.chars().rev().collect();

        // Step 3: Decode base64
        let decoded_bytes = general_purpose::STANDARD
            .decode(&unreversed)
            .map_err(|_| CryptoError::DecodingFailed)?;

        String::from_utf8(decoded_bytes).map_err(|_| CryptoError::InvalidUtf8)
    }

    /// Check if string is advanced obfuscated (alternating case pattern)
    pub fn is_advanced_obfuscated(&self, data: &str) -> bool {
        is_advanced_obfuscated_pattern(data)
    }
}

/// Generate a random AES-256 key as base64 string
pub fn generate_random_key() -> String {
    let mut key_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut key_bytes);
    general_purpose::STANDARD.encode(key_bytes)
}

/// Generate a secure random string for agent IDs, session tokens, etc.
pub fn generate_secure_id(length: usize) -> String {
    let mut bytes = vec![0u8; length];
    OsRng.fill_bytes(&mut bytes);
    let encoded = general_purpose::URL_SAFE_NO_PAD.encode(&bytes);
    encoded[..length.min(encoded.len())].to_string()
}

/// Hash a password using bcrypt (for operator authentication)
pub fn hash_password(password: &str) -> Result<String, CryptoError> {
    bcrypt::hash(password, bcrypt::DEFAULT_COST).map_err(|_| CryptoError::HashingFailed)
}

/// Verify a password against a bcrypt hash
pub fn verify_password(password: &str, hash: &str) -> Result<bool, CryptoError> {
    bcrypt::verify(password, hash).map_err(|_| CryptoError::VerificationFailed)
}

/// Decode advanced obfuscated string (case-alternating reverse base64)
pub fn decode_advanced_obfuscated(encoded: &str) -> Result<String, CryptoError> {
    // Step 1: Normalize case pattern
    let normalized = normalize_case_pattern(encoded);

    // Step 2: Reverse the string
    let unreversed: String = normalized.chars().rev().collect();

    // Step 3: Decode base64
    let decoded_bytes = general_purpose::STANDARD
        .decode(&unreversed)
        .map_err(|_| CryptoError::DecodingFailed)?;

    String::from_utf8(decoded_bytes).map_err(|_| CryptoError::InvalidUtf8)
}

/// Encode data using advanced obfuscation (case-alternating reverse base64)
pub fn encode_advanced_obfuscated(data: &str) -> String {
    // Step 1: Base64 encode
    let base64_encoded = general_purpose::STANDARD.encode(data.as_bytes());

    // Step 2: Reverse the string
    let reversed: String = base64_encoded.chars().rev().collect();

    // Step 3: Alternate case
    alternate_case_pattern(&reversed)
}

/// Check if string appears to be advanced obfuscated
pub fn is_advanced_obfuscated_pattern(data: &str) -> bool {
    if data.is_empty() {
        return false;
    }

    let mut has_upper_lower = false;
    let mut has_lower_upper = false;
    let chars: Vec<char> = data.chars().collect();

    for i in 0..chars.len().saturating_sub(1) {
        let current = chars[i];
        let next = chars[i + 1];

        if current.is_lowercase() && next.is_uppercase() {
            has_lower_upper = true;
        }
        if current.is_uppercase() && next.is_lowercase() {
            has_upper_lower = true;
        }
    }

    // Check if contains base64-like characters
    let has_base64_chars = data
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=');

    has_base64_chars && (has_upper_lower || has_lower_upper)
}

/// Normalize case pattern (restore original base64 case)
fn normalize_case_pattern(encoded: &str) -> String {
    let mut result = String::with_capacity(encoded.len());

    for (i, c) in encoded.chars().enumerate() {
        if c.is_alphabetic() {
            if i % 2 == 0 {
                // Even positions were uppercased, keep as-is
                result.push(c);
            } else {
                // Odd positions were lowercased, restore to uppercase if needed
                if c.is_lowercase() {
                    result.push(c.to_uppercase().next().unwrap_or(c));
                } else {
                    result.push(c);
                }
            }
        } else {
            result.push(c);
        }
    }

    result
}

/// Apply alternating case pattern
fn alternate_case_pattern(data: &str) -> String {
    let mut result = String::with_capacity(data.len());

    for (i, c) in data.chars().enumerate() {
        if i % 2 == 0 {
            result.push(c.to_uppercase().next().unwrap_or(c));
        } else {
            result.push(c.to_lowercase().next().unwrap_or(c));
        }
    }

    result
}

#[derive(Debug, Clone)]
pub enum CryptoError {
    InvalidKey,
    InvalidNonce,
    InvalidCiphertext,
    InvalidUtf8,
    EncryptionFailed,
    DecryptionFailed,
    SerializationFailed,
    DeserializationFailed,
    HashingFailed,
    VerificationFailed,
    DecodingFailed,
    KeyRotationRequired,
    PayloadTooLarge,
    InternalError,
    RateLimitExceeded,
}

#[derive(Debug, Clone)]
pub struct KeyMetadata {
    pub key_id: String,
    pub created_at: DateTime<Utc>,
    pub age_seconds: u64,
    pub usage_count: u64,
    pub needs_rotation: bool,
}

/// Enterprise key manager for handling multiple keys and rotation
pub struct EnterpriseKeyManager {
    current_key: Arc<RwLock<C2Crypto>>,
    old_keys: Arc<RwLock<HashMap<String, C2Crypto>>>,
    rotation_threshold: u64,
    max_usage_count: u64,
}

impl EnterpriseKeyManager {
    pub fn new(rotation_threshold: u64, max_usage_count: u64) -> (Self, String) {
        let (crypto, key) = C2Crypto::new_enterprise(rotation_threshold, max_usage_count);

        (
            Self {
                current_key: Arc::new(RwLock::new(crypto)),
                old_keys: Arc::new(RwLock::new(HashMap::new())),
                rotation_threshold,
                max_usage_count,
            },
            key,
        )
    }

    pub fn rotate_key(&self) -> Result<String, CryptoError> {
        let (new_crypto, new_key) =
            C2Crypto::new_enterprise(self.rotation_threshold, self.max_usage_count);

        {
            let mut current = self
                .current_key
                .write()
                .map_err(|_| CryptoError::InternalError)?;
            let old_key_id = current.key_id.clone();

            let mut old_keys = self
                .old_keys
                .write()
                .map_err(|_| CryptoError::InternalError)?;
            let old_crypto = std::mem::replace(&mut *current, new_crypto);
            old_keys.insert(old_key_id, old_crypto);

            // Keep only last 5 keys
            if old_keys.len() > 5 {
                let oldest_key = old_keys.keys().next().cloned();
                if let Some(key) = oldest_key {
                    old_keys.remove(&key);
                }
            }
        }

        Ok(new_key)
    }

    pub fn encrypt(&self, plaintext: &str) -> Result<EncryptedMessage, CryptoError> {
        let current = self
            .current_key
            .read()
            .map_err(|_| CryptoError::InternalError)?;
        current.encrypt(plaintext)
    }

    pub fn decrypt(&self, encrypted: &EncryptedMessage) -> Result<String, CryptoError> {
        // Try current key first
        {
            let current = self
                .current_key
                .read()
                .map_err(|_| CryptoError::InternalError)?;
            if let Ok(result) = current.decrypt(encrypted) {
                return Ok(result);
            }
        }

        // Try old keys
        let old_keys = self
            .old_keys
            .read()
            .map_err(|_| CryptoError::InternalError)?;
        for crypto in old_keys.values() {
            if let Ok(result) = crypto.decrypt(encrypted) {
                return Ok(result);
            }
        }

        Err(CryptoError::DecryptionFailed)
    }

    pub fn needs_rotation(&self) -> Result<bool, CryptoError> {
        let current = self
            .current_key
            .read()
            .map_err(|_| CryptoError::InternalError)?;
        Ok(current.needs_rotation())
    }

    pub fn get_key_metadata(&self) -> Result<KeyMetadata, CryptoError> {
        let current = self
            .current_key
            .read()
            .map_err(|_| CryptoError::InternalError)?;
        Ok(current.get_key_metadata())
    }
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CryptoError::InvalidKey => write!(f, "Invalid encryption key"),
            CryptoError::InvalidNonce => write!(f, "Invalid nonce"),
            CryptoError::InvalidCiphertext => write!(f, "Invalid ciphertext"),
            CryptoError::InvalidUtf8 => write!(f, "Invalid UTF-8 in decrypted data"),
            CryptoError::EncryptionFailed => write!(f, "Encryption failed"),
            CryptoError::DecryptionFailed => write!(f, "Decryption failed"),
            CryptoError::SerializationFailed => write!(f, "JSON serialization failed"),
            CryptoError::DeserializationFailed => write!(f, "JSON deserialization failed"),
            CryptoError::HashingFailed => write!(f, "Password hashing failed"),
            CryptoError::VerificationFailed => write!(f, "Password verification failed"),
            CryptoError::DecodingFailed => write!(f, "Advanced obfuscation decoding failed"),
            CryptoError::KeyRotationRequired => write!(
                f,
                "Key rotation required - key has expired or reached usage limit"
            ),
            CryptoError::PayloadTooLarge => write!(f, "Payload exceeds maximum allowed size"),
            CryptoError::InternalError => write!(f, "Internal cryptographic error"),
            CryptoError::RateLimitExceeded => {
                write!(f, "Rate limit exceeded for cryptographic operations")
            }
        }
    }
}

impl std::error::Error for CryptoError {}

/// Enterprise crypto context that combines all components
pub struct EnterpriseCryptoContext {
    pub key_manager: EnterpriseKeyManager,
    pub monitor: Arc<CryptoMonitor>,
    pub config: CryptoConfig,
}

impl EnterpriseCryptoContext {
    pub fn new(config: CryptoConfig) -> Result<(Self, String), CryptoError> {
        let (key_manager, initial_key) = EnterpriseKeyManager::new(
            config.key_management.rotation_threshold_seconds,
            config.key_management.max_operations_per_key,
        );

        let rate_limit_config = monitoring::RateLimitConfig {
            max_operations_per_minute: config.rate_limiting.max_ops_per_minute,
            max_operations_per_hour: config.rate_limiting.max_ops_per_hour,
            burst_limit: config.rate_limiting.burst_limit,
            block_duration_minutes: config.rate_limiting.block_duration_minutes,
        };

        let monitor = Arc::new(CryptoMonitor::new(
            rate_limit_config,
            config.audit.max_logs_in_memory,
        ));

        Ok((
            Self {
                key_manager,
                monitor,
                config,
            },
            initial_key,
        ))
    }

    pub fn new_default() -> Result<(Self, String), CryptoError> {
        Self::new(CryptoConfig::default())
    }

    /// Perform encrypted operation with full enterprise monitoring
    pub fn encrypt_with_monitoring(
        &self,
        data: &str,
        client_id: &str,
        agent_id: Option<&str>,
        operator_id: Option<&str>,
        client_ip: Option<&str>,
        user_agent: Option<&str>,
        classification: Option<&str>,
    ) -> Result<EncryptedMessage, CryptoError> {
        // Check rate limiting
        self.monitor.check_rate_limit(client_id)?;

        // Check data classification requirements
        if let Some(class) = classification {
            if let Some(_class_config) = self.config.get_classification_config(class) {
                // Additional validation based on classification could go here
                log::info!("Processing {} classified data", class);
            }
        }

        // Check operation permission
        if !self
            .config
            .is_operation_allowed("encrypt", Some(data.len()))
        {
            return Err(CryptoError::PayloadTooLarge);
        }

        let start_time = std::time::Instant::now();
        let result = self.key_manager.encrypt(data);
        let duration = start_time.elapsed();

        // Log the operation
        let log_result = result.as_ref().map_err(|e| e.clone()).map(|_| ());
        self.monitor.log_operation(
            "encrypt",
            &self.key_manager.get_key_metadata()?.key_id,
            &log_result,
            duration,
            agent_id,
            operator_id,
            Some(data.len()),
            client_ip,
            user_agent,
        );

        result
    }

    /// Perform decryption with full enterprise monitoring
    pub fn decrypt_with_monitoring(
        &self,
        encrypted: &EncryptedMessage,
        client_id: &str,
        agent_id: Option<&str>,
        operator_id: Option<&str>,
        client_ip: Option<&str>,
        user_agent: Option<&str>,
    ) -> Result<String, CryptoError> {
        // Check rate limiting
        self.monitor.check_rate_limit(client_id)?;

        let start_time = std::time::Instant::now();
        let result = self.key_manager.decrypt(encrypted);
        let duration = start_time.elapsed();

        // Log the operation
        let log_result = result.as_ref().map_err(|e| e.clone()).map(|_| ());
        self.monitor.log_operation(
            "decrypt",
            "unknown", // We don't know which key was used for decryption
            &log_result,
            duration,
            agent_id,
            operator_id,
            Some(encrypted.ciphertext.len()),
            client_ip,
            user_agent,
        );

        result
    }

    /// Rotate keys with enterprise monitoring
    pub fn rotate_key_with_monitoring(
        &self,
        operator_id: &str,
        client_ip: Option<&str>,
    ) -> Result<String, CryptoError> {
        let start_time = std::time::Instant::now();
        let result = self.key_manager.rotate_key();
        let duration = start_time.elapsed();

        // Log the operation
        let log_result = result.as_ref().map_err(|e| e.clone()).map(|_| ());
        self.monitor.log_operation(
            "key_rotation",
            &self.key_manager.get_key_metadata()?.key_id,
            &log_result,
            duration,
            None,
            Some(operator_id),
            None,
            client_ip,
            Some("enterprise-key-manager/1.0"),
        );

        result
    }

    /// Get comprehensive security status
    pub fn get_security_status(&self) -> Result<SecurityStatus, CryptoError> {
        let key_metadata = self.key_manager.get_key_metadata()?;
        let metrics = self.monitor.get_metrics();
        let alerts = self.monitor.check_security_alerts();
        let system_health = SystemHealth::calculate(&metrics);

        Ok(SecurityStatus {
            key_metadata,
            metrics,
            alerts,
            config_compliance: self.config.validate().is_ok(),
            system_health,
        })
    }
}

#[derive(Debug, Clone)]
pub struct SecurityStatus {
    pub key_metadata: KeyMetadata,
    pub metrics: CryptoMetrics,
    pub alerts: Vec<SecurityAlert>,
    pub config_compliance: bool,
    pub system_health: SystemHealth,
}

#[derive(Debug, Clone)]
pub enum SystemHealth {
    Healthy,
    Warning(String),
    Critical(String),
}

impl SystemHealth {
    fn calculate(metrics: &CryptoMetrics) -> Self {
        if metrics.total_operations > 0 {
            let failure_rate = metrics.failed_operations as f64 / metrics.total_operations as f64;

            if failure_rate > 0.5 {
                SystemHealth::Critical("High failure rate detected".to_string())
            } else if failure_rate > 0.1 {
                SystemHealth::Warning("Elevated failure rate".to_string())
            } else if metrics.average_duration_ms > 5000.0 {
                SystemHealth::Warning("High average operation latency".to_string())
            } else {
                SystemHealth::Healthy
            }
        } else {
            SystemHealth::Healthy
        }
    }
}

#[cfg(test)]
mod legacy_tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt() {
        let (crypto, _key) = C2Crypto::new();
        let plaintext = "Hello, World!";

        let encrypted = crypto.encrypt(plaintext).unwrap();
        let decrypted = crypto.decrypt(&encrypted).unwrap();

        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_encrypt_decrypt_json() {
        use serde::{Deserialize, Serialize};

        #[derive(Serialize, Deserialize, PartialEq, Debug)]
        struct TestData {
            message: String,
            number: u32,
        }

        let (crypto, _key) = C2Crypto::new();
        let data = TestData {
            message: "test".to_string(),
            number: 42,
        };

        let encrypted = crypto.encrypt_json(&data).unwrap();
        let decrypted: TestData = crypto.decrypt_json(&encrypted).unwrap();

        assert_eq!(data, decrypted);
    }

    #[test]
    fn test_key_persistence() {
        let (crypto1, key) = C2Crypto::new();
        let crypto2 = C2Crypto::from_key(&key).unwrap();

        let plaintext = "test message";
        let encrypted = crypto1.encrypt(plaintext).unwrap();
        let decrypted = crypto2.decrypt(&encrypted).unwrap();

        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_password_hashing() {
        let password = "secure_password_123";
        let hash = hash_password(password).unwrap();

        assert!(verify_password(password, &hash).unwrap());
        assert!(!verify_password("wrong_password", &hash).unwrap());
    }
}
