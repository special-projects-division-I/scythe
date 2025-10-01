use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

/// Enterprise-grade cryptographic configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoConfig {
    /// Key management settings
    pub key_management: KeyManagementConfig,
    /// Security policies
    pub security_policies: SecurityPoliciesConfig,
    /// Rate limiting configuration
    pub rate_limiting: RateLimitingConfig,
    /// Audit and compliance settings
    pub audit: AuditConfig,
    /// Performance tuning
    pub performance: PerformanceConfig,
    /// Compliance standards to enforce
    pub compliance: ComplianceConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyManagementConfig {
    /// Key rotation threshold in seconds (default: 24 hours)
    pub rotation_threshold_seconds: u64,
    /// Maximum operations per key before rotation (default: 100,000)
    pub max_operations_per_key: u64,
    /// Number of old keys to retain for decryption (default: 5)
    pub old_key_retention_count: u8,
    /// Key derivation algorithm parameters
    pub kdf_config: KdfConfig,
    /// Hardware Security Module settings (if available)
    pub hsm_config: Option<HsmConfig>,
    /// Key escrow settings for compliance
    pub key_escrow: Option<KeyEscrowConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KdfConfig {
    /// PBKDF2 iterations for key derivation
    pub pbkdf2_iterations: u32,
    /// Argon2 memory cost in KB
    pub argon2_memory_cost: u32,
    /// Argon2 time cost
    pub argon2_time_cost: u32,
    /// Salt length in bytes
    pub salt_length: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HsmConfig {
    /// HSM provider (e.g., "pkcs11", "aws-cloudhsm", "azure-keyvault")
    pub provider: String,
    /// HSM connection configuration
    pub connection_config: HashMap<String, String>,
    /// Key slot or identifier in HSM
    pub key_slot: String,
    /// PIN or authentication credential
    pub auth_credential: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyEscrowConfig {
    /// Enable key escrow for compliance
    pub enabled: bool,
    /// Escrow agent public keys
    pub escrow_public_keys: Vec<String>,
    /// Minimum number of escrow agents required
    pub threshold: u8,
    /// Escrow key storage location
    pub storage_location: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityPoliciesConfig {
    /// Minimum password strength requirements
    pub password_policy: PasswordPolicyConfig,
    /// Allowed encryption algorithms
    pub allowed_algorithms: Vec<String>,
    /// Minimum key sizes for each algorithm
    pub minimum_key_sizes: HashMap<String, u32>,
    /// Maximum payload sizes
    pub max_payload_sizes: PayloadSizeLimits,
    /// IP-based access controls
    pub ip_restrictions: Option<IpRestrictionsConfig>,
    /// Time-based access controls
    pub time_restrictions: Option<TimeRestrictionsConfig>,
    /// Multi-factor authentication requirements
    pub mfa_requirements: MfaConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordPolicyConfig {
    /// Minimum password length
    pub min_length: u8,
    /// Require uppercase letters
    pub require_uppercase: bool,
    /// Require lowercase letters
    pub require_lowercase: bool,
    /// Require numbers
    pub require_numbers: bool,
    /// Require special characters
    pub require_special_chars: bool,
    /// Password history to prevent reuse
    pub password_history_count: u8,
    /// Password expiration in days
    pub expiration_days: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayloadSizeLimits {
    /// Maximum plaintext size in bytes
    pub max_plaintext_bytes: usize,
    /// Maximum encrypted payload size in bytes
    pub max_encrypted_bytes: usize,
    /// Maximum JSON payload size in bytes
    pub max_json_bytes: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpRestrictionsConfig {
    /// Allowed IP addresses/ranges
    pub allowed_ips: Vec<String>,
    /// Blocked IP addresses/ranges
    pub blocked_ips: Vec<String>,
    /// Enable geolocation filtering
    pub geolocation_filtering: bool,
    /// Allowed countries (ISO codes)
    pub allowed_countries: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeRestrictionsConfig {
    /// Allowed time windows (24-hour format, e.g., "09:00-17:00")
    pub allowed_time_windows: Vec<String>,
    /// Allowed days of week (0=Sunday, 6=Saturday)
    pub allowed_days: Vec<u8>,
    /// Timezone for time restrictions
    pub timezone: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MfaConfig {
    /// Require MFA for administrative operations
    pub require_for_admin: bool,
    /// Require MFA for key operations
    pub require_for_key_ops: bool,
    /// Allowed MFA methods
    pub allowed_methods: Vec<String>,
    /// MFA session timeout in minutes
    pub session_timeout_minutes: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitingConfig {
    /// Maximum operations per minute per client
    pub max_ops_per_minute: u64,
    /// Maximum operations per hour per client
    pub max_ops_per_hour: u64,
    /// Burst allowance
    pub burst_limit: u64,
    /// Block duration after rate limit exceeded (minutes)
    pub block_duration_minutes: u64,
    /// Global rate limits
    pub global_limits: Option<GlobalRateLimits>,
    /// Per-operation rate limits
    pub per_operation_limits: HashMap<String, u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobalRateLimits {
    /// Maximum total operations per second across all clients
    pub max_total_ops_per_second: u64,
    /// Maximum concurrent operations
    pub max_concurrent_operations: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditConfig {
    /// Enable detailed audit logging
    pub enabled: bool,
    /// Maximum audit logs to retain in memory
    pub max_logs_in_memory: usize,
    /// Audit log retention period in days
    pub retention_days: u32,
    /// Log levels to capture
    pub log_levels: Vec<String>,
    /// Export audit logs to external systems
    pub export_config: Option<AuditExportConfig>,
    /// Compliance reporting settings
    pub compliance_reporting: ComplianceReportingConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditExportConfig {
    /// Export destination (e.g., "syslog", "splunk", "elasticsearch")
    pub destination: String,
    /// Export configuration parameters
    pub config: HashMap<String, String>,
    /// Export frequency in minutes
    pub export_frequency_minutes: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceReportingConfig {
    /// Generate daily compliance reports
    pub daily_reports: bool,
    /// Generate weekly compliance reports
    pub weekly_reports: bool,
    /// Report recipients
    pub report_recipients: Vec<String>,
    /// Report format ("json", "csv", "pdf")
    pub report_format: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceConfig {
    /// Enable parallel processing for bulk operations
    pub parallel_processing: bool,
    /// Number of worker threads for crypto operations
    pub worker_threads: Option<usize>,
    /// Enable operation caching
    pub enable_caching: bool,
    /// Cache size limits
    pub cache_limits: CacheLimits,
    /// Performance monitoring thresholds
    pub performance_thresholds: PerformanceThresholds,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheLimits {
    /// Maximum cached keys
    pub max_cached_keys: usize,
    /// Cache TTL in seconds
    pub cache_ttl_seconds: u64,
    /// Maximum memory usage for caching in MB
    pub max_cache_memory_mb: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceThresholds {
    /// Warning threshold for operation duration (ms)
    pub operation_warning_ms: u64,
    /// Error threshold for operation duration (ms)
    pub operation_error_ms: u64,
    /// Memory usage warning threshold (MB)
    pub memory_warning_mb: usize,
    /// CPU usage warning threshold (percentage)
    pub cpu_warning_percent: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceConfig {
    /// FIPS 140-2 compliance mode
    pub fips_140_2: bool,
    /// Common Criteria compliance
    pub common_criteria: bool,
    /// PCI-DSS compliance requirements
    pub pci_dss: bool,
    /// HIPAA compliance requirements
    pub hipaa: bool,
    /// SOX compliance requirements
    pub sox: bool,
    /// Custom compliance frameworks
    pub custom_frameworks: Vec<String>,
    /// Data classification handling
    pub data_classification: DataClassificationConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataClassificationConfig {
    /// Enable data classification
    pub enabled: bool,
    /// Classification levels and their crypto requirements
    pub classification_levels: HashMap<String, ClassificationRequirements>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClassificationRequirements {
    /// Minimum encryption algorithm
    pub min_encryption_algorithm: String,
    /// Minimum key size
    pub min_key_size: u32,
    /// Key rotation frequency (seconds)
    pub key_rotation_frequency: u64,
    /// Additional security controls
    pub additional_controls: Vec<String>,
}

impl Default for CryptoConfig {
    fn default() -> Self {
        Self {
            key_management: KeyManagementConfig::default(),
            security_policies: SecurityPoliciesConfig::default(),
            rate_limiting: RateLimitingConfig::default(),
            audit: AuditConfig::default(),
            performance: PerformanceConfig::default(),
            compliance: ComplianceConfig::default(),
        }
    }
}

impl Default for KeyManagementConfig {
    fn default() -> Self {
        Self {
            rotation_threshold_seconds: 86400, // 24 hours
            max_operations_per_key: 100000,
            old_key_retention_count: 5,
            kdf_config: KdfConfig::default(),
            hsm_config: None,
            key_escrow: None,
        }
    }
}

impl Default for KdfConfig {
    fn default() -> Self {
        Self {
            pbkdf2_iterations: 100000,
            argon2_memory_cost: 65536, // 64 MB
            argon2_time_cost: 3,
            salt_length: 32,
        }
    }
}

impl Default for SecurityPoliciesConfig {
    fn default() -> Self {
        let mut minimum_key_sizes = HashMap::new();
        minimum_key_sizes.insert("AES".to_string(), 256);
        minimum_key_sizes.insert("RSA".to_string(), 2048);
        minimum_key_sizes.insert("ECDSA".to_string(), 256);

        Self {
            password_policy: PasswordPolicyConfig::default(),
            allowed_algorithms: vec!["AES-256-GCM".to_string(), "ChaCha20Poly1305".to_string()],
            minimum_key_sizes,
            max_payload_sizes: PayloadSizeLimits::default(),
            ip_restrictions: None,
            time_restrictions: None,
            mfa_requirements: MfaConfig::default(),
        }
    }
}

impl Default for PasswordPolicyConfig {
    fn default() -> Self {
        Self {
            min_length: 12,
            require_uppercase: true,
            require_lowercase: true,
            require_numbers: true,
            require_special_chars: true,
            password_history_count: 5,
            expiration_days: Some(90),
        }
    }
}

impl Default for PayloadSizeLimits {
    fn default() -> Self {
        Self {
            max_plaintext_bytes: 1024 * 1024,     // 1 MB
            max_encrypted_bytes: 2 * 1024 * 1024, // 2 MB
            max_json_bytes: 512 * 1024,           // 512 KB
        }
    }
}

impl Default for MfaConfig {
    fn default() -> Self {
        Self {
            require_for_admin: true,
            require_for_key_ops: false,
            allowed_methods: vec!["TOTP".to_string(), "SMS".to_string(), "Push".to_string()],
            session_timeout_minutes: 30,
        }
    }
}

impl Default for RateLimitingConfig {
    fn default() -> Self {
        let mut per_operation_limits = HashMap::new();
        per_operation_limits.insert("encrypt".to_string(), 1000);
        per_operation_limits.insert("decrypt".to_string(), 1000);
        per_operation_limits.insert("key_rotation".to_string(), 10);

        Self {
            max_ops_per_minute: 1000,
            max_ops_per_hour: 50000,
            burst_limit: 100,
            block_duration_minutes: 15,
            global_limits: Some(GlobalRateLimits {
                max_total_ops_per_second: 10000,
                max_concurrent_operations: 1000,
            }),
            per_operation_limits,
        }
    }
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_logs_in_memory: 10000,
            retention_days: 90,
            log_levels: vec!["INFO".to_string(), "WARN".to_string(), "ERROR".to_string()],
            export_config: None,
            compliance_reporting: ComplianceReportingConfig::default(),
        }
    }
}

impl Default for ComplianceReportingConfig {
    fn default() -> Self {
        Self {
            daily_reports: true,
            weekly_reports: true,
            report_recipients: vec!["security@company.com".to_string()],
            report_format: "json".to_string(),
        }
    }
}

impl Default for PerformanceConfig {
    fn default() -> Self {
        Self {
            parallel_processing: true,
            worker_threads: None, // Auto-detect based on CPU cores
            enable_caching: true,
            cache_limits: CacheLimits::default(),
            performance_thresholds: PerformanceThresholds::default(),
        }
    }
}

impl Default for CacheLimits {
    fn default() -> Self {
        Self {
            max_cached_keys: 1000,
            cache_ttl_seconds: 3600, // 1 hour
            max_cache_memory_mb: 100,
        }
    }
}

impl Default for PerformanceThresholds {
    fn default() -> Self {
        Self {
            operation_warning_ms: 1000, // 1 second
            operation_error_ms: 5000,   // 5 seconds
            memory_warning_mb: 1024,    // 1 GB
            cpu_warning_percent: 80.0,
        }
    }
}

impl Default for ComplianceConfig {
    fn default() -> Self {
        let mut classification_levels = HashMap::new();

        // Public data
        classification_levels.insert(
            "public".to_string(),
            ClassificationRequirements {
                min_encryption_algorithm: "AES-128-GCM".to_string(),
                min_key_size: 128,
                key_rotation_frequency: 7 * 24 * 3600, // 7 days
                additional_controls: vec![],
            },
        );

        // Internal data
        classification_levels.insert(
            "internal".to_string(),
            ClassificationRequirements {
                min_encryption_algorithm: "AES-256-GCM".to_string(),
                min_key_size: 256,
                key_rotation_frequency: 24 * 3600, // 1 day
                additional_controls: vec!["audit_logging".to_string()],
            },
        );

        // Confidential data
        classification_levels.insert(
            "confidential".to_string(),
            ClassificationRequirements {
                min_encryption_algorithm: "AES-256-GCM".to_string(),
                min_key_size: 256,
                key_rotation_frequency: 6 * 3600, // 6 hours
                additional_controls: vec![
                    "audit_logging".to_string(),
                    "mfa_required".to_string(),
                    "key_escrow".to_string(),
                ],
            },
        );

        Self {
            fips_140_2: false,
            common_criteria: false,
            pci_dss: false,
            hipaa: false,
            sox: false,
            custom_frameworks: vec![],
            data_classification: DataClassificationConfig {
                enabled: true,
                classification_levels,
            },
        }
    }
}

impl CryptoConfig {
    /// Load configuration from file
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, Box<dyn std::error::Error>> {
        let contents = std::fs::read_to_string(path)?;
        let config: CryptoConfig = toml::from_str(&contents)?;
        Ok(config)
    }

    /// Save configuration to file
    pub fn to_file<P: AsRef<Path>>(&self, path: P) -> Result<(), Box<dyn std::error::Error>> {
        let contents = toml::to_string_pretty(self)?;
        std::fs::write(path, contents)?;
        Ok(())
    }

    /// Validate configuration for security compliance
    pub fn validate(&self) -> Result<(), ConfigValidationError> {
        // Validate key management settings
        if self.key_management.rotation_threshold_seconds < 3600 {
            return Err(ConfigValidationError::InvalidKeyRotationThreshold);
        }

        if self.key_management.max_operations_per_key < 1000 {
            return Err(ConfigValidationError::InvalidMaxOperations);
        }

        // Validate security policies
        if self.security_policies.password_policy.min_length < 8 {
            return Err(ConfigValidationError::WeakPasswordPolicy);
        }

        // Validate payload limits
        if self.security_policies.max_payload_sizes.max_plaintext_bytes > 10 * 1024 * 1024 {
            return Err(ConfigValidationError::PayloadLimitTooHigh);
        }

        // Validate compliance settings
        if self.compliance.fips_140_2 {
            // FIPS 140-2 requires specific algorithms
            let fips_algorithms = vec!["AES-256-GCM"];
            for algo in &self.security_policies.allowed_algorithms {
                if !fips_algorithms.contains(&algo.as_str()) {
                    return Err(ConfigValidationError::NonFipsCompliantAlgorithm);
                }
            }
        }

        Ok(())
    }

    /// Get effective configuration for a specific data classification level
    pub fn get_classification_config(&self, level: &str) -> Option<&ClassificationRequirements> {
        if self.compliance.data_classification.enabled {
            self.compliance
                .data_classification
                .classification_levels
                .get(level)
        } else {
            None
        }
    }

    /// Check if an operation is allowed based on current policies
    pub fn is_operation_allowed(&self, operation: &str, payload_size: Option<usize>) -> bool {
        // Check payload size limits
        if let Some(size) = payload_size {
            match operation {
                "encrypt" | "decrypt" => {
                    if size > self.security_policies.max_payload_sizes.max_plaintext_bytes {
                        return false;
                    }
                }
                "encrypt_json" | "decrypt_json" => {
                    if size > self.security_policies.max_payload_sizes.max_json_bytes {
                        return false;
                    }
                }
                _ => {}
            }
        }

        // Check per-operation rate limits
        if let Some(&limit) = self.rate_limiting.per_operation_limits.get(operation) {
            // This would need to be checked against actual usage metrics
            // For now, just return true if limit exists
            limit > 0
        } else {
            true
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigValidationError {
    #[error("Key rotation threshold is too short (minimum 1 hour)")]
    InvalidKeyRotationThreshold,

    #[error("Maximum operations per key is too low (minimum 1000)")]
    InvalidMaxOperations,

    #[error("Password policy is too weak")]
    WeakPasswordPolicy,

    #[error("Payload size limit is too high (maximum 10MB)")]
    PayloadLimitTooHigh,

    #[error("Algorithm is not FIPS 140-2 compliant")]
    NonFipsCompliantAlgorithm,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config_validation() {
        let config = CryptoConfig::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_fips_compliance_validation() {
        let mut config = CryptoConfig::default();
        config.compliance.fips_140_2 = true;
        config.security_policies.allowed_algorithms = vec!["AES-128-GCM".to_string()];

        assert!(config.validate().is_err());
    }

    #[test]
    fn test_operation_allowed() {
        let config = CryptoConfig::default();

        // Should allow normal operations
        assert!(config.is_operation_allowed("encrypt", Some(1024)));

        // Should block oversized operations
        assert!(!config.is_operation_allowed("encrypt", Some(10 * 1024 * 1024)));
    }

    #[test]
    fn test_classification_config() {
        let config = CryptoConfig::default();

        let confidential_config = config.get_classification_config("confidential");
        assert!(confidential_config.is_some());

        let unknown_config = config.get_classification_config("unknown");
        assert!(unknown_config.is_none());
    }
}
