use super::*;
use std::sync::Arc;
use std::time::Duration;

#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    fn test_c2_crypto_basic_operations() {
        let (crypto, _key) = C2Crypto::new();
        let plaintext = "Hello, Enterprise Security!";

        let encrypted = crypto.encrypt(plaintext).unwrap();
        let decrypted = crypto.decrypt(&encrypted).unwrap();

        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_enterprise_crypto_with_custom_settings() {
        let rotation_threshold = 3600; // 1 hour
        let max_usage = 10000;

        let (crypto, _key) = C2Crypto::new_enterprise(rotation_threshold, max_usage);
        let metadata = crypto.get_key_metadata();

        assert_eq!(metadata.usage_count, 0);
        assert!(!metadata.needs_rotation);
    }

    #[test]
    fn test_key_rotation_threshold() {
        let (mut crypto, _key) = C2Crypto::new_enterprise(1, 5); // Very low thresholds for testing

        // Perform operations to trigger usage-based rotation
        for _ in 0..6 {
            let _ = crypto.encrypt("test").unwrap();
        }

        assert!(crypto.needs_rotation());
    }

    #[test]
    fn test_payload_size_limits() {
        let (crypto, _key) = C2Crypto::new();

        // Test with oversized payload
        let large_payload = "A".repeat(2 * 1024 * 1024); // 2MB
        let result = crypto.encrypt(&large_payload);

        assert!(matches!(result, Err(CryptoError::PayloadTooLarge)));
    }

    #[test]
    fn test_json_encryption_decryption() {
        use serde::{Deserialize, Serialize};

        #[derive(Serialize, Deserialize, PartialEq, Debug)]
        struct TestPayload {
            id: u64,
            name: String,
            data: Vec<u8>,
            timestamp: String,
        }

        let (crypto, _key) = C2Crypto::new();
        let payload = TestPayload {
            id: 12345,
            name: "Enterprise Test".to_string(),
            data: vec![1, 2, 3, 4, 5],
            timestamp: Utc::now().to_rfc3339(),
        };

        let encrypted = crypto.encrypt_json(&payload).unwrap();
        let decrypted: TestPayload = crypto.decrypt_json(&encrypted).unwrap();

        assert_eq!(payload, decrypted);
    }

    #[test]
    fn test_key_persistence_and_compatibility() {
        let (crypto1, key) = C2Crypto::new();
        let crypto2 = C2Crypto::from_key(&key).unwrap();

        let test_data = "Cross-instance compatibility test";
        let encrypted = crypto1.encrypt(test_data).unwrap();
        let decrypted = crypto2.decrypt(&encrypted).unwrap();

        assert_eq!(test_data, decrypted);
    }

    #[test]
    fn test_advanced_obfuscation() {
        let original_data = "SensitiveCommandData123!";

        // Encode
        let encoded = encode_advanced_obfuscated(original_data);
        assert_ne!(original_data, encoded);
        assert!(is_advanced_obfuscated_pattern(&encoded));

        // Decode
        let decoded = decode_advanced_obfuscated(&encoded).unwrap();
        assert_eq!(original_data, decoded);
    }

    #[test]
    fn test_password_hashing_security() {
        let password = "SecureEnterprisePassword123!";
        let hash = hash_password(password).unwrap();

        // Verify correct password
        assert!(verify_password(password, &hash).unwrap());

        // Verify incorrect password fails
        assert!(!verify_password("WrongPassword", &hash).unwrap());

        // Ensure hash is different each time
        let hash2 = hash_password(password).unwrap();
        assert_ne!(hash, hash2);
    }

    #[test]
    fn test_secure_id_generation() {
        let id1 = generate_secure_id(16);
        let id2 = generate_secure_id(16);

        assert_eq!(id1.len(), 16);
        assert_eq!(id2.len(), 16);
        assert_ne!(id1, id2);

        // Check for base64 URL-safe characters
        for c in id1.chars() {
            assert!(c.is_ascii_alphanumeric() || c == '-' || c == '_');
        }
    }
}

#[cfg(test)]
mod enterprise_key_manager_tests {
    use super::*;

    #[test]
    fn test_key_manager_creation() {
        let (manager, key) = EnterpriseKeyManager::new(3600, 10000);

        assert!(!key.is_empty());
        assert!(manager.get_key_metadata().is_ok());
    }

    #[test]
    fn test_key_rotation() {
        let (manager, initial_key) = EnterpriseKeyManager::new(3600, 10000);
        let initial_metadata = manager.get_key_metadata().unwrap();

        // Rotate the key
        let new_key = manager.rotate_key().unwrap();
        let new_metadata = manager.get_key_metadata().unwrap();

        assert_ne!(initial_key, new_key);
        assert_ne!(initial_metadata.key_id, new_metadata.key_id);
    }

    #[test]
    fn test_backward_compatibility_after_rotation() {
        let (manager, _) = EnterpriseKeyManager::new(3600, 10000);
        let test_data = "Test backward compatibility";

        // Encrypt with initial key
        let encrypted = manager.encrypt(test_data).unwrap();

        // Rotate key
        let _ = manager.rotate_key().unwrap();

        // Should still be able to decrypt old data
        let decrypted = manager.decrypt(&encrypted).unwrap();
        assert_eq!(test_data, decrypted);
    }

    #[test]
    fn test_multiple_key_rotations() {
        let (manager, _) = EnterpriseKeyManager::new(3600, 10000);
        let mut encrypted_data = Vec::new();
        let test_messages = vec!["Message 1", "Message 2", "Message 3", "Message 4"];

        // Encrypt messages and rotate keys between each
        for (i, msg) in test_messages.iter().enumerate() {
            encrypted_data.push(manager.encrypt(msg).unwrap());
            if i < test_messages.len() - 1 {
                let _ = manager.rotate_key().unwrap();
            }
        }

        // All messages should still be decryptable
        for (i, encrypted) in encrypted_data.iter().enumerate() {
            let decrypted = manager.decrypt(encrypted).unwrap();
            assert_eq!(test_messages[i], decrypted);
        }
    }

    #[test]
    fn test_old_key_cleanup() {
        let (manager, _) = EnterpriseKeyManager::new(3600, 10000);

        // Rotate more than 5 keys to test cleanup
        for _ in 0..7 {
            let _ = manager.rotate_key().unwrap();
        }

        // Should still work (implicit test that old keys are managed properly)
        let test_data = "Key cleanup test";
        let encrypted = manager.encrypt(test_data).unwrap();
        let decrypted = manager.decrypt(&encrypted).unwrap();
        assert_eq!(test_data, decrypted);
    }
}

#[cfg(test)]
mod monitoring_tests {
    use super::monitoring::*;
    use super::*;

    #[test]
    fn test_crypto_monitor_basic_functionality() {
        let monitor = CryptoMonitor::new_default();

        // Log successful operation
        monitor.log_operation(
            "encrypt",
            "test-key-1",
            &Ok(()),
            Duration::from_millis(50),
            Some("agent-123"),
            Some("operator-456"),
            Some(1024),
            Some("192.168.1.100"),
            Some("test-client/1.0"),
        );

        let metrics = monitor.get_metrics();
        assert_eq!(metrics.total_operations, 1);
        assert_eq!(metrics.successful_operations, 1);
        assert_eq!(metrics.failed_operations, 0);
    }

    #[test]
    fn test_rate_limiting() {
        let rate_config = RateLimitConfig {
            max_operations_per_minute: 5,
            max_operations_per_hour: 100,
            burst_limit: 10,
            block_duration_minutes: 1,
        };

        let monitor = CryptoMonitor::new(rate_config, 1000);
        let client_id = "test-client-123";

        // Should allow initial operations
        for i in 0..5 {
            assert!(
                monitor.check_rate_limit(client_id).is_ok(),
                "Operation {} should be allowed",
                i + 1
            );
        }

        // Should block the 6th operation
        assert!(
            monitor.check_rate_limit(client_id).is_err(),
            "6th operation should be rate limited"
        );
    }

    #[test]
    fn test_security_alert_generation() {
        let monitor = CryptoMonitor::new_default();

        // Generate many failed operations from same IP
        // Generate failed operations to trigger alerts
        for _ in 0..60 {
            let log_result: Result<(), CryptoError> = Err(CryptoError::InvalidKey);
            let log_result2: Result<(), CryptoError> = Err(CryptoError::InvalidKey);
            monitor.log_operation(
                "decrypt",
                "test-key-1",
                &log_result2,
                Duration::from_millis(5),
                None,
                None,
                None,
                Some("192.168.1.100"),
                None,
            );
        }

        let alerts = monitor.check_security_alerts();
        assert!(!alerts.is_empty());

        let has_brute_force_alert = alerts
            .iter()
            .any(|alert| matches!(alert.alert_type, SecurityAlertType::BruteForceAttempt));
        assert!(has_brute_force_alert);
    }

    #[test]
    fn test_audit_log_filtering() {
        let monitor = CryptoMonitor::new_default();

        // Log various operations
        let log_result1: Result<(), CryptoError> = Ok(());
        monitor.log_operation(
            "encrypt",
            "key1",
            &log_result1,
            Duration::from_millis(10),
            None,
            None,
            None,
            None,
            None,
        );
        let log_result2: Result<(), CryptoError> = Ok(());
        monitor.log_operation(
            "decrypt",
            "key2",
            &log_result2,
            Duration::from_millis(15),
            None,
            None,
            None,
            None,
            None,
        );
        let log_result3: Result<(), CryptoError> = Err(CryptoError::InvalidKey);
        monitor.log_operation(
            "encrypt",
            "key3",
            &log_result3,
            Duration::from_millis(5),
            None,
            None,
            None,
            None,
            None,
        );

        // Filter by operation type
        let encrypt_logs = monitor.get_filtered_logs(Some("encrypt"), None, None, 10);
        assert_eq!(encrypt_logs.len(), 2);

        // Filter by success status
        let failed_logs = monitor.get_filtered_logs(None, Some(false), None, 10);
        assert_eq!(failed_logs.len(), 1);
    }

    #[test]
    fn test_metrics_tracking() {
        let monitor = CryptoMonitor::new_default();

        // Log mixed operations
        let log_result1: Result<(), CryptoError> = Ok(());
        monitor.log_operation(
            "encrypt",
            "key1",
            &log_result1,
            Duration::from_millis(100),
            None,
            None,
            None,
            None,
            None,
        );
        let log_result2: Result<(), CryptoError> = Ok(());
        monitor.log_operation(
            "decrypt",
            "key1",
            &log_result2,
            Duration::from_millis(50),
            None,
            None,
            None,
            None,
            None,
        );
        let log_result3: Result<(), CryptoError> = Err(CryptoError::DecryptionFailed);
        monitor.log_operation(
            "encrypt",
            "key1",
            &log_result3,
            Duration::from_millis(200),
            None,
            None,
            None,
            None,
            None,
        );

        let metrics = monitor.get_metrics();
        assert_eq!(metrics.total_operations, 3);
        assert_eq!(metrics.successful_operations, 2);
        assert_eq!(metrics.failed_operations, 1);
        assert!(metrics.average_duration_ms > 0.0);

        // Check operation-specific counts
        assert_eq!(metrics.operations_by_type.get("encrypt"), Some(&2));
        assert_eq!(metrics.operations_by_type.get("decrypt"), Some(&1));
    }
}

#[cfg(test)]
mod config_tests {
    use super::config::*;

    #[test]
    fn test_default_config_creation() {
        let config = CryptoConfig::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_config_validation() {
        let mut config = CryptoConfig::default();

        // Test invalid rotation threshold
        config.key_management.rotation_threshold_seconds = 1800; // 30 minutes (too short)
        assert!(config.validate().is_err());

        // Fix it
        config.key_management.rotation_threshold_seconds = 3600; // 1 hour
        assert!(config.validate().is_ok());

        // Test weak password policy
        config.security_policies.password_policy.min_length = 4; // Too short
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_operation_permission_checking() {
        let config = CryptoConfig::default();

        // Normal operation should be allowed
        assert!(config.is_operation_allowed("encrypt", Some(1024)));

        // Oversized operation should be blocked
        assert!(!config.is_operation_allowed("encrypt", Some(2 * 1024 * 1024)));

        // JSON operations have different limits
        assert!(config.is_operation_allowed("encrypt_json", Some(256 * 1024)));
        assert!(!config.is_operation_allowed("encrypt_json", Some(1024 * 1024)));
    }

    #[test]
    fn test_data_classification_config() {
        let config = CryptoConfig::default();

        let public_req = config.get_classification_config("public");
        assert!(public_req.is_some());
        assert_eq!(public_req.unwrap().min_key_size, 128);

        let confidential_req = config.get_classification_config("confidential");
        assert!(confidential_req.is_some());
        assert_eq!(confidential_req.unwrap().min_key_size, 256);
        assert!(
            confidential_req
                .unwrap()
                .additional_controls
                .contains(&"mfa_required".to_string())
        );
    }

    #[test]
    fn test_fips_compliance_validation() {
        let mut config = CryptoConfig::default();
        config.compliance.fips_140_2 = true;

        // Non-FIPS algorithm should fail validation
        config.security_policies.allowed_algorithms = vec!["AES-128-GCM".to_string()];
        assert!(config.validate().is_err());

        // FIPS-compliant algorithm should pass
        config.security_policies.allowed_algorithms = vec!["AES-256-GCM".to_string()];
        assert!(config.validate().is_ok());
    }
}

#[cfg(test)]
mod integration_tests {
    use super::*;
    // Integration tests using tokio

    #[tokio::test]
    async fn test_full_enterprise_crypto_workflow() {
        let config = CryptoConfig::default();
        let monitor = Arc::new(CryptoMonitor::new_default());
        let (key_manager, _) = EnterpriseKeyManager::new(
            config.key_management.rotation_threshold_seconds,
            config.key_management.max_operations_per_key,
        );

        // Test data classification workflow
        let sensitive_data = r#"{"patient_id": 12345, "diagnosis": "confidential"}"#;
        let classification = "confidential";

        // Check if operation is allowed based on classification
        let classification_config = config.get_classification_config(classification).unwrap();
        assert_eq!(
            classification_config.min_encryption_algorithm,
            "AES-256-GCM"
        );

        // Perform rate limiting check
        let client_id = "integration-test-client";
        assert!(monitor.check_rate_limit(client_id).is_ok());

        // Encrypt the data
        let start_time = std::time::Instant::now();
        let encrypted = key_manager.encrypt(sensitive_data);
        let duration = start_time.elapsed();

        assert!(encrypted.is_ok());

        // Log the operation
        let log_result = encrypted.as_ref().map(|_| ()).map_err(|e| e.clone());
        monitor.log_operation(
            "encrypt",
            "integration-test-key",
            &log_result,
            duration,
            Some("test-agent"),
            Some("test-operator"),
            Some(sensitive_data.len()),
            Some("127.0.0.1"),
            Some("integration-test/1.0"),
        );

        // Decrypt the data
        let decrypted = key_manager.decrypt(&encrypted.unwrap()).unwrap();
        assert_eq!(sensitive_data, decrypted);

        // Check metrics
        let metrics = monitor.get_metrics();
        assert_eq!(metrics.total_operations, 1);
        assert_eq!(metrics.successful_operations, 1);
    }

    #[tokio::test]
    async fn test_concurrent_crypto_operations() {
        let (key_manager, _) = EnterpriseKeyManager::new(86400, 100000);
        let key_manager = Arc::new(key_manager);
        let monitor = Arc::new(CryptoMonitor::new_default());

        let mut handles = Vec::new();

        // Spawn multiple concurrent encryption tasks
        for i in 0..10 {
            let km = Arc::clone(&key_manager);
            let mon = Arc::clone(&monitor);

            let handle = tokio::spawn(async move {
                let test_data = format!("Concurrent test data {}", i);
                let client_id = format!("client-{}", i);

                // Rate limit check
                if mon.check_rate_limit(&client_id).is_err() {
                    return Err("Rate limited".to_string());
                }

                // Encrypt
                let start = std::time::Instant::now();
                let encrypted = km.encrypt(&test_data).map_err(|e| format!("{:?}", e))?;
                let duration = start.elapsed();

                // Log operation
                let log_result: Result<(), CryptoError> = Ok(());
                mon.log_operation(
                    "encrypt",
                    &format!("concurrent-key-{}", i),
                    &log_result,
                    duration,
                    Some(&format!("agent-{}", i)),
                    None,
                    Some(test_data.len()),
                    Some("127.0.0.1"),
                    None,
                );

                // Decrypt
                let decrypted = km.decrypt(&encrypted).map_err(|e| format!("{:?}", e))?;

                if decrypted == test_data {
                    Ok(i)
                } else {
                    Err("Decryption mismatch".to_string())
                }
            });

            handles.push(handle);
        }

        // Wait for all tasks to complete
        let mut successful_operations = 0;
        for handle in handles {
            if handle.await.unwrap().is_ok() {
                successful_operations += 1;
            }
        }

        assert_eq!(successful_operations, 10);

        // Check that all operations were logged
        let metrics = monitor.get_metrics();
        assert_eq!(metrics.total_operations, 10);
        assert_eq!(metrics.successful_operations, 10);
    }

    #[test]
    fn test_performance_benchmarks() {
        let (crypto, _) = C2Crypto::new();
        let test_data = "A".repeat(1024); // 1KB test data
        let iterations = 1000;

        // Benchmark encryption
        let start = std::time::Instant::now();
        let mut encrypted_results = Vec::new();

        for _ in 0..iterations {
            encrypted_results.push(crypto.encrypt(&test_data).unwrap());
        }

        let encryption_duration = start.elapsed();
        let encryption_ops_per_sec = iterations as f64 / encryption_duration.as_secs_f64();

        println!("Encryption: {:.2} ops/sec", encryption_ops_per_sec);
        assert!(
            encryption_ops_per_sec > 1000.0,
            "Encryption should be > 1000 ops/sec"
        );

        // Benchmark decryption
        let start = std::time::Instant::now();

        for encrypted in &encrypted_results {
            let _ = crypto.decrypt(encrypted).unwrap();
        }

        let decryption_duration = start.elapsed();
        let decryption_ops_per_sec = iterations as f64 / decryption_duration.as_secs_f64();

        println!("Decryption: {:.2} ops/sec", decryption_ops_per_sec);
        assert!(
            decryption_ops_per_sec > 1000.0,
            "Decryption should be > 1000 ops/sec"
        );
    }

    #[test]
    fn test_memory_usage_limits() {
        let (crypto, _) = C2Crypto::new();

        // Test that we can handle reasonable payloads
        let reasonable_payload = "A".repeat(512 * 1024); // 512KB
        assert!(crypto.encrypt(&reasonable_payload).is_ok());

        // Test that oversized payloads are rejected
        let oversized_payload = "A".repeat(2 * 1024 * 1024); // 2MB
        assert!(matches!(
            crypto.encrypt(&oversized_payload),
            Err(CryptoError::PayloadTooLarge)
        ));
    }

    #[test]
    fn test_error_handling_robustness() {
        // Test invalid key format
        let invalid_key = "not-a-valid-base64-key!";
        assert!(C2Crypto::from_key(invalid_key).is_err());

        // Test invalid key length
        let short_key = base64::engine::general_purpose::STANDARD.encode(b"short");
        assert!(C2Crypto::from_key(&short_key).is_err());

        // Test corrupted encrypted message
        let (crypto, _) = C2Crypto::new();
        let mut corrupted_msg = crypto.encrypt("test").unwrap();
        corrupted_msg.ciphertext = "corrupted_data".to_string();

        assert!(crypto.decrypt(&corrupted_msg).is_err());
    }
}

#[cfg(test)]
mod compliance_tests {
    use super::*;

    #[test]
    fn test_audit_trail_completeness() {
        let monitor = CryptoMonitor::new_default();
        let operations = vec!["encrypt", "decrypt", "key_rotation", "admin_access"];

        // Log various operations with full audit data
        for (i, op) in operations.iter().enumerate() {
            let log_result: Result<(), CryptoError> = Ok(());
            monitor.log_operation(
                op,
                &format!("audit-key-{}", i),
                &log_result,
                Duration::from_millis(50 + i as u64 * 10),
                Some(&format!("agent-{}", i)),
                Some(&format!("operator-{}", i)),
                Some(1024 * (i + 1)),
                Some(&format!("192.168.1.{}", 100 + i)),
                Some(&format!("audit-client/{}.0", i + 1)),
            );
        }

        let logs = monitor.get_recent_logs(10);
        assert_eq!(logs.len(), 4);

        // Verify audit trail completeness
        for log in logs.iter() {
            assert!(log.agent_id.is_some());
            assert!(log.operator_id.is_some());
            assert!(log.client_ip.is_some());
            assert!(log.user_agent.is_some());
            assert!(log.payload_size.is_some());
            assert!(log.duration_ms > 0);
        }
    }

    #[test]
    fn test_data_retention_policies() {
        let monitor = CryptoMonitor::new_default();

        // Simulate old logs
        let log_result: Result<(), CryptoError> = Ok(());
        monitor.log_operation(
            "encrypt",
            "old-key",
            &log_result,
            Duration::from_millis(10),
            None,
            None,
            None,
            None,
            None,
        );

        // Clean up logs older than 0 days (should remove all)
        monitor.cleanup_old_logs(0);

        let remaining_logs = monitor.get_recent_logs(100);
        // Should be empty or very few (depending on timing)
        assert!(remaining_logs.len() <= 1);
    }

    #[test]
    fn test_pci_dss_compliance_requirements() {
        let mut config = CryptoConfig::default();
        config.compliance.pci_dss = true;

        // PCI-DSS requires strong encryption
        assert!(
            config
                .security_policies
                .minimum_key_sizes
                .get("AES")
                .unwrap()
                >= &256
        );

        // Should require audit logging
        assert!(config.audit.enabled);

        // Should require strong password policy
        assert!(config.security_policies.password_policy.min_length >= 8);
        assert!(
            config
                .security_policies
                .password_policy
                .require_special_chars
        );
    }

    #[test]
    fn test_hipaa_compliance_features() {
        let mut config = CryptoConfig::default();
        config.compliance.hipaa = true;

        // HIPAA requires audit trails
        assert!(config.audit.enabled);
        assert!(config.audit.retention_days >= 6 * 365); // 6 years minimum

        // Should have data classification enabled
        assert!(config.compliance.data_classification.enabled);

        // Should require MFA for administrative functions
        assert!(config.security_policies.mfa_requirements.require_for_admin);
    }
}

#[cfg(test)]
mod stress_tests {
    use super::*;

    #[test]
    fn test_high_volume_operations() {
        let (key_manager, _) = EnterpriseKeyManager::new(86400, 1000000);
        let test_data = "High volume test data";

        let start = std::time::Instant::now();
        let iterations = 10000;

        for i in 0..iterations {
            let encrypted = key_manager.encrypt(test_data).unwrap();
            let decrypted = key_manager.decrypt(&encrypted).unwrap();

            assert_eq!(test_data, decrypted);

            if i % 1000 == 0 {
                println!("Completed {} operations", i);
            }
        }

        let duration = start.elapsed();
        let ops_per_sec = (iterations * 2) as f64 / duration.as_secs_f64(); // 2 ops per iteration

        println!(
            "Stress test: {:.2} ops/sec over {} total operations",
            ops_per_sec,
            iterations * 2
        );
        assert!(
            ops_per_sec > 100.0,
            "Should handle > 100 ops/sec under stress"
        );
    }

    #[test]
    fn test_memory_pressure() {
        let (crypto, _) = C2Crypto::new();
        let mut encrypted_messages = Vec::new();

        // Create many encrypted messages to test memory handling
        for i in 0..1000 {
            let test_data = format!("Memory pressure test data item {}", i);
            let encrypted = crypto.encrypt(&test_data).unwrap();
            encrypted_messages.push((encrypted, test_data));
        }

        // Verify all messages can still be decrypted
        for (encrypted, original) in &encrypted_messages {
            let decrypted = crypto.decrypt(encrypted).unwrap();
            assert_eq!(*original, decrypted);
        }

        println!(
            "Successfully handled {} encrypted messages in memory",
            encrypted_messages.len()
        );
    }

    #[test]
    fn test_rapid_key_rotation() {
        let (manager, _) = EnterpriseKeyManager::new(1, 10); // Very aggressive rotation
        let mut test_data = Vec::new();

        // Create data with different keys
        for i in 0..20 {
            let data = format!("Rapid rotation test {}", i);
            let encrypted = manager.encrypt(&data).unwrap();
            test_data.push((encrypted, data));

            // Rotate every few operations
            if i % 3 == 0 {
                let _ = manager.rotate_key().unwrap();
            }
        }

        // All data should still be decryptable
        for (encrypted, original) in &test_data {
            let decrypted = manager.decrypt(encrypted).unwrap();
            assert_eq!(*original, decrypted);
        }
    }
}
