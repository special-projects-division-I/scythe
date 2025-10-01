use chrono::{DateTime, Utc};
use log::{debug, error, info, warn};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use super::CryptoError;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoAuditLog {
    pub timestamp: DateTime<Utc>,
    pub operation: String,
    pub key_id: String,
    pub agent_id: Option<String>,
    pub operator_id: Option<String>,
    pub success: bool,
    pub error_type: Option<String>,
    pub payload_size: Option<usize>,
    pub duration_ms: u64,
    pub client_ip: Option<String>,
    pub user_agent: Option<String>,
}

#[derive(Debug, Clone)]
pub struct CryptoMetrics {
    pub total_operations: u64,
    pub successful_operations: u64,
    pub failed_operations: u64,
    pub average_duration_ms: f64,
    pub last_reset: DateTime<Utc>,
    pub operations_by_type: HashMap<String, u64>,
    pub errors_by_type: HashMap<String, u64>,
}

#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    pub max_operations_per_minute: u64,
    pub max_operations_per_hour: u64,
    pub burst_limit: u64,
    pub block_duration_minutes: u64,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            max_operations_per_minute: 1000,
            max_operations_per_hour: 50000,
            burst_limit: 100,
            block_duration_minutes: 15,
        }
    }
}

#[derive(Debug)]
struct RateLimitEntry {
    count_minute: u64,
    count_hour: u64,
    last_reset_minute: Instant,
    last_reset_hour: Instant,
    blocked_until: Option<Instant>,
}

pub struct CryptoMonitor {
    audit_logs: Arc<RwLock<Vec<CryptoAuditLog>>>,
    metrics: Arc<RwLock<CryptoMetrics>>,
    rate_limits: Arc<RwLock<HashMap<String, RateLimitEntry>>>,
    rate_limit_config: RateLimitConfig,
    max_audit_logs: usize,
}

impl CryptoMonitor {
    pub fn new(rate_limit_config: RateLimitConfig, max_audit_logs: usize) -> Self {
        Self {
            audit_logs: Arc::new(RwLock::new(Vec::new())),
            metrics: Arc::new(RwLock::new(CryptoMetrics {
                total_operations: 0,
                successful_operations: 0,
                failed_operations: 0,
                average_duration_ms: 0.0,
                last_reset: Utc::now(),
                operations_by_type: HashMap::new(),
                errors_by_type: HashMap::new(),
            })),
            rate_limits: Arc::new(RwLock::new(HashMap::new())),
            rate_limit_config,
            max_audit_logs,
        }
    }

    pub fn new_default() -> Self {
        Self::new(RateLimitConfig::default(), 10000)
    }

    /// Check if an operation is allowed based on rate limiting
    pub fn check_rate_limit(&self, client_identifier: &str) -> Result<(), CryptoError> {
        let mut rate_limits = self.rate_limits.write().unwrap();
        let now = Instant::now();

        let entry = rate_limits
            .entry(client_identifier.to_string())
            .or_insert(RateLimitEntry {
                count_minute: 0,
                count_hour: 0,
                last_reset_minute: now,
                last_reset_hour: now,
                blocked_until: None,
            });

        // Check if currently blocked
        if let Some(blocked_until) = entry.blocked_until {
            if now < blocked_until {
                warn!("Rate limit block still active for {}", client_identifier);
                return Err(CryptoError::RateLimitExceeded);
            } else {
                entry.blocked_until = None;
            }
        }

        // Reset minute counter if needed
        if now.duration_since(entry.last_reset_minute) >= Duration::from_secs(60) {
            entry.count_minute = 0;
            entry.last_reset_minute = now;
        }

        // Reset hour counter if needed
        if now.duration_since(entry.last_reset_hour) >= Duration::from_secs(3600) {
            entry.count_hour = 0;
            entry.last_reset_hour = now;
        }

        // Check limits
        if entry.count_minute >= self.rate_limit_config.max_operations_per_minute {
            warn!("Rate limit exceeded (per minute) for {}", client_identifier);
            entry.blocked_until =
                Some(now + Duration::from_secs(self.rate_limit_config.block_duration_minutes * 60));
            return Err(CryptoError::RateLimitExceeded);
        }

        if entry.count_hour >= self.rate_limit_config.max_operations_per_hour {
            warn!("Rate limit exceeded (per hour) for {}", client_identifier);
            entry.blocked_until =
                Some(now + Duration::from_secs(self.rate_limit_config.block_duration_minutes * 60));
            return Err(CryptoError::RateLimitExceeded);
        }

        // Increment counters
        entry.count_minute += 1;
        entry.count_hour += 1;

        Ok(())
    }

    /// Log a crypto operation with full audit trail
    pub fn log_operation(
        &self,
        operation: &str,
        key_id: &str,
        result: &Result<(), CryptoError>,
        duration: Duration,
        agent_id: Option<&str>,
        operator_id: Option<&str>,
        payload_size: Option<usize>,
        client_ip: Option<&str>,
        user_agent: Option<&str>,
    ) {
        let audit_log = CryptoAuditLog {
            timestamp: Utc::now(),
            operation: operation.to_string(),
            key_id: key_id.to_string(),
            agent_id: agent_id.map(|s| s.to_string()),
            operator_id: operator_id.map(|s| s.to_string()),
            success: result.is_ok(),
            error_type: result.as_ref().err().map(|e| format!("{:?}", e)),
            payload_size,
            duration_ms: duration.as_millis() as u64,
            client_ip: client_ip.map(|s| s.to_string()),
            user_agent: user_agent.map(|s| s.to_string()),
        };

        // Log to system logger
        if result.is_ok() {
            debug!(
                "Crypto operation succeeded: {} for key {} in {}ms",
                operation,
                key_id,
                duration.as_millis()
            );
        } else {
            error!(
                "Crypto operation failed: {} for key {} - {:?} in {}ms",
                operation,
                key_id,
                result.as_ref().err().unwrap(),
                duration.as_millis()
            );
        }

        // Store in audit log
        {
            let mut logs = self.audit_logs.write().unwrap();
            logs.push(audit_log);

            // Trim logs if they exceed max size
            if logs.len() > self.max_audit_logs {
                let excess = logs.len() - self.max_audit_logs;
                logs.drain(0..excess);
            }
        }

        // Update metrics
        {
            let mut metrics = self.metrics.write().unwrap();
            metrics.total_operations += 1;

            if result.is_ok() {
                metrics.successful_operations += 1;
            } else {
                metrics.failed_operations += 1;
                if let Err(error) = result {
                    let error_type = format!("{:?}", error);
                    *metrics.errors_by_type.entry(error_type).or_insert(0) += 1;
                }
            }

            *metrics
                .operations_by_type
                .entry(operation.to_string())
                .or_insert(0) += 1;

            // Update average duration
            let total_duration =
                metrics.average_duration_ms * (metrics.total_operations - 1) as f64;
            metrics.average_duration_ms =
                (total_duration + duration.as_millis() as f64) / metrics.total_operations as f64;
        }
    }

    /// Get current metrics snapshot
    pub fn get_metrics(&self) -> CryptoMetrics {
        self.metrics.read().unwrap().clone()
    }

    /// Get recent audit logs
    pub fn get_recent_logs(&self, limit: usize) -> Vec<CryptoAuditLog> {
        let logs = self.audit_logs.read().unwrap();
        let start = if logs.len() > limit {
            logs.len() - limit
        } else {
            0
        };
        logs[start..].to_vec()
    }

    /// Get audit logs filtered by criteria
    pub fn get_filtered_logs(
        &self,
        operation_filter: Option<&str>,
        success_filter: Option<bool>,
        since: Option<DateTime<Utc>>,
        limit: usize,
    ) -> Vec<CryptoAuditLog> {
        let logs = self.audit_logs.read().unwrap();

        logs.iter()
            .filter(|log| {
                if let Some(op) = operation_filter {
                    if log.operation != op {
                        return false;
                    }
                }
                if let Some(success) = success_filter {
                    if log.success != success {
                        return false;
                    }
                }
                if let Some(since_time) = since {
                    if log.timestamp < since_time {
                        return false;
                    }
                }
                true
            })
            .rev()
            .take(limit)
            .cloned()
            .collect()
    }

    /// Reset metrics (typically called daily/weekly)
    pub fn reset_metrics(&self) {
        let mut metrics = self.metrics.write().unwrap();
        *metrics = CryptoMetrics {
            total_operations: 0,
            successful_operations: 0,
            failed_operations: 0,
            average_duration_ms: 0.0,
            last_reset: Utc::now(),
            operations_by_type: HashMap::new(),
            errors_by_type: HashMap::new(),
        };
        info!("Crypto metrics reset");
    }

    /// Clear old audit logs based on age
    pub fn cleanup_old_logs(&self, older_than_days: u64) {
        let cutoff = Utc::now() - chrono::Duration::days(older_than_days as i64);
        let mut logs = self.audit_logs.write().unwrap();
        let original_count = logs.len();

        logs.retain(|log| log.timestamp > cutoff);

        let removed_count = original_count - logs.len();
        if removed_count > 0 {
            info!(
                "Cleaned up {} old audit logs (older than {} days)",
                removed_count, older_than_days
            );
        }
    }

    /// Generate security alert based on patterns
    pub fn check_security_alerts(&self) -> Vec<SecurityAlert> {
        let mut alerts = Vec::new();
        let metrics = self.metrics.read().unwrap();

        // High failure rate alert
        if metrics.total_operations > 100 {
            let failure_rate = metrics.failed_operations as f64 / metrics.total_operations as f64;
            if failure_rate > 0.1 {
                alerts.push(SecurityAlert {
                    alert_type: SecurityAlertType::HighFailureRate,
                    message: format!(
                        "High crypto operation failure rate: {:.2}%",
                        failure_rate * 100.0
                    ),
                    timestamp: Utc::now(),
                    severity: AlertSeverity::Medium,
                });
            }
        }

        // Suspicious error patterns
        for (error_type, count) in &metrics.errors_by_type {
            if *count > 50 && error_type.contains("InvalidKey") {
                alerts.push(SecurityAlert {
                    alert_type: SecurityAlertType::SuspiciousActivity,
                    message: format!("High number of invalid key attempts: {}", count),
                    timestamp: Utc::now(),
                    severity: AlertSeverity::High,
                });
            }
        }

        // Check for brute force patterns in recent logs
        let recent_logs = self.get_recent_logs(1000);
        let failed_attempts: HashMap<String, u64> = recent_logs
            .iter()
            .filter(|log| !log.success)
            .filter_map(|log| log.client_ip.as_ref())
            .fold(HashMap::new(), |mut acc, ip| {
                *acc.entry(ip.clone()).or_insert(0) += 1;
                acc
            });

        for (ip, failures) in failed_attempts {
            if failures > 20 {
                alerts.push(SecurityAlert {
                    alert_type: SecurityAlertType::BruteForceAttempt,
                    message: format!(
                        "Possible brute force attack from IP {}: {} failed attempts",
                        ip, failures
                    ),
                    timestamp: Utc::now(),
                    severity: AlertSeverity::Critical,
                });
            }
        }

        alerts
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct SecurityAlert {
    pub alert_type: SecurityAlertType,
    pub message: String,
    pub timestamp: DateTime<Utc>,
    pub severity: AlertSeverity,
}

#[derive(Debug, Clone, Serialize)]
pub enum SecurityAlertType {
    HighFailureRate,
    SuspiciousActivity,
    BruteForceAttempt,
    KeyRotationOverdue,
    UnusualTrafficPattern,
}

#[derive(Debug, Clone, Serialize)]
pub enum AlertSeverity {
    Low,
    Medium,
    High,
    Critical,
}

/// Helper macro for timing crypto operations
#[macro_export]
macro_rules! time_crypto_operation {
    ($monitor:expr, $operation:expr, $key_id:expr, $agent_id:expr, $operator_id:expr, $payload_size:expr, $client_ip:expr, $user_agent:expr, $block:block) => {{
        let start = std::time::Instant::now();
        let result: Result<_, CryptoError> = (|| $block)();
        let duration = start.elapsed();

        $monitor.log_operation(
            $operation,
            $key_id,
            &result.as_ref().map(|_| ()),
            duration,
            $agent_id,
            $operator_id,
            $payload_size,
            $client_ip,
            $user_agent,
        );

        result
    }};
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::time::Duration;

    #[test]
    fn test_rate_limiting() {
        let monitor = CryptoMonitor::new(
            RateLimitConfig {
                max_operations_per_minute: 5,
                max_operations_per_hour: 100,
                burst_limit: 10,
                block_duration_minutes: 1,
            },
            1000,
        );

        let client_id = "test-client";

        // Should allow initial operations
        for i in 0..5 {
            assert!(
                monitor.check_rate_limit(client_id).is_ok(),
                "Operation {} should be allowed",
                i
            );
        }

        // Should block the 6th operation
        assert!(
            monitor.check_rate_limit(client_id).is_err(),
            "6th operation should be blocked"
        );
    }

    #[test]
    fn test_metrics_tracking() {
        let monitor = CryptoMonitor::new_default();

        // Log some operations
        monitor.log_operation(
            "encrypt",
            "test-key-1",
            &Ok(()),
            Duration::from_millis(10),
            Some("agent-1"),
            Some("operator-1"),
            Some(1024),
            Some("192.168.1.1"),
            Some("test-agent/1.0"),
        );

        monitor.log_operation(
            "decrypt",
            "test-key-1",
            &Err(CryptoError::InvalidKey),
            Duration::from_millis(5),
            Some("agent-2"),
            Some("operator-1"),
            Some(512),
            Some("192.168.1.2"),
            Some("test-agent/1.0"),
        );

        let metrics = monitor.get_metrics();
        assert_eq!(metrics.total_operations, 2);
        assert_eq!(metrics.successful_operations, 1);
        assert_eq!(metrics.failed_operations, 1);
        assert!(metrics.average_duration_ms > 0.0);
    }

    #[test]
    fn test_security_alerts() {
        let monitor = CryptoMonitor::new_default();

        // Generate failed operations to trigger alerts
        for _ in 0..60 {
            monitor.log_operation(
                "decrypt",
                "test-key",
                &Err(CryptoError::InvalidKey),
                Duration::from_millis(1),
                None,
                None,
                None,
                Some("192.168.1.100"),
                None,
            );
        }

        let alerts = monitor.check_security_alerts();
        assert!(!alerts.is_empty(), "Should generate security alerts");

        let has_brute_force_alert = alerts
            .iter()
            .any(|alert| matches!(alert.alert_type, SecurityAlertType::BruteForceAttempt));
        assert!(has_brute_force_alert, "Should detect brute force attempt");
    }
}
