#include <iostream>
#include <string>
#include <vector>
#include <fstream>
#include <sstream>

#include <boost/algorithm/string.hpp>
#include <boost/archive/iterators/base64_from_binary.hpp>
#include <boost/archive/iterators/binary_from_base64.hpp>
#include <boost/archive/iterators/transform_width.hpp>

// Base64 encoding for binary data
std::string base64_encode_data(const std::vector<uint8_t>& data) {
    using namespace boost::archive::iterators;
    using base64_enc = base64_from_binary<transform_width<std::vector<uint8_t>::const_iterator, 6, 8>>;
    
    std::string encoded(base64_enc(data.begin()), base64_enc(data.end()));
    
    // Add padding
    size_t padding = (4 - encoded.length() % 4) % 4;
    encoded.append(padding, '=');
    
    return encoded;
}

// Base64 encoding for strings
std::string base64_encode_string(const std::string& str) {
    std::vector<uint8_t> bytes(str.begin(), str.end());
    return base64_encode_data(bytes);
}

// Base64 decoding to binary data
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
        std::cerr << "[ERROR] Base64 decode failed: " << e.what() << std::endl;
        return std::vector<uint8_t>();
    }
}

// Base64 decoding to string
std::string base64_decode_to_string(const std::string& encoded) {
    std::vector<uint8_t> bytes = base64_decode_to_bytes(encoded);
    return std::string(bytes.begin(), bytes.end());
}

// Read file to binary data
std::vector<uint8_t> read_file_to_bytes(const std::string& filepath) {
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
bool write_bytes_to_file(const std::string& filepath, const std::vector<uint8_t>& data) {
    std::ofstream file(filepath, std::ios::binary);
    
    if (!file.is_open()) {
        return false;
    }
    
    file.write(reinterpret_cast<const char*>(data.data()), data.size());
    return file.good();
}

int main() {
    std::cout << "=== Scythe Base64 Encoding/Decoding Test ===" << std::endl;
    std::cout << "[*] Testing base64 functionality for C2 implant" << std::endl;
    
    // Test 1: Basic string encoding/decoding
    std::cout << "\n1. Testing String Encoding/Decoding:" << std::endl;
    
    std::string original_text = "whoami";
    std::string encoded_cmd = base64_encode_string(original_text);
    std::string decoded_cmd = base64_decode_to_string(encoded_cmd);
    
    std::cout << "Original Command: " << original_text << std::endl;
    std::cout << "Encoded Command:  " << encoded_cmd << std::endl;
    std::cout << "Decoded Command:  " << decoded_cmd << std::endl;
    std::cout << "Match: " << (original_text == decoded_cmd ? "✅ PASS" : "❌ FAIL") << std::endl;
    
    // Test 2: Advanced commands
    std::cout << "\n2. Testing Advanced Commands:" << std::endl;
    
    std::vector<std::string> test_commands = {
        "whoami",
        "ls -la /etc/passwd",
        "cat /proc/version",
        "ps aux | grep ssh",
        "netstat -tulpn"
    };
    
    for (const auto& cmd : test_commands) {
        std::string encoded = base64_encode_string(cmd);
        std::string decoded = base64_decode_to_string(encoded);
        
        std::cout << "CMD: " << cmd << std::endl;
        std::cout << "B64: " << encoded << std::endl;
        std::cout << "DEC: " << decoded << std::endl;
        std::cout << "✓ " << (cmd == decoded ? "PASS" : "FAIL") << std::endl;
        std::cout << "---" << std::endl;
    }
    
    // Test 3: File operations simulation
    std::cout << "\n3. Testing File Operations:" << std::endl;
    
    // Create a test file
    std::string test_file = "test_data.txt";
    std::string test_content = "This is a test file for the Scythe C2 implant.\n"
                               "It contains some sample data to test file upload/download.\n"
                               "Base64 encoding will obfuscate this content during transfer.\n"
                               "Educational purposes only - for AD lab testing.\n";
    
    // Write test file
    std::vector<uint8_t> test_bytes(test_content.begin(), test_content.end());
    if (write_bytes_to_file(test_file, test_bytes)) {
        std::cout << "[+] Created test file: " << test_file << std::endl;
    } else {
        std::cerr << "[-] Failed to create test file" << std::endl;
        return 1;
    }
    
    // Simulate download (file -> base64)
    std::vector<uint8_t> file_data = read_file_to_bytes(test_file);
    if (file_data.empty()) {
        std::cerr << "[-] Failed to read test file" << std::endl;
        return 1;
    }
    
    std::string encoded_file = base64_encode_data(file_data);
    std::cout << "[+] File encoded to base64 (" << encoded_file.length() << " chars)" << std::endl;
    std::cout << "Base64 Preview: " << encoded_file.substr(0, 50) << "..." << std::endl;
    
    // Simulate upload (base64 -> file)
    std::vector<uint8_t> decoded_file = base64_decode_to_bytes(encoded_file);
    std::string recovered_file = "recovered_test.txt";
    
    if (write_bytes_to_file(recovered_file, decoded_file)) {
        std::cout << "[+] File decoded and written: " << recovered_file << std::endl;
        
        // Verify content
        std::vector<uint8_t> recovered_data = read_file_to_bytes(recovered_file);
        if (file_data == recovered_data) {
            std::cout << "✅ File integrity verified - perfect match!" << std::endl;
        } else {
            std::cout << "❌ File integrity failed - data corruption!" << std::endl;
        }
    } else {
        std::cerr << "[-] Failed to write recovered file" << std::endl;
    }
    
    // Test 4: Binary data handling
    std::cout << "\n4. Testing Binary Data:" << std::endl;
    
    // Create binary test data
    std::vector<uint8_t> binary_data;
    for (int i = 0; i < 256; ++i) {
        binary_data.push_back(static_cast<uint8_t>(i));
    }
    
    std::string encoded_binary = base64_encode_data(binary_data);
    std::vector<uint8_t> decoded_binary = base64_decode_to_bytes(encoded_binary);
    
    std::cout << "Original binary size: " << binary_data.size() << " bytes" << std::endl;
    std::cout << "Base64 encoded size:  " << encoded_binary.size() << " chars" << std::endl;
    std::cout << "Decoded binary size:  " << decoded_binary.size() << " bytes" << std::endl;
    std::cout << "Binary integrity: " << (binary_data == decoded_binary ? "✅ PASS" : "❌ FAIL") << std::endl;
    
    // Test 5: PowerShell/CMD obfuscation examples
    std::cout << "\n5. Command Obfuscation Examples for AD Lab:" << std::endl;
    
    std::vector<std::string> ad_commands = {
        "net user",
        "net group \"Domain Admins\" /domain",
        "whoami /priv",
        "systeminfo",
        "ipconfig /all",
        "nltest /dclist:",
        "net view /domain",
        "wmic process list full"
    };
    
    std::cout << "\nEncoded commands for C2 testing:" << std::endl;
    for (const auto& cmd : ad_commands) {
        std::string encoded = base64_encode_string(cmd);
        std::cout << "Original: " << cmd << std::endl;
        std::cout << "Encoded:  " << encoded << std::endl;
        std::cout << "---" << std::endl;
    }
    
    // Cleanup
    std::remove(test_file.c_str());
    std::remove(recovered_file.c_str());
    
    std::cout << "\n✅ All Base64 tests completed!" << std::endl;
    std::cout << "[*] Your implant is ready for steganographic file transfers" << std::endl;
    std::cout << "[*] Perfect for educational AD lab penetration testing!" << std::endl;
    
    return 0;
}