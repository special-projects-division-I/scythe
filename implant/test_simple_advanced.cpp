#include <iostream>
#include <string>
#include <vector>
#include <algorithm>
#include <cctype>

#include <boost/algorithm/string.hpp>
#include <boost/archive/iterators/base64_from_binary.hpp>
#include <boost/archive/iterators/binary_from_base64.hpp>
#include <boost/archive/iterators/transform_width.hpp>

// Standard base64 encoding
std::string base64_encode_string(const std::string& str) {
    using namespace boost::archive::iterators;
    using base64_enc = base64_from_binary<transform_width<std::string::const_iterator, 6, 8>>;
    
    std::string encoded(base64_enc(str.begin()), base64_enc(str.end()));
    
    // Add padding
    size_t padding = (4 - encoded.length() % 4) % 4;
    encoded.append(padding, '=');
    
    return encoded;
}

// Standard base64 decoding
std::string base64_decode_string(const std::string& encoded) {
    using namespace boost::archive::iterators;
    using base64_dec = transform_width<binary_from_base64<std::string::const_iterator>, 8, 6>;
    
    std::string clean_encoded = encoded;
    boost::algorithm::trim(clean_encoded);
    
    // Remove padding
    while (!clean_encoded.empty() && clean_encoded.back() == '=') {
        clean_encoded.pop_back();
    }
    
    try {
        std::string decoded(base64_dec(clean_encoded.begin()), base64_dec(clean_encoded.end()));
        return decoded;
    } catch (const std::exception& e) {
        return "";
    }
}

// Simple character mapping for obfuscation
std::string obfuscate_string(const std::string& str) {
    std::string result;
    result.reserve(str.length());
    
    for (size_t i = 0; i < str.length(); ++i) {
        char c = str[i];
        
        // Apply transformations based on position
        if (i % 3 == 0) {
            // Every 3rd character: swap case
            if (std::islower(c)) {
                result += std::toupper(c);
            } else if (std::isupper(c)) {
                result += std::tolower(c);
            } else {
                result += c;
            }
        } else if (i % 2 == 0) {
            // Even positions (not divisible by 3): reverse if alphabetic
            if (c >= 'A' && c <= 'Z') {
                result += char('Z' - (c - 'A'));
            } else if (c >= 'a' && c <= 'z') {
                result += char('z' - (c - 'a'));
            } else {
                result += c;
            }
        } else {
            // Odd positions: keep as-is
            result += c;
        }
    }
    
    return result;
}

// Deobfuscate string (reverse of above)
std::string deobfuscate_string(const std::string& str) {
    std::string result;
    result.reserve(str.length());
    
    for (size_t i = 0; i < str.length(); ++i) {
        char c = str[i];
        
        // Reverse the transformations
        if (i % 3 == 0) {
            // Every 3rd character: swap case back
            if (std::islower(c)) {
                result += std::toupper(c);
            } else if (std::isupper(c)) {
                result += std::tolower(c);
            } else {
                result += c;
            }
        } else if (i % 2 == 0) {
            // Even positions: reverse the alphabet reversal
            if (c >= 'A' && c <= 'Z') {
                result += char('Z' - (c - 'A'));
            } else if (c >= 'a' && c <= 'z') {
                result += char('z' - (c - 'a'));
            } else {
                result += c;
            }
        } else {
            // Odd positions: keep as-is
            result += c;
        }
    }
    
    return result;
}

// Advanced obfuscation: Base64 + Reverse + Character mapping
std::string advanced_encode(const std::string& plaintext) {
    // Step 1: Base64 encode
    std::string b64 = base64_encode_string(plaintext);
    
    // Step 2: Reverse string
    std::reverse(b64.begin(), b64.end());
    
    // Step 3: Apply character obfuscation
    std::string obfuscated = obfuscate_string(b64);
    
    return obfuscated;
}

// Advanced deobfuscation: reverse of above
std::string advanced_decode(const std::string& encoded) {
    // Step 1: Deobfuscate characters
    std::string deobf = deobfuscate_string(encoded);
    
    // Step 2: Reverse string back
    std::reverse(deobf.begin(), deobf.end());
    
    // Step 3: Base64 decode
    std::string plaintext = base64_decode_string(deobf);
    
    return plaintext;
}

// Simulate signature detection
std::string detect_signatures(const std::string& data) {
    std::vector<std::string> signatures = {
        "whoami", "net user", "systeminfo", "ipconfig", "mimikatz",
        "d2hvYW1p", "bmV0IHVzZXI=", "c3lzdGVtaW5mbw=="  // base64 signatures
    };
    
    for (const auto& sig : signatures) {
        if (data.find(sig) != std::string::npos) {
            return "🚨 DETECTED: " + sig;
        }
    }
    
    // Check for standard base64 pattern
    if (data.length() % 4 == 0 && 
        data.length() > 4 &&
        data.find_first_not_of("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=") == std::string::npos) {
        return "🚨 DETECTED: Base64 pattern";
    }
    
    return "✅ CLEAN";
}

int main() {
    std::cout << "=== Simplified Advanced Obfuscation Test ===" << std::endl;
    std::cout << "[*] Testing multi-layer encoding for C2 evasion" << std::endl;
    
    // Test commands
    std::vector<std::string> test_commands = {
        "whoami",
        "net user",
        "systeminfo",
        "ipconfig /all",
        "mimikatz.exe"
    };
    
    std::cout << "\n1. Encoding Comparison Test:" << std::endl;
    
    int total_tests = 0;
    int normal_detections = 0;
    int advanced_clean = 0;
    int decode_successes = 0;
    
    for (const auto& cmd : test_commands) {
        total_tests++;
        
        // Normal base64
        std::string normal_b64 = base64_encode_string(cmd);
        
        // Advanced obfuscation
        std::string advanced_obf = advanced_encode(cmd);
        
        // Test decoding
        std::string decoded = advanced_decode(advanced_obf);
        bool decode_success = (decoded == cmd);
        
        if (decode_success) decode_successes++;
        
        // Test detection
        std::string normal_detection = detect_signatures(normal_b64);
        std::string advanced_detection = detect_signatures(advanced_obf);
        
        if (normal_detection.find("DETECTED") != std::string::npos) {
            normal_detections++;
        }
        
        if (advanced_detection.find("CLEAN") != std::string::npos) {
            advanced_clean++;
        }
        
        std::cout << "\nCommand: " << cmd << std::endl;
        std::cout << "Normal B64:  " << normal_b64 << std::endl;
        std::cout << "Advanced:    " << advanced_obf << std::endl;
        std::cout << "Normal Det:  " << normal_detection << std::endl;
        std::cout << "Advanced Det: " << advanced_detection << std::endl;
        std::cout << "Decode Test: " << (decode_success ? "✅ PASS" : "❌ FAIL") << std::endl;
    }
    
    std::cout << "\n2. Results Summary:" << std::endl;
    std::cout << "Total Commands Tested: " << total_tests << std::endl;
    std::cout << "Normal B64 Detections: " << normal_detections << "/" << total_tests 
              << " (" << (100.0 * normal_detections / total_tests) << "%)" << std::endl;
    std::cout << "Advanced Clean Results: " << advanced_clean << "/" << total_tests 
              << " (" << (100.0 * advanced_clean / total_tests) << "%)" << std::endl;
    std::cout << "Decode Success Rate: " << decode_successes << "/" << total_tests 
              << " (" << (100.0 * decode_successes / total_tests) << "%)" << std::endl;
    
    double evasion_improvement = (100.0 * advanced_clean / total_tests) - (100.0 * (total_tests - normal_detections) / total_tests);
    std::cout << "Evasion Improvement: " << evasion_improvement << "%" << std::endl;
    
    std::cout << "\n3. Visual Pattern Analysis:" << std::endl;
    std::string sample_cmd = "net group \"Domain Admins\" /domain";
    std::string sample_normal = base64_encode_string(sample_cmd);
    std::string sample_advanced = advanced_encode(sample_cmd);
    
    std::cout << "Original: " << sample_cmd << std::endl;
    std::cout << "Normal:   " << sample_normal << std::endl;
    std::cout << "Advanced: " << sample_advanced << std::endl;
    std::cout << "Normal Detection:   " << detect_signatures(sample_normal) << std::endl;
    std::cout << "Advanced Detection: " << detect_signatures(sample_advanced) << std::endl;
    
    // Test bidirectional encoding
    std::cout << "\n4. Bidirectional Test:" << std::endl;
    std::string test_payload = "This is a test payload for the C2 framework";
    std::string encoded = advanced_encode(test_payload);
    std::string decoded_back = advanced_decode(encoded);
    
    std::cout << "Original:  " << test_payload << std::endl;
    std::cout << "Encoded:   " << encoded << std::endl;
    std::cout << "Decoded:   " << decoded_back << std::endl;
    std::cout << "Match:     " << (test_payload == decoded_back ? "✅ PERFECT" : "❌ FAILED") << std::endl;
    
    if (decode_successes == total_tests && advanced_clean > normal_detections) {
        std::cout << "\n🎉 SUCCESS: Advanced obfuscation working perfectly!" << std::endl;
        std::cout << "[+] All commands decode correctly" << std::endl;
        std::cout << "[+] Better signature evasion than normal base64" << std::endl;
        std::cout << "[+] Ready for deployment in AD lab environment" << std::endl;
    } else if (decode_successes == total_tests) {
        std::cout << "\n✅ PARTIAL SUCCESS: Encoding/decoding works perfectly" << std::endl;
        std::cout << "[*] Consider additional obfuscation layers for better evasion" << std::endl;
    } else {
        std::cout << "\n⚠️  WARNING: Some decode tests failed" << std::endl;
        std::cout << "[*] Algorithm needs refinement" << std::endl;
    }
    
    return 0;
}