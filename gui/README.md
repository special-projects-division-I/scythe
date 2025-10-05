# SCYTHE C2 Controller GUI

A modern, cross-platform graphical user interface for the SCYTHE Command & Control framework, designed for authorized security testing and red team operations.

![SCYTHE GUI](https://img.shields.io/badge/SCYTHE-GUI-blue?style=for-the-badge)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey?style=flat)
![License](https://img.shields.io/badge/license-MIT-green?style=flat)

## 🖥️ Overview

SCYTHE GUI provides a professional, intuitive interface for managing C2 operations, featuring real-time agent monitoring, task execution, file operations, and comprehensive activity logging. Built with security-first principles and designed for operational security.

### ⚠️ Legal Notice

**This tool is designed exclusively for authorized security testing and red team exercises.** Users must ensure compliance with all applicable laws and regulations. Unauthorized use is strictly prohibited.

## ✨ Key Features

### Core Functionality
- **🔍 Real-time Agent Monitoring** - Live status tracking of connected implants
- **📋 Task Management** - Create, execute, and monitor tasks across agents
- **📁 File Operations** - Secure upload/download with progress tracking
- **📊 Activity Logging** - Comprehensive audit trail with filtering
- **🎛️ Interactive Shell** - Direct command execution with templates

### User Experience
- **🎨 Modern UI** - Clean, professional interface with dark/light themes
- **📱 Responsive Design** - Adapts to different screen sizes and resolutions
- **⚡ Fast Performance** - Optimized for real-time operations
- **🔒 Security Focused** - Encrypted communications and secure data handling

### Cross-Platform Support
- **🐧 Linux** - AppImage, DEB packages, and native binaries
- **🪟 Windows** - MSI installers and portable executables
- **🍎 macOS** - Native app bundles and DMG packages

## 🚀 Quick Start

### Prerequisites

- **Node.js 18+** - [Download](https://nodejs.org/)
- **Rust 1.70+** - [Install Rust](https://rustup.rs/)
- **GNU Make** (optional, for Makefile usage)

### Installation

1. **Clone and navigate to GUI directory:**
   ```bash
   cd scythe/gui
   ```

2. **Setup development environment:**
   ```bash
   # Using Makefile (recommended)
   make setup

   # Or using build script
   ./build.sh setup

   # Or using just (if installed)
   just setup
   ```

3. **Start development server:**
   ```bash
   make dev
   # or
   ./build.sh dev
   # or
   just dev
   ```

4. **Connect to your SCYTHE server:**
   - Server URL: `http://127.0.0.1:8080`
   - Configure connection in Settings → Connection

## 🏗️ Build System

SCYTHE GUI includes a comprehensive build system with multiple interfaces:

### Makefile (Primary)
```bash
# Development
make dev              # Start development server
make build-dev        # Build for development

# Production
make build            # Build for production
make build-release    # Build release version

# Cross-platform
make build-linux      # Build for Linux
make build-windows    # Build for Windows
make build-macos      # Build for macOS
make build-all        # Build for all platforms

# Quality Assurance
make test             # Run all tests
make lint             # Run linting
make check            # Run all checks
make type-check       # TypeScript checking

# Utilities
make clean            # Clean build artifacts
make format           # Format code
make docs             # Generate documentation
make info             # Show project info
```

### Build Script (`build.sh`)
```bash
./build.sh setup      # Setup environment
./build.sh dev        # Development server
./build.sh build      # Production build
./build.sh test       # Run tests
./build.sh clean      # Clean artifacts
./build.sh info       # Project information
```

### Justfile (Alternative)
```bash
just dev              # Development server
just build            # Production build
just test             # Run tests
just clean            # Clean artifacts
just info             # Project information
```

## 📋 Usage Guide

### Dashboard
- **Agent Overview** - Monitor connected agents with real-time status
- **Connection Status** - Server connectivity and health indicators
- **Quick Actions** - Fast access to common operations
- **System Information** - Platform and version details

### Agent Management
- **Agent Grid** - Visual overview of all connected agents
- **Agent Details** - Comprehensive information and configuration
- **Interactive Shell** - Direct command execution with history
- **Status Monitoring** - Real-time health and activity tracking

### Task Execution
- **Task Creation** - Build tasks with command templates
- **Task Monitoring** - Track execution progress and results
- **Result Viewing** - Detailed output with syntax highlighting
- **Task History** - Complete execution history and logs

### File Operations
- **File Browser** - Navigate remote file systems
- **Upload/Download** - Secure file transfer with progress
- **Directory Navigation** - Breadcrumb navigation
- **File Management** - Create, delete, and organize files

### Activity Logging
- **Comprehensive Logs** - All system and agent activities
- **Advanced Filtering** - Filter by level, source, time, and content
- **Log Export** - Save logs for analysis and reporting
- **Real-time Updates** - Live log streaming

## 🏛️ Architecture

### Technology Stack
```
Frontend (Vue.js + TypeScript)
├── Vue 3              - Reactive UI framework
├── Element Plus       - UI component library
├── Pinia             - State management
├── Vite              - Build tool and dev server
└── TypeScript        - Type safety

Backend (Rust + Tauri)
├── Tauri             - Desktop application framework
├── Rust              - Systems programming language
├── Tokio             - Async runtime
├── Reqwest           - HTTP client
└── Serde             - Serialization
```

### Project Structure
```
scythe/gui/
├── src/                    # Frontend Vue.js application
│   ├── components/         # Reusable UI components
│   ├── stores/            # Pinia state management
│   ├── views/             # Main application views
│   ├── router/            # Vue Router configuration
│   └── style.css          # Global styles
├── src-tauri/             # Rust backend
│   ├── src/
│   │   ├── api_client.rs  # HTTP client for C2 API
│   │   ├── commands.rs    # Tauri command handlers
│   │   ├── models.rs      # Data models
│   │   └── main.rs        # Application entry point
│   └── Cargo.toml         # Rust dependencies
├── dist/                  # Built frontend assets
├── node_modules/          # Frontend dependencies
├── Makefile              # Primary build system
├── justfile              # Alternative build system
├── build.sh              # Convenience script
└── README.md             # This file
```

### Security Architecture
- **Encrypted Communications** - TLS/HTTPS for server connections
- **Memory Safety** - Rust prevents common vulnerabilities
- **Input Validation** - Client and server-side sanitization
- **Session Management** - Configurable timeouts and security
- **Audit Logging** - Comprehensive activity tracking

## 🔧 Configuration

### Server Connection
```typescript
// Settings stored in local app data directory
interface ServerSettings {
  server_url: string;
  auto_connect: boolean;
  connection_timeout: number;
  retry_attempts: number;
}
```

### Application Settings
```typescript
interface AppSettings {
  theme: 'dark' | 'light' | 'auto';
  auto_refresh: boolean;
  refresh_interval: number;
  font_size: number;
  compact_mode: boolean;
}
```

### Build Configuration
```toml
# tauri.conf.json
{
  "package": {
    "productName": "SCYTHE C2 Controller",
    "version": "0.1.0"
  },
  "tauri": {
    "bundle": {
      "targets": "all",
      "identifier": "com.scythe.c2.controller"
    }
  }
}
```

## 🧪 Development

### Development Workflow
```bash
# 1. Setup environment
make setup

# 2. Start development server
make dev

# 3. Run tests
make test

# 4. Build for production
make build

# 5. Clean workspace
make clean
```

### Code Quality
```bash
# Run all checks
make check

# Type checking
make type-check

# Linting
make lint

# Formatting
make format
```

### Testing
```bash
# Frontend tests
npm test

# Backend tests
cd src-tauri && cargo test

# Integration tests
make test
```

## 🚀 Deployment

### Production Builds
```bash
# Build for current platform
make build

# Build for specific platforms
make build-linux
make build-windows
make build-macos

# Create deployment package
make deploy
```

### Distribution Packages
- **Linux**: AppImage, DEB packages
- **Windows**: MSI installer, portable executable
- **macOS**: DMG installer, app bundle

### CI/CD Integration
```yaml
# Example GitHub Actions workflow
name: Build and Release
on: [push, pull_request]

jobs:
  build:
    runs-on: ${{ matrix.os }}
    strategy:
      matrix:
        os: [ubuntu-latest, windows-latest, macos-latest]
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-node@v3
        with:
          node-version: '18'
      - uses: dtolnay/rust-toolchain@stable
      - run: make setup
      - run: make build
```

## 🤝 Contributing

### Development Guidelines
1. **Code Style** - Follow established patterns and formatting
2. **Testing** - Add tests for new features
3. **Documentation** - Update docs for changes
4. **Security** - Follow security best practices
5. **Cross-platform** - Test on all supported platforms

### Pull Request Process
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Code Standards
- **TypeScript**: Strict mode, proper typing
- **Rust**: Follow `clippy` recommendations
- **Vue**: Composition API, proper component structure
- **Security**: Input validation, secure defaults

## 📊 Performance

### Benchmarks
- **Startup Time**: < 3 seconds
- **Memory Usage**: < 100MB idle
- **Network Latency**: < 100ms for API calls
- **UI Responsiveness**: 60fps animations

### Optimization Features
- **Lazy Loading** - Components loaded on demand
- **Code Splitting** - Optimized bundle sizes
- **Caching** - Intelligent data caching
- **Async Operations** - Non-blocking UI updates

## 🐛 Troubleshooting

### Common Issues

**Connection Failed**
```bash
# Check server status
curl http://127.0.0.1:8080/api/v1/agents

# Verify firewall settings
# Check network connectivity
```

**Build Errors**
```bash
# Clean and rebuild
make clean-all
make setup
make build

# Check dependencies
make check-deps
```

**Performance Issues**
```bash
# Adjust refresh settings
# Clear cache: make clean
# Update dependencies: make update-deps
```

### Debug Mode
```bash
# Enable debug logging
export RUST_LOG=debug
export TAURI_LOG=debug

# Start with verbose output
make dev 2>&1 | tee debug.log
```

## 📞 Support

### Documentation
- **User Guide**: See main SCYTHE documentation
- **API Reference**: Auto-generated from code comments
- **Troubleshooting**: This README and issue tracker

### Community
- **Issues**: [GitHub Issues](https://github.com/scythe-framework/scythe/issues)
- **Discussions**: [GitHub Discussions](https://github.com/scythe-framework/scythe/discussions)
- **Security**: Contact maintainers privately for security issues

### Version Information
```bash
# Show version and system info
make info

# Check for updates
make version
```

## 📄 License

This project is licensed under the MIT License - see the main SCYTHE project LICENSE file for details.

## 🙏 Acknowledgments

- **SCYTHE Framework** - Core C2 functionality
- **Tauri Team** - Desktop application framework
- **Vue.js Community** - Frontend framework and ecosystem
- **Rust Community** - Systems programming language
- **Security Research Community** - Best practices and methodologies

---

**⚡ Built for Security Professionals, by Security Professionals**

*SCYTHE GUI provides the tools you need for comprehensive C2 operations with the security and performance you expect.*