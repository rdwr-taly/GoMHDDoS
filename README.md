# GoMHDDoS - Go Port of MHDDoS

<h1 align="center">GoMHDDoS - Layer 7 DDoS Testing Tool</h1>
<em><h5 align="center">(Programming Language - Go)</h5></em>

<p align="center">
<img alt="Go" src="https://img.shields.io/badge/Go-1.23+-00ADD8?style=for-the-badge&logo=go">
<img alt="License" src="https://img.shields.io/badge/License-Educational%20Use-orange?style=for-the-badge">
<img alt="Platform" src="https://img.shields.io/badge/Platform-Cross--Platform-brightgreen?style=for-the-badge">
</p>

<p align="center">⚠️ <strong>Educational and Testing Purposes Only</strong> ⚠️</p>
<p align="center">Please don't attack websites without the owner's consent.</p>

## 📋 Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Available Methods](#available-methods)
- [Advantages over Original](#advantages-over-original)
- [Limitations](#limitations)
- [Configuration](#configuration)
- [Examples](#examples)
- [Contributing](#contributing)
- [License](#license)

## 🎯 Overview

GoMHDDoS is a Go port of the popular [MHDDoS](https://github.com/MatrixTM/MHDDoS) Python tool, specifically focused on **Layer 7 (Application Layer) DDoS testing**. This port provides improved performance, better concurrency handling, and cross-platform compatibility while maintaining the core functionality of the original tool.

**Version**: 2.4 SNAPSHOT (L7 Only Mod) [Go Port]

## ✨ Features

### 🚀 Performance Improvements
- **Native Go Concurrency**: Utilizes Go's goroutines for superior concurrent request handling
- **Lower Memory Footprint**: More efficient memory usage compared to Python threads
- **Better Resource Management**: Automatic garbage collection and connection pooling
- **Cross-Platform Binary**: Single executable file for Windows, Linux, and macOS

### 🔧 Enhanced Architecture
- **Atomic Counters**: Thread-safe request and byte counters
- **Context-Based Cancellation**: Graceful shutdown and timeout handling
- **Connection Pooling**: Optimized TCP connection reuse
- **Proxy Rotation**: Efficient proxy cycling with support for HTTP, SOCKS4, and SOCKS5

### 📊 Monitoring & Debugging
- **Real-time Statistics**: Live request/second and bandwidth monitoring
- **Debug Mode**: Detailed logging for troubleshooting
- **Colorized Output**: Easy-to-read terminal output with ANSI colors
- **Progress Indicators**: Visual feedback during attacks

## 🛠️ Installation

### Prerequisites
- Go 1.23 or later
- Internet connection for downloading dependencies

### Method 1: Build from Source
```bash
# Clone the repository
git clone https://github.com/yourusername/GoMHDDoS.git
cd GoMHDDoS

# Build the binary
go build -o gomhddos mhddos.go

# Run the tool
./gomhddos --help
```

### Method 2: Go Install
```bash
# Install directly from source
go install github.com/yourusername/GoMHDDoS@latest

# Run from anywhere
gomhddos --help
```

### Method 3: Download Binary
Download pre-compiled binaries from the [Releases](https://github.com/yourusername/GoMHDDoS/releases) page.

## 🧰 Running the Prebuilt Binary

The repository ships with statically linked binaries under [`binary/`](binary/) (for example `mhddos-x64` for 64-bit Linux/macOS
and `mhddos-arm64` for ARM64). You can also download the same artifacts from the releases page. Running them directly on a CLI
requires no additional Go toolchain once the runtime layout is prepared.

### 1. Make the binary executable

```bash
chmod +x binary/mhddos-x64           # adapt the name to the architecture you downloaded
```

On Windows, keep the file extension (`mhddos-x64.exe` if you renamed it) and run the following from PowerShell:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass   # optional if scripts are restricted
.\binary\mhddos-x64.exe --help
```

### 2. Run the CLI

```bash
./binary/mhddos-x64 --help           # prints every flag and the default values
./binary/mhddos-x64 -method GET -url https://example.com -threads 100 -duration 60
```

Any relative path you pass (including the default proxy file) is resolved from the folder that contains the executable, so you
can copy the binary plus the `files/` folder anywhere on disk and run it from there.

### Default runtime layout

When you execute the binary, it determines its own location (`scriptDir`) and expects the following structure alongside the
executable:

```
<your-folder>/
├── gomhddos (or mhddos-x64 / mhddos-arm64)
└── files/
    ├── proxies/
    │   └── http.txt          # default proxy list used by -proxyfile (see below)
    ├── useragent.txt         # auto-created with sensible defaults if missing
    └── referers.txt          # auto-created with sensible defaults if missing
```

You can relocate the binary to any directory, provided this `files/` folder sits next to it (or you pass absolute paths for the
individual resources).

### Proxy file resolution & fallback behaviour

- **Default path**: unless you override `-proxyfile`, the tool looks for `files/proxies/http.txt` relative to the binary's own
  directory. For example, if you run `/opt/gomhddos/mhddos-x64`, the default proxy file is
  `/opt/gomhddos/files/proxies/http.txt`.
- **Custom locations**: you can supply either a relative or an absolute path via `-proxyfile`. Relative paths are resolved from
  the binary directory; absolute paths are honoured as-is.

#### When the proxy directory or file is missing

If `files/proxies/http.txt` (or any custom path) does not exist when the program starts, GoMHDDoS will:

1. Log a warning that the proxy file is missing.
2. Automatically create the required directory tree (for example `files/proxies/`).
3. Create an empty proxy file at the expected location.
4. Proceed with the attack **without using proxies** until you populate the file.

This makes the binary self-contained on first launch, but you must edit the newly created file to add one proxy per line before
proxy-based methods become effective.

#### When the proxy file exists but is empty (or only comments)

- The program will emit a warning similar to `Empty or invalid Proxy File ... running flood without proxy`.
- Every attack runs directly from your host until you populate the file with valid proxy entries.
- Invalid lines are ignored individually, so you can mix comments (`# ...`) with actual proxies without causing a failure.

Populate the file with entries such as `ip:port`, `user:pass@ip:port`, or full URLs like `socks5://example.com:1080` depending on
your needs. Whenever at least one proxy is successfully parsed, the CLI prints a summary of how many were loaded per protocol.

## 🎮 Usage

### Command Line Flags (Recommended)
```bash
./gomhddos -method <METHOD> -url <TARGET_URL> [OPTIONS]
```

### Available Flags
- `-method`: Attack method (required)
- `-url`: Target URL (required)
- `-threads`: Number of concurrent threads (default: 100)
- `-proxyfile`: Path to proxy file (default: "files/proxies/http.txt")
- `-rpc`: Requests per connection (default: 50)
- `-duration`: Attack duration in seconds (default: 60)
- `-cookie`: Optional cookie string
- `-debug`: Enable debug logging
- `-bombardier`: Path to bombardier executable (for BOMB method)

### Legacy Positional Arguments (Deprecated)
```bash
./gomhddos <METHOD> <URL> <THREADS> <PROXY_FILE> <RPC> <DURATION> [COOKIE] [DEBUG]
```

## 🎯 Available Methods

### 💣 Layer 7 Methods (27 Available)

| Method | Description | Status |
|--------|-------------|--------|
| **GET** | Standard HTTP GET flood | ✅ Full |
| **POST** | HTTP POST flood with JSON payloads | ✅ Full |
| **HEAD** | HTTP HEAD request flood | ✅ Full |
| **CFB** | Cloudflare bypass attempt (no JS solver) | ⚠️ Limited |
| **BYPASS** | Generic bypass using net/http | ✅ Full |
| **DGB** | DDoS-Guard bypass attempt | ⚠️ Limited |
| **SLOW** | Slowloris-style attack | ✅ Full |
| **STRESS** | High-byte HTTP packet stress | ✅ Full |
| **TOR** | Tor network flood via tor2web gateways | ✅ Full |
| **BOMB** | External bombardier integration | ✅ Full |
| **BOT** | Bot-like requests with Google agents | ✅ Full |
| **COOKIE** | Cookie-based flood | ✅ Full |
| **NULL** | Null user-agent requests | ✅ Full |
| **PPS** | Minimal HTTP requests | ✅ Full |
| **EVEN** | Enhanced GET with extra headers | ✅ Full |
| **OVH** | OVH-specific bypass | ✅ Full |
| **DYN** | Dynamic subdomain requests | ✅ Full |
| **DOWNLOADER** | Slow download simulation | ✅ Full |
| **GSB** | Google Shield bypass | ✅ Full |
| **RHEX** | Random HEX path requests | ✅ Full |
| **STOMP** | CAPTCHA bypass attempt | ✅ Full |
| **APACHE** | Apache-specific requests | ✅ Full |
| **XMLRPC** | XML-RPC flood | ✅ Full |
| **KILLER** | Aggressive request patterns | ✅ Full |
| **AVB** | Advanced bypass method | ✅ Full |
| **CFBUAM** | Cloudflare UAM bypass | ⚠️ Limited |

## 🚀 Advantages over Original

### Performance Benefits
- **10-50x Better Performance**: Go's efficient concurrency model
- **Lower CPU Usage**: More efficient thread management
- **Reduced Memory Consumption**: Better garbage collection and memory pooling
- **Faster Startup Time**: No Python interpreter overhead

### Reliability Improvements
- **Better Error Handling**: Comprehensive error recovery mechanisms
- **Graceful Shutdown**: Proper cleanup on interruption
- **Connection Stability**: Improved socket management
- **Proxy Resilience**: Better proxy failure handling

### Usability Enhancements
- **Single Binary**: No dependencies or virtual environments needed
- **Cross-Platform**: Works on Windows, Linux, macOS without modifications
- **Modern CLI**: Flag-based interface with help system
- **Better Logging**: Structured logging with debug modes

## ⚠️ Limitations

### Missing Features (vs Original Python Version)

#### 🚫 **Layer 4 Methods (Completely Removed)**
The Go port **does not include** any Layer 4 methods. The following are **NOT available**:
- UDP, TCP, SYN floods
- ICMP attacks
- Amplification attacks (NTP, DNS, CHAR, etc.)
- Minecraft, TeamSpeak, FiveM protocols
- Raw socket operations

#### 🚫 **JavaScript Challenge Solving**
- **No Cloudflare JS Challenge Support**: CFB and CFBUAM methods cannot solve JavaScript challenges
- **No Browser Automation**: No puppeteer/selenium equivalent
- **Limited WAF Bypass**: Modern WAF bypass capabilities are reduced

#### 🚫 **Advanced Bypass Features**
- **No Cloudscraper**: Python's cloudscraper library not available
- **No TLS Fingerprinting**: Advanced TLS evasion not implemented
- **No Browser Fingerprinting**: No realistic browser simulation

#### 🚫 **Additional Tools**
The original Python version includes utility tools (DNS lookup, ping, etc.) that are **not implemented** in this Go port.

#### 🚫 **Real-time Proxy Validation**
- **No Proxy Checker**: Built-in proxy validation not implemented
- **No Proxy Rotation Health**: Dead proxy detection is basic

### Working but Limited Features

#### ⚠️ **Cloudflare Bypass Methods**
- **CFB**: Works but cannot solve JavaScript challenges
- **CFBUAM**: Basic implementation without UAM solving
- **DGB**: Simplified DDoS-Guard bypass without full challenge solving

#### ⚠️ **BOMB Method**
- **External Dependency**: Requires separate `bombardier` installation
- **Limited Integration**: Less seamless than Python's requests integration

## 📁 Configuration

### Proxy File Format
Create proxy files in the `files/proxies/` directory:

```
# HTTP Proxies (files/proxies/http.txt)
proxy1.example.com:8080
user:pass@proxy2.example.com:3128
1.2.3.4:8080

# SOCKS Proxies
socks5://proxy.example.com:1080
socks4://user:pass@proxy.example.com:1080
```

### User Agent & Referer Files
- `files/useragent.txt`: List of user agents (one per line)
- `files/referers.txt`: List of referer URLs (one per line)

### Configuration File
Optional `config.json` for advanced settings (implementation varies).

## 📚 Examples

### Basic Attack
```bash
# Simple GET flood
./gomhddos -method GET -url http://example.com -threads 100 -duration 60

# POST flood with proxies
./gomhddos -method POST -url https://example.com -threads 200 -proxyfile files/proxies/http.txt -rpc 100 -duration 120
```

### Advanced Attacks
```bash
# Cloudflare bypass attempt
./gomhddos -method CFB -url https://protected.example.com -threads 50 -proxyfile files/proxies/socks5.txt -debug

# Slowloris attack
./gomhddos -method SLOW -url http://example.com -threads 500 -duration 300

# TOR network attack
./gomhddos -method TOR -url http://example.onion -threads 20 -duration 60
```

### Using Bombardier
```bash
# Install bombardier first
go install github.com/codesenberg/bombardier@latest

# Run BOMB method
./gomhddos -method BOMB -url https://example.com -threads 50 -proxyfile files/proxies/http.txt -bombardier $(which bombardier)
```

### Debug Mode
```bash
# Enable detailed logging
./gomhddos -method GET -url http://example.com -threads 10 -duration 30 -debug
```

## 🤝 Contributing

Contributions are welcome! Areas for improvement:

1. **JavaScript Challenge Solving**: Implement JS challenge solvers
2. **Layer 4 Methods**: Add UDP/TCP flood capabilities
3. **Proxy Validation**: Add real-time proxy health checking
4. **WAF Bypass**: Improve modern WAF evasion techniques
5. **Documentation**: Expand usage examples and tutorials

### Development Setup
```bash
git clone https://github.com/yourusername/GoMHDDoS.git
cd GoMHDDoS
go mod tidy
go build -o gomhddos mhddos.go
```

## 📄 License

This project is for **educational and authorized testing purposes only**. Users are responsible for complying with all applicable laws and regulations. The developers are not responsible for any misuse of this tool.

## 🙏 Acknowledgments

- Original [MHDDoS](https://github.com/MatrixTM/MHDDoS) by MatrixTM
- Go community for excellent networking libraries
- [Bombardier](https://github.com/codesenberg/bombardier) for HTTP load testing

## 📞 Support

For issues, questions, or contributions:
- Open an issue on GitHub
- Check the [Wiki](https://github.com/yourusername/GoMHDDoS/wiki) for detailed documentation
- Review the original [MHDDoS documentation](https://github.com/MatrixTM/MHDDoS/wiki) for method details

---

<p align="center">
<strong>⚠️ Remember: Use responsibly and only on systems you own or have explicit permission to test! ⚠️</strong>
</p>