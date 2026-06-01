# Zero-Day Forge - Professional Vulnerability Scanner

Welcome to **Zero-Day Forge**, an advanced, professional-grade vulnerability scanner built for security researchers, penetration testers, and ethical hackers. This powerful tool combines modern asynchronous scanning techniques, behavioral analysis for zero-day detection, and AI-powered verification to identify security flaws in web applications.

---

## Table of Contents

1. [Features](#features)
2. [Architecture Overview](#architecture-overview)
3. [Installation](#installation)
4. [Quick Start](#quick-start)
5. [Usage Guide](#usage-guide)
6. [Scanning Modules](#scanning-modules)
7. [Reports & Output](#reports--output)
8. [Configuration](#configuration)
9. [Contributing](#contributing)
10. [Disclaimer](#disclaimer)
11. [License](#license)

---

## Features

Zero-Day Forge comes packed with cutting-edge features to make vulnerability detection efficient and thorough:

- **Zero-Day Detection** via behavioral analysis and anomaly detection
- **XSS (Cross-Site Scripting)** detection:
  - Reflected XSS
  - Stored XSS (planned)
  - DOM-based XSS
- **IDOR (Insecure Direct Object References)** with privilege escalation testing
- **SQL Injection** detection (in progress)
- **CSRF (Cross-Site Request Forgery)** detection (planned)
- **SSRF (Server-Side Request Forgery)** testing (planned)
- **AI-Powered Verification**: Optional false-positive reduction using Ollama
- **Multi-Format Professional Reports**: HTML, JSON, CSV, and Markdown
- **Asynchronous Scanning**: High-performance scanning using async I/O
- **User-Agent Rotation**: Avoids basic fingerprinting
- **Proxy Support**: For scanning through proxies or VPNs
- **Rate Limiting & Delays**: Respects server limits

---

## Architecture Overview

The scanner is built with a modular, extensible architecture:

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Main CLI Entry Point                          │
├─────────────────────────────────────────────────────────────────────┤
│                      Advanced Scanner Engine                        │
│  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐ ┌───────────┐  │
│  │ XSS Module   │ │ IDOR Module  │ │ SQLi Module  │ │ Etc...    │  │
│  └──────────────┘ └──────────────┘ └──────────────┘ └───────────┘  │
├─────────────────────────────────────────────────────────────────────┤
│                    Zero-Day Behavioral Analyzer                     │
├─────────────────────────────────────────────────────────────────────┤
│                Optional AI Verifier (Ollama)                        │
├─────────────────────────────────────────────────────────────────────┤
│                    Report Generator (Multi-Format)                   │
└─────────────────────────────────────────────────────────────────────┘
```

Key Components:
1. **Core Engine (`src/core/engine.py`)**: The heart of the scanner, coordinates all scanning operations, manages async HTTP sessions, and collects vulnerabilities.
2. **Modules (`src/modules/`)**: Pluggable scanning components (XSS, IDOR, SQLi, etc.)
3. **Network Utilities (`src/utils/network.py`)**: Handles HTTP requests, user agent rotation, proxies, and rate limiting.
4. **Crawler (`src/core/crawler.py`)**: Discovers hidden endpoints and parameters.
5. **Reporter (`src/core/reporter.py`)**: Generates professional reports in multiple formats.
6. **AI Detector (`src/core/ai_detector.py`)**: Optional Ollama integration for verification.

---

## Installation

### Prerequisites
- **Python 3.8 or newer** (3.10+ recommended)
- **pip** (Python package manager)
- Optional: **Ollama** (for AI verification)

### Step-by-Step Installation

1. **Clone the repository (or extract the files):**
   ```bash
   cd c:\Users\getas\Downloads\ZeroDayForge
   ```

2. **Create a virtual environment (optional but highly recommended):**
   ```bash
   python -m venv .venv
   .venv\Scripts\activate  # Windows
   # source .venv/bin/activate  # Linux/macOS
   ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Verify the installation:**
   ```bash
   python main.py --help
   ```

### Optional: Installing Ollama for AI Verification
If you want to use AI-powered verification, install Ollama:
1. Download from [ollama.com](https://ollama.com/)
2. Install and run Ollama
3. Pull a model (we recommend tinydolphin for speed):
   ```bash
   ollama pull tinydolphin
   ```

---

## Quick Start

Let's perform a basic scan to get started!

1. **Run a basic scan on a test target:**
   ```bash
   python main.py -u https://testphp.vulnweb.com
   ```

2. **Check your reports:**
   After the scan completes, look in the `reports/` directory for your HTML, JSON, CSV, and Markdown reports!

---

## Usage Guide

### Command-Line Options

Zero-Day Forge has a full-featured CLI interface. Here are all the options:

```
usage: main.py [-h] -u URL [-t THREADS] [-o {json,html,csv,markdown,all}]
               [--xss] [--idor] [--sqli] [--delay DELAY] [--timeout TIMEOUT]    
               [--proxy PROXY] [--ai] [--verbose]

Zero-Day Forge - Professional Vulnerability Scanner

options:
  -h, --help            Show this help message and exit
  -u, --url URL         Target URL to scan (REQUIRED)
  -t, --threads THREADS
                        Maximum concurrent threads (default: 20)
  -o, --output {json,html,csv,markdown,all}
                        Output format (default: all)
  --xss                 Only scan for XSS vulnerabilities
  --idor                Only scan for IDOR vulnerabilities
  --sqli                Only scan for SQL injection vulnerabilities
  --delay DELAY         Delay between requests in seconds (default: 0.1)
  --timeout TIMEOUT     Request timeout in seconds (default: 10)
  --proxy PROXY         Proxy URL (e.g., http://localhost:8080)
  --ai                  Enable AI verification (requires Ollama)
  --verbose             Enable verbose debug logging
```

### Usage Examples

#### 1. Basic Full Scan
```bash
python main.py -u https://example.com
```

#### 2. High-Performance Scan (More Threads)
```bash
python main.py -u https://example.com -t 50
```

#### 3. Slower, More Polite Scan (Increased Delay)
```bash
python main.py -u https://example.com --delay 0.5
```

#### 4. Scan Only for XSS
```bash
python main.py -u https://example.com --xss
```

#### 5. Scan Using a Proxy
```bash
python main.py -u https://example.com --proxy http://localhost:8080
```

#### 6. Scan with AI Verification
```bash
python main.py -u https://example.com --ai
```

#### 7. Generate Only HTML Reports
```bash
python main.py -u https://example.com -o html
```

---

## Scanning Modules

Zero-Day Forge includes several specialized scanning modules. Here's how they work:

### XSS Scanner (`src/modules/xss_scanner.py`)
The XSS module detects Cross-Site Scripting vulnerabilities by:
1. Testing common query parameters with various XSS payloads
2. Checking DOM sinks and sources via JavaScript analysis
3. Verifying payload execution context

**Payload Library**: Includes basic script injections, event handlers, javascript: protocol, encoded variants, and WAF bypass techniques.

### IDOR Scanner (`src/modules/idor_scanner.py`)
The IDOR module detects Insecure Direct Object References by:
1. Discovering endpoints with numeric IDs, UUIDs, etc.
2. Testing access with modified IDs
3. Checking for sensitive data exposure
4. Testing access to admin/protected endpoints

### SQLi Scanner (In Progress)
Detects SQL injection vulnerabilities via error-based, union-based, boolean-based, and time-based techniques.

---

## Reports & Output

After each scan, Zero-Day Forge generates professional reports in the `reports/` directory:

### 1. HTML Report
A beautiful, responsive, interactive report with:
- Summary cards showing vulnerability counts by severity
- Detailed tables of all vulnerabilities
- Individual vulnerability details (URL, parameter, payload, description, remediation, CVSS, CWE)
- Confidentiality footer

### 2. JSON Report
Machine-readable JSON format for integration with other tools.

### 3. CSV Report
Spreadsheet-friendly format for easy analysis in Excel or Google Sheets.

### 4. Markdown Report
Clean Markdown format for documentation purposes.

---

## Configuration

For advanced configuration, edit `config/settings.yaml`:

```yaml
scanner:
  max_threads: 20           # Number of concurrent threads
  timeout: 10               # Request timeout in seconds
  delay: 0.1                # Delay between requests in seconds
  retry_count: 3            # Number of retries for failed requests
  user_agent_rotation: true # Rotate User-Agent strings

modules:
  xss:
    enabled: true
    dom_scan: true
  idor:
    enabled: true

output:
  directory: "reports"      # Directory for saving reports

network:
  proxy: null               # Proxy URL (e.g., "http://localhost:8080")
  verify_ssl: false         # Verify SSL certificates

ai:
  enabled: false
  ollama_url: "http://localhost:11434"
```

---

## Contributing

Contributions are welcome! Here's how you can help:
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

---

## Disclaimer

**USE RESPONSIBLY!** This tool is intended for authorized security testing only. You must have explicit permission to scan any target system. Unauthorized access to computer systems is illegal and unethical. The authors are not responsible for any misuse or damage caused by this tool.

---

## License

Zero-Day Forge is released under the MIT License. See the LICENSE file for details.

---

## Contact & Support

For questions, issues, or feature requests, please open an issue on the project's repository!

---

**Happy Scanning! 🛡️**
