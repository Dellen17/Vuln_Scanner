Mini Vulnerability Scanner
A modular, educational CLI vulnerability scanner for security testing of systems you own or have explicit permission to test.

🛠 Skills Demonstrated
- Python packaging & CLI tools (`setup.py`, `__main__.py`)
- Networking: Socket port scanning, HTTP analysis (`requests`)
- Security: Header checks, TLS cert validation, vuln detection
- Concurrency: `ThreadPoolExecutor` for fast scans
- Ethical design: Safety warnings & local-only defaults

🚀 Features
Port Scanning: TCP connect scanning with banner grabbing and service detection

HTTP Security Headers: Comprehensive security header analysis (CSP, HSTS, X-Frame-Options, etc.)

TLS Certificate Analysis: Certificate expiry validation and issuer information

Screenshot Capture: Automatic webpage screenshots using Playwright

Vulnerability Detection: Automated vulnerability identification and risk scoring

Concurrent Scanning: Multi-threaded scanning with ThreadPoolExecutor

Rich Output: Beautiful console output with tables and panels

JSON Reports: Save detailed scan results to JSON files

Safety Features: Built-in warnings for external IP scanning

📁 Project Structure
text
Scanner/
├── scanner/                 # Main package directory
│   ├── __init__.py         # Package initialization
│   ├── __main__.py         # Module entry point
│   ├── cli.py              # Command-line interface
│   ├── scanner.py          # Main scanner orchestrator
│   ├── port_scanner.py     # Port scanning functionality
│   ├── http_analyzer.py    # HTTP header analysis
│   ├── tls_checker.py      # TLS certificate validation
│   ├── screenshot.py       # Screenshot capture
│   ├── vulnerability.py    # Vulnerability detection
│   ├── reporter.py         # Result reporting
│   └── utils.py            # Utility functions
├── scripts/
│   └── scan.py             # CLI script
├── ll_scan/                # Virtual environment (created)
├── requirements.txt        # Python dependencies
├── setup.py               # Package installation
└── README.md              # This file


🛠 Installation
Method 1: Install as Package (Recommended)
bash
# Clone or download the project
cd Scanner

# Create virtual environment
python3 -m venv ll_scan
source ll_scan/bin/activate

# Install package and dependencies
pip install -e .

# Install Playwright for screenshots (optional)
pip install playwright
playwright install
Method 2: Direct Usage
bash
# Install dependencies only
pip install -r requirements.txt

# Run directly using the script
python scripts/scan.py --target 192.168.1.50 --screenshot
🎯 Usage
Basic Scan
bash
For organization, optionally create `screenshots/` and `json_reports/` folders

# Scan a target with default ports (21,22,80,443,3306)
vulnscan --target 192.168.1.50

# Or using module syntax
python -m scanner scan --target 192.168.1.50
Advanced Scanning
bash
# Scan specific ports with screenshots
vulnscan --target 192.168.1.50 --ports 80,443,8080 --screenshot

# Custom timeout and workers
vulnscan --target 192.168.1.50 --timeout 2.0 --workers 16

# Save results to JSON report
vulnscan --target 192.168.1.50 --save scan_report.json

# Verbose output for debugging
vulnscan --target 192.168.1.50 --verbose

# Disable rich output (for simpler terminals)
vulnscan --target 192.168.1.50 --no-rich
Scan External Targets
bash
# Scan external IPs (requires explicit permission)
vulnscan --target example.com --allow-external --ports 80,443
📊 What Gets Scanned
Port Scanning
Default Ports: 21 (FTP), 22 (SSH), 80 (HTTP), 443 (HTTPS), 3306 (MySQL)

Service Detection: Identifies services from banners

Banner Grabbing: Attempts to retrieve service information

HTTP Security Headers
Content-Security-Policy - Prevents XSS attacks

Strict-Transport-Security - Enforces HTTPS

X-Frame-Options - Prevents clickjacking

X-Content-Type-Options - Prevents MIME sniffing

Referrer-Policy - Controls referrer information

Permissions-Policy - Controls browser features

TLS Certificate Checks
Certificate Expiry - Days until expiration

Issuer Information - Certificate authority details

Subject Information - Certificate owner details

Validity Status - Expired, near expiry, or valid

Vulnerability Detection
Missing Security Headers - Identifies critical headers not present

Exposed Services - Flags insecure services (FTP, Telnet)

Certificate Issues - Expired or soon-to-expire certificates

Risk Scoring - Calculates overall risk score (0-100)

🔒 Safety Features
External IP Warning: Alerts when scanning public IPs without explicit permission

Safety Reminder: Always displays responsible usage notice

Private Range Detection: Automatically identifies local/private IP ranges

📝 Output Examples:
-Rich Console Output
-The scanner provides beautiful, color-coded output with:
-Tables for open ports, HTTP headers, and vulnerabilities
-Panels for safety warnings and scan information
-Color-coded risk assessment (Green/Yellow/Red)

JSON Reports
Save detailed scan results for later analysis:

json
{
  "target": "192.168.1.50",
  "timestamp": "2024-01-15T10:30:00Z",
  "ports": [...],
  "http_headers": {...},
  "tls_cert": {...},
  "vulnerabilities": [...],
  "risk_score": 45,
  "screenshots": [...]
}
🎨 Screenshot Feature
The screenshot feature requires Playwright:

bash
# Install Playwright
pip install playwright
playwright install

# Use with scans
vulnscan --target 192.168.1.50 --screenshot
Screenshots are saved to the screenshots/ directory with timestamps.

⚠️ Legal & Ethical Usage
IMPORTANT: This tool is for educational purposes and authorized testing only.

✅ Permitted Usage
Scanning your own systems

Testing systems with explicit written permission

Educational environments and CTF exercises

Security research with proper authorization

❌ Prohibited Usage
Scanning systems without explicit permission

Testing systems you don't own or manage

Malicious or unauthorized security testing

Violating laws or terms of service

Unauthorized scanning may be illegal in your jurisdiction. Always get proper authorization before scanning any system.

🐛 Troubleshooting
Common Issues
Import Errors:

bash
# Reinstall the package
pip install -e .
Playwright Not Working:

bash
# Reinstall Playwright
pip install playwright
playwright install
Permission Errors:

Ensure you're using --allow-external for external targets

Verify you have permission to scan the target

No Open Ports Found:

Check if the target is online and accessible

Verify firewall settings

Try different ports with --ports option

🔧 Development
The scanner is built with a modular architecture for easy extension:

Adding New Features
New Scanner Module: Create a new file in scanner/ directory

Update Main Scanner: Import and use in scanner.py

Add CLI Options: Update cli.py for new command-line options

Module Structure
Each component is isolated for testing

Clear separation of concerns

Easy to maintain and extend

📄 License
Educational Use - Only use on systems you own or have explicit permission to test.

🤝 Contributing
This is an educational project. Feel free to:

Report bugs or issues

Suggest new features

Improve documentation

Enhance security checks

Remember: With great power comes great responsibility. Always scan ethically! 🔒