# Hopper - Advanced Open Redirect Vulnerability Scanner

![Hopper Scanner](generated-icon.png)

## Overview

Hopper is a high-speed Python-based open redirect vulnerability scanner with advanced payload support and minimal false positives. Created by aryahmpillai, it's designed to help bug hunters and security professionals quickly identify open redirect vulnerabilities in web applications.

## Features

- **Comprehensive Scanning**: Checks for open redirect vulnerabilities in all parts of a URL
- **Advanced Payloads**: Uses a wide range of sophisticated payloads to bypass filters
- **Minimal False Positives**: Smart validation of redirects to confirm actual vulnerabilities
- **URL Fuzzing**: Discovers hidden or less obvious redirect parameters
- **Multiple Bypass Techniques**: Supports URL encoding, double encoding, backslashing, and special characters
- **External Redirect Detection**: Analyzes HTTP response codes and follows redirect chains
- **Reporting**: Clean logs showing vulnerable URLs, payloads used, and redirect destinations
- **Multi-threading**: Handles large URL lists efficiently with parallel processing
- **Proxy Support**: Run requests through proxies like Burp Suite
- **Customization**: Use your own payload lists and configure scan parameters

## Installation

```bash
# Clone the repository
git clone https://github.com/aryahmpillai/hopper.git
cd hopper

# Install dependencies
pip install -r requirements.txt
```

## Usage

### Basic Usage

```bash
# Scan a single URL
python hopper.py -u https://example.com/redirectpage

# Scan multiple URLs from a file
python hopper.py -l urls.txt

# Use custom payloads
python hopper.py -u https://example.com/redirectpage -p custom_payloads.txt
```

### Advanced Options

```bash
# Set number of threads for parallel processing
python hopper.py -l urls.txt -t 20

# Specify timeout and delay between requests
python hopper.py -u https://example.com/redirectpage --timeout 15 --delay 0.5

# Use a proxy
python hopper.py -u https://example.com/redirectpage --proxy http://127.0.0.1:8080

# Save results to a file
python hopper.py -l urls.txt -o results.txt

# Verbose output
python hopper.py -u https://example.com/redirectpage -v

# Only show found vulnerabilities (quiet mode)
python hopper.py -l urls.txt --quiet
```

### Command Line Arguments

```
  -h, --help            Show this help message and exit
  -u URL, --url URL     Single URL to scan
  -l LIST, --list LIST  File containing list of URLs to scan
  -p PAYLOAD, --payload PAYLOAD
                        File containing custom payloads
  -t THREADS, --threads THREADS
                        Number of threads (default: 10)
  -o OUTPUT, --output OUTPUT
                        Output file for results
  -v, --verbose         Verbose output
  --proxy PROXY         Proxy to use (e.g., http://127.0.0.1:8080)
  --timeout TIMEOUT     Request timeout in seconds (default: 10)
  --delay DELAY         Delay between requests in seconds (default: 0)
  --user-agent USER_AGENT
                        Custom User-Agent string
  --follow-redirects FOLLOW_REDIRECTS
                        Maximum number of redirects to follow (default: 5)
  --quiet               Only show found vulnerabilities
```

## Example Custom Payload File

```
# Custom Open Redirect Payloads
# Format: One payload per line, comments start with #

https://evil.com
//evil.com
https://google.com@evil.com
https://evil.com%2Egoogle.com
```

## How It Works

1. **URL Analysis**: Hopper first analyzes the URL to identify potential redirect parameters
2. **Parameter Fuzzing**: It then tries to discover hidden redirect parameters
3. **Payload Testing**: Each parameter is tested with various payloads and bypass techniques
4. **Redirect Analysis**: It analyzes HTTP, HTML, and JavaScript-based redirects
5. **Validation**: Confirms that the redirect is to an external domain containing the payload
6. **Reporting**: Reports confirmed vulnerabilities with detailed information

## Output Example

For each vulnerability discovered, Hopper provides detailed information:

```
[VULNERABLE] Open Redirect Found!
URL: https://example.com/redirect?url=https://example.com
Parameter: url
Payload: https://evil.com
Bypass Technique: standard
Redirect Type: HTTP
Redirects To: https://evil.com
```

## Contributing

Contributions are welcome! Feel free to submit pull requests or open issues for:

- New bypass techniques
- Additional payload types
- Bug fixes
- Performance improvements
- Feature requests

## License

This project is licensed under the MIT License - see the LICENSE file for details.