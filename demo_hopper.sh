#!/bin/bash
# Demo script for showing Hopper usage examples

echo "==== Hopper Open Redirect Scanner Demo ===="
echo ""

# Run the vulnerable demo app in the background
echo "Starting vulnerable demo application on port 8000..."
python demo_vulnerable_app.py &
APP_PID=$!

# Give the app a moment to start
sleep 2
echo "Vulnerable application started."
echo ""

# Example 1: Basic scan of a single URL
echo "==== Example 1: Scanning a single URL ===="
echo "Command: python hopper.py -u http://localhost:8000/redirect?url=https://example.com"
python hopper.py -u http://localhost:8000/redirect?url=https://example.com
echo ""

# Example 2: Scan with custom payloads
echo "==== Example 2: Scanning with custom payloads ===="
echo "Command: python hopper.py -u http://localhost:8000/login -p custom_payloads.txt"
python hopper.py -u http://localhost:8000/login -p custom_payloads.txt
echo ""

# Example 3: Scan multiple URLs from a file
echo "==== Example 3: Scanning multiple URLs from a file ===="
# Create a temp file with localhost URLs
cat > temp_urls.txt << EOF
http://localhost:8000/redirect?url=https://example.com
http://localhost:8000/login?next=https://example.com
http://localhost:8000/go?to=https://example.com
http://localhost:8000/js-redirect?location=https://example.com
EOF
echo "Command: python hopper.py -l temp_urls.txt -t 4"
python hopper.py -l temp_urls.txt -t 4
echo ""

# Example 4: Verbose output with output file
echo "==== Example 4: Verbose output with results saved to file ===="
echo "Command: python hopper.py -u http://localhost:8000/meta-redirect -v -o results.txt"
python hopper.py -u http://localhost:8000/meta-redirect -v -o results.txt
echo ""
echo "Results saved to results.txt"
echo ""

# Clean up
echo "Cleaning up..."
kill $APP_PID
rm temp_urls.txt
echo "Demo completed."