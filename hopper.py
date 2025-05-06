#!/usr/bin/env python3
"""
Hopper - Advanced Open Redirect Vulnerability Scanner
Created by aryahmpillai

A high-speed Python-based open redirect vulnerability scanner 
with advanced payload support and minimal false positives.
"""

import argparse
import concurrent.futures
import sys
import time
from datetime import datetime
import logging

from colorama import init, Fore, Style
from scanner import OpenRedirectScanner
from utils import load_urls_from_file, print_banner

# Initialize colorama for cross-platform colored terminal output
init(autoreset=True)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("hopper_scan.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("hopper")

def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='Hopper - Advanced Open Redirect Vulnerability Scanner')
    
    # Main arguments group
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument('-u', '--url', help='Single URL to scan')
    input_group.add_argument('-l', '--list', help='File containing list of URLs to scan')
    
    # Additional options
    parser.add_argument('-p', '--payload', help='File containing custom payloads')
    parser.add_argument('-t', '--threads', type=int, default=10, help='Number of threads (default: 10)')
    parser.add_argument('-o', '--output', help='Output file for results')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('--proxy', help='Proxy to use (e.g., http://127.0.0.1:8080)')
    parser.add_argument('--timeout', type=int, default=10, help='Request timeout in seconds (default: 10)')
    parser.add_argument('--delay', type=float, default=0, help='Delay between requests in seconds (default: 0)')
    parser.add_argument('--user-agent', help='Custom User-Agent string')
    parser.add_argument('--follow-redirects', type=int, default=5, 
                         help='Maximum number of redirects to follow (default: 5)')
    parser.add_argument('--quiet', action='store_true', help='Only show found vulnerabilities')
    
    return parser.parse_args()

def main():
    """Main function to run the Hopper scanner."""
    # Print the ASCII banner
    print_banner()
    
    # Parse command line arguments
    args = parse_arguments()
    
    # Set verbosity level
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    
    # Create output file if specified
    output_file = None
    if args.output:
        try:
            output_file = open(args.output, 'w')
            output_file.write(f"# Hopper Open Redirect Scan Results\n")
            output_file.write(f"# Scan started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        except IOError as e:
            logger.error(f"Failed to open output file: {e}")
            sys.exit(1)
    
    # Prepare URLs to scan
    urls = []
    if args.url:
        urls = [args.url]
    elif args.list:
        urls = load_urls_from_file(args.list)
    
    if not urls:
        logger.error("No valid URLs to scan!")
        sys.exit(1)
    
    logger.info(f"Loaded {len(urls)} URL(s) to scan")
    
    # Create scanner instance
    scanner = OpenRedirectScanner(
        payload_file=args.payload,
        proxy=args.proxy,
        timeout=args.timeout,
        user_agent=args.user_agent,
        follow_redirects=args.follow_redirects,
        delay=args.delay,
        output_file=output_file,
        quiet_mode=args.quiet
    )
    
    # Start scanning
    start_time = time.time()
    
    if len(urls) == 1:
        # Single URL scan
        scanner.scan_url(urls[0])
    else:
        # Multiple URLs scan with threading
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
            list(executor.map(scanner.scan_url, urls))
    
    # Print summary
    elapsed_time = time.time() - start_time
    logger.info(f"Scan completed in {elapsed_time:.2f} seconds")
    logger.info(f"Found {scanner.vulnerability_count} potential open redirect vulnerabilities")
    
    # Close output file if open
    if output_file:
        output_file.write(f"\n# Scan completed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        output_file.write(f"# Total vulnerabilities found: {scanner.vulnerability_count}\n")
        output_file.close()
        logger.info(f"Results saved to {args.output}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Scan interrupted by user. Exiting...{Style.RESET_ALL}")
        sys.exit(0)
    except Exception as e:
        logger.error(f"An unexpected error occurred: {e}")
        sys.exit(1)
