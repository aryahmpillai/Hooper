"""
Scanner module for the Hopper open redirect scanner.
Handles URL scanning, payload testing, and vulnerability identification.
"""

import time
import re
import logging
import sys
from urllib.parse import urlparse, parse_qs, urljoin, urlencode, unquote

import requests
from colorama import Fore, Style

from payloads import OpenRedirectPayloads
from fuzzer import ParameterFuzzer
from utils import extract_parameters, is_same_domain, extract_domain, apply_bypass_technique

# Disable SSL warnings
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger("hopper")

class OpenRedirectScanner:
    """Scanner class for finding open redirect vulnerabilities."""
    
    def __init__(self, payload_file=None, proxy=None, timeout=10, user_agent=None, 
                follow_redirects=5, delay=0, output_file=None, quiet_mode=False):
        """Initialize the scanner with the given configuration."""
        self.payloads = OpenRedirectPayloads(custom_payload_file=payload_file)
        self.fuzzer = ParameterFuzzer()
        self.vulnerability_count = 0
        self.timeout = timeout
        self.follow_redirects = follow_redirects
        self.delay = delay
        self.output_file = output_file
        self.quiet_mode = quiet_mode
        
        # Setup session
        self.session = requests.Session()
        
        # Configure proxies if specified
        if proxy:
            self.session.proxies = {
                "http": proxy,
                "https": proxy
            }
        
        # Set User-Agent
        if user_agent:
            self.session.headers["User-Agent"] = user_agent
        else:
            self.session.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
    
    def scan_url(self, url):
        """Scan a single URL for open redirect vulnerabilities."""
        if not self._is_valid_url(url):
            if not self.quiet_mode:
                logger.warning(f"Invalid URL format: {url}")
            return
        
        if not self.quiet_mode:
            logger.info(f"Scanning: {url}")
        
        # Get base domain for comparison with redirects
        base_domain = extract_domain(url)
        
        # Extract parameters from the URL
        original_params = extract_parameters(url)
        
        # Fuzz for additional parameters
        fuzzed_params = self.fuzzer.fuzz_parameters(url, self.session, self.timeout)
        
        # Combine original and fuzzed parameters
        all_params = list(set(original_params + fuzzed_params))
        
        if len(all_params) == 0 and not self.quiet_mode:
            logger.info(f"No parameters found in URL: {url}")
            return
        
        # Test each parameter
        for param_name in all_params:
            self._test_parameter(url, param_name, base_domain)
            
            # Apply delay if specified
            if self.delay > 0:
                time.sleep(self.delay)
    
    def _test_parameter(self, url, param_name, base_domain):
        """Test a specific parameter for open redirect vulnerabilities."""
        if not self.quiet_mode:
            logger.debug(f"Testing parameter: {param_name} in {url}")
        
        # Extract URL without the query string
        parsed_url = urlparse(url)
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
        
        # Get original parameters
        query_params = parse_qs(parsed_url.query)
        
        # Test parameter with each payload
        for payload in self.payloads.get_payloads():
            for bypass_technique in ['standard', 'url_encode', 'double_encode', 'backslash', 'special_chars']:
                # Apply bypass technique to payload
                processed_payload = apply_bypass_technique(payload, bypass_technique)
                
                # Create new query parameters with the payload
                new_params = query_params.copy()
                new_params[param_name] = [processed_payload]
                
                # Create the new URL with the payload
                test_url = f"{base_url}?{urlencode(new_params, doseq=True)}"
                
                # Send request and analyze
                self._send_request_and_analyze(
                    original_url=url,
                    test_url=test_url,
                    param_name=param_name,
                    payload=payload,
                    bypass_technique=bypass_technique,
                    base_domain=base_domain
                )
    
    def _send_request_and_analyze(self, original_url, test_url, param_name, payload, bypass_technique, base_domain):
        """Send a request with a payload and analyze the response."""
        try:
            # Send the request with allow_redirects=False to handle redirects manually
            response = self.session.get(
                test_url,
                timeout=self.timeout,
                verify=False,
                allow_redirects=False
            )
            
            # Check for immediate redirect
            if response.status_code in (301, 302, 303, 307, 308):
                redirect_url = response.headers.get('Location', '')
                
                # If the redirect URL is absolute
                if redirect_url.startswith(('http://', 'https://')):
                    redirect_domain = extract_domain(redirect_url)
                    
                    # Check if the redirect is to a different domain
                    if not is_same_domain(base_domain, redirect_domain):
                        if payload in redirect_url or unquote(payload) in redirect_url:
                            self._report_vulnerability(
                                url=original_url,
                                param=param_name,
                                payload=payload,
                                technique=bypass_technique,
                                redirect_url=redirect_url
                            )
                            return
                
                # If the redirect URL is relative, we need to resolve it
                elif redirect_url.startswith('/'):
                    # Resolve the relative URL
                    absolute_redirect = urljoin(test_url, redirect_url)
                    redirect_domain = extract_domain(absolute_redirect)
                    
                    # Check if the redirect is to a different domain
                    if not is_same_domain(base_domain, redirect_domain):
                        if payload in absolute_redirect or unquote(payload) in absolute_redirect:
                            self._report_vulnerability(
                                url=original_url,
                                param=param_name,
                                payload=payload,
                                technique=bypass_technique,
                                redirect_url=absolute_redirect
                            )
                            return
                
                # Follow the redirect chain if configured
                if self.follow_redirects > 0:
                    self._follow_redirect_chain(
                        original_url=original_url,
                        redirect_url=urljoin(test_url, redirect_url),
                        param_name=param_name,
                        payload=payload,
                        bypass_technique=bypass_technique,
                        base_domain=base_domain,
                        remaining_redirects=self.follow_redirects
                    )
            
            # Check for meta refresh redirects or JavaScript redirects in the response body
            elif response.status_code == 200:
                self._check_html_redirects(
                    original_url=original_url,
                    test_url=test_url,
                    response=response,
                    param_name=param_name,
                    payload=payload,
                    bypass_technique=bypass_technique,
                    base_domain=base_domain
                )
                
        except requests.RequestException as e:
            if not self.quiet_mode:
                logger.debug(f"Request error for {test_url}: {str(e)}")
    
    def _follow_redirect_chain(self, original_url, redirect_url, param_name, payload, 
                              bypass_technique, base_domain, remaining_redirects):
        """Follow a chain of redirects to detect external redirects."""
        if remaining_redirects <= 0:
            return
        
        try:
            # Send the request with allow_redirects=False to handle each redirect manually
            response = self.session.get(
                redirect_url,
                timeout=self.timeout,
                verify=False,
                allow_redirects=False
            )
            
            # Check for immediate redirect
            if response.status_code in (301, 302, 303, 307, 308):
                next_redirect = response.headers.get('Location', '')
                
                # Resolve the next redirect URL
                next_redirect_url = urljoin(redirect_url, next_redirect)
                redirect_domain = extract_domain(next_redirect_url)
                
                # Check if the redirect is to a different domain
                if not is_same_domain(base_domain, redirect_domain):
                    if payload in next_redirect_url or unquote(payload) in next_redirect_url:
                        self._report_vulnerability(
                            url=original_url,
                            param=param_name,
                            payload=payload,
                            technique=bypass_technique,
                            redirect_url=next_redirect_url,
                            redirect_chain=True
                        )
                        return
                
                # Continue following the redirect chain
                self._follow_redirect_chain(
                    original_url=original_url,
                    redirect_url=next_redirect_url,
                    param_name=param_name,
                    payload=payload,
                    bypass_technique=bypass_technique,
                    base_domain=base_domain,
                    remaining_redirects=remaining_redirects - 1
                )
            
            # Check for meta refresh redirects or JavaScript redirects in the response body
            elif response.status_code == 200:
                self._check_html_redirects(
                    original_url=original_url,
                    test_url=redirect_url,
                    response=response,
                    param_name=param_name,
                    payload=payload,
                    bypass_technique=bypass_technique,
                    base_domain=base_domain
                )
                
        except requests.RequestException as e:
            if not self.quiet_mode:
                logger.debug(f"Request error while following redirect to {redirect_url}: {str(e)}")
    
    def _check_html_redirects(self, original_url, test_url, response, param_name, 
                             payload, bypass_technique, base_domain):
        """Check for HTML-based redirects (meta refresh, JavaScript)."""
        try:
            content = response.text
            
            # Check for meta refresh redirects
            meta_refresh = re.search(r'<meta\s+http-equiv=["\']refresh["\']\s+content=["\'].*?url=(.*?)["\']', content, re.IGNORECASE)
            if meta_refresh:
                meta_redirect_url = meta_refresh.group(1)
                absolute_redirect = urljoin(test_url, meta_redirect_url)
                redirect_domain = extract_domain(absolute_redirect)
                
                if not is_same_domain(base_domain, redirect_domain):
                    if payload in absolute_redirect or unquote(payload) in absolute_redirect:
                        self._report_vulnerability(
                            url=original_url,
                            param=param_name,
                            payload=payload,
                            technique=bypass_technique,
                            redirect_url=absolute_redirect,
                            redirect_type="META refresh"
                        )
                        return
            
            # Check for JavaScript redirects
            js_redirect_patterns = [
                r'window\.location(?:\.href)?\s*=\s*[\'"]([^\'"]+)[\'"]',
                r'location\.replace\([\'"]([^\'"]+)[\'"]\)',
                r'location\.href\s*=\s*[\'"]([^\'"]+)[\'"]',
                r'document\.location\s*=\s*[\'"]([^\'"]+)[\'"]'
            ]
            
            for pattern in js_redirect_patterns:
                js_match = re.search(pattern, content, re.IGNORECASE)
                if js_match:
                    js_redirect_url = js_match.group(1)
                    absolute_redirect = urljoin(test_url, js_redirect_url)
                    redirect_domain = extract_domain(absolute_redirect)
                    
                    if not is_same_domain(base_domain, redirect_domain):
                        if payload in absolute_redirect or unquote(payload) in absolute_redirect:
                            self._report_vulnerability(
                                url=original_url,
                                param=param_name,
                                payload=payload,
                                technique=bypass_technique,
                                redirect_url=absolute_redirect,
                                redirect_type="JavaScript"
                            )
                            return
        
        except Exception as e:
            if not self.quiet_mode:
                logger.debug(f"Error checking HTML redirects in {test_url}: {str(e)}")
    
    def _report_vulnerability(self, url, param, payload, technique, redirect_url, 
                             redirect_type="HTTP", redirect_chain=False):
        """Report a found vulnerability."""
        self.vulnerability_count += 1
        
        # Create detailed vulnerability report
        report = f"\n{Fore.RED}[VULNERABLE] {Fore.RESET}Open Redirect Found!\n"
        report += f"{Fore.YELLOW}URL:{Fore.RESET} {url}\n"
        report += f"{Fore.YELLOW}Parameter:{Fore.RESET} {param}\n"
        report += f"{Fore.YELLOW}Payload:{Fore.RESET} {payload}\n"
        report += f"{Fore.YELLOW}Bypass Technique:{Fore.RESET} {technique}\n"
        report += f"{Fore.YELLOW}Redirect Type:{Fore.RESET} {redirect_type}"
        if redirect_chain:
            report += " (found in redirect chain)"
        report += f"\n{Fore.YELLOW}Redirects To:{Fore.RESET} {redirect_url}\n"
        
        # Print to console
        print(report)
        
        # Write to output file if specified
        if self.output_file:
            # Write without color codes
            clean_report = report.replace(Fore.RED, "").replace(Fore.YELLOW, "").replace(Fore.RESET, "")
            self.output_file.write(clean_report + "\n")
            self.output_file.flush()
    
    def _is_valid_url(self, url):
        """Check if a URL is valid."""
        try:
            result = urlparse(url)
            return all([result.scheme, result.netloc]) and result.scheme in ['http', 'https']
        except:
            return False
