"""
Utility functions for the Hopper open redirect scanner.
"""

import re
import os
import logging
import urllib.parse
from urllib.parse import urlparse, parse_qs, quote

from colorama import Fore, Style

logger = logging.getLogger("hopper")

def print_banner():
    """Print the ASCII art banner for Hopper."""
    banner = f"""
{Fore.CYAN}
  _    _                                 
 | |  | |                                
 | |__| | ___  _ __  _ __   ___ _ __ 
 |  __  |/ _ \| '_ \| '_ \ / _ \ '__|
 | |  | | (_) | |_) | |_) |  __/ |   
 |_|  |_|\___/| .__/| .__/ \___|_|   
              | |   | |              
              |_|   |_|              
{Style.RESET_ALL}
{Fore.GREEN}[ Advanced Open Redirect Vulnerability Scanner ]{Style.RESET_ALL}
{Fore.YELLOW}[ Created by aryahmpillai ]{Style.RESET_ALL}
{Fore.CYAN}[ https://github.com/aryahmpillai/hopper ]{Style.RESET_ALL}

"""
    print(banner)

def load_urls_from_file(file_path):
    """Load URLs from a file, one URL per line."""
    urls = []
    
    if not os.path.exists(file_path):
        logger.error(f"File not found: {file_path}")
        return urls
        
    try:
        with open(file_path, 'r') as f:
            for line in f:
                url = line.strip()
                if url and not url.startswith('#'):
                    # Make sure the URL has a scheme
                    if not url.startswith(('http://', 'https://')):
                        url = f"http://{url}"
                    urls.append(url)
                    
        logger.info(f"Loaded {len(urls)} URLs from {file_path}")
    except Exception as e:
        logger.error(f"Error loading URLs from file: {e}")
    
    return urls

def extract_parameters(url):
    """Extract parameter names from a URL."""
    parsed = urlparse(url)
    
    # Get query parameters
    params = list(parse_qs(parsed.query).keys())
    
    # Also check for parameters in the path (REST-style URLs)
    path_params = re.findall(r'/([^/]+)/([^/]+)', parsed.path)
    for param, value in path_params:
        if param.lower() in ['redirect', 'return', 'next', 'url', 'goto', 'continue']:
            params.append(param)
    
    return params

def extract_domain(url):
    """Extract the domain from a URL."""
    try:
        parsed = urlparse(url)
        return parsed.netloc
    except:
        return ""

def is_same_domain(domain1, domain2):
    """Check if two domains are the same or subdomains of each other."""
    if not domain1 or not domain2:
        return False
        
    # Remove port if present
    domain1 = domain1.split(':')[0]
    domain2 = domain2.split(':')[0]
    
    # Compare exact match
    if domain1 == domain2:
        return True
    
    # Check if one is a subdomain of the other
    parts1 = domain1.split('.')
    parts2 = domain2.split('.')
    
    # Extract base domain (last two parts)
    base1 = '.'.join(parts1[-2:]) if len(parts1) >= 2 else domain1
    base2 = '.'.join(parts2[-2:]) if len(parts2) >= 2 else domain2
    
    return base1 == base2

def apply_bypass_technique(payload, technique):
    """Apply different bypass techniques to a payload."""
    if technique == 'standard':
        return payload
    
    elif technique == 'url_encode':
        # URL encode once
        return urllib.parse.quote(payload)
    
    elif technique == 'double_encode':
        # URL encode twice
        return urllib.parse.quote(urllib.parse.quote(payload))
    
    elif technique == 'backslash':
        # Add backslashes to potentially bypass filters
        if payload.startswith('http'):
            parts = payload.split('://')
            if len(parts) >= 2:
                return f"{parts[0]}://\\{parts[1]}"
        
        # If not starting with http, just add backslashes before slashes
        return payload.replace('/', '\\/')
    
    elif technique == 'special_chars':
        # Add special characters for potential bypasses
        # Try to insert nullbytes, tabs, etc. in strategic places
        if payload.startswith('http'):
            parts = payload.split('://')
            if len(parts) >= 2:
                domain_parts = parts[1].split('.')
                if len(domain_parts) >= 2:
                    # Insert special character between domain parts
                    domain_parts[0] = f"{domain_parts[0]}%09"
                    return f"{parts[0]}://{'.'.join(domain_parts)}"
        
        return payload
    
    # Default to original payload if technique not recognized
    return payload
