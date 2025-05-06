"""
Fuzzer module for the Hopper open redirect scanner.
Used to discover hidden or non-obvious redirect parameters.
"""

import logging
import re
from urllib.parse import urlparse, parse_qs, urlencode

from utils import extract_parameters

logger = logging.getLogger("hopper")

class ParameterFuzzer:
    """Class to fuzz URL parameters for discovering hidden redirect points."""
    
    def __init__(self):
        """Initialize the parameter fuzzer with common redirect parameter names."""
        self.common_redirect_params = [
            # Common redirect parameter names
            'redirect', 'redirect_uri', 'redirect_url', 'redirecturi', 'redirecturl',
            'redir', 'redirurl', 'return', 'returnurl', 'return_url', 'returnto',
            'return_to', 'destination', 'next', 'checkout_url', 'continue', 'continueurl',
            'url', 'goto', 'go', 'exit', 'target', 'link', 'out', 'to', 'view', 'path',
            'Navigation', 'jump', 'jumpurl', 'returnUri', 'retURL', 'forward', 'dest',
            'dir', 'callback', 'oauth_callback', 'uri', 'location', 'back', 'backurl',
            'from_url', 'go_to', 'login_url', 'loginto', 'logout', 'logouturl',
            'referrer', 'ref', 'referer', 'page', 'page_url', 'address', 'origin',
            'site', 'source', 'u', 'uri', 'endpoint', 'success_url', 'cancel_url',
            'docurl', 'document', 'load', 'window', 'data', 'channel', 'successUrl',
            'cancelUrl', 'failUrl', 'return_path', 'backto'
        ]
    
    def fuzz_parameters(self, url, session, timeout):
        """Fuzz the URL to discover hidden redirect parameters."""
        discovered_params = []
        parsed_url = urlparse(url)
        
        # Check if the URL already has parameters
        original_params = extract_parameters(url)
        
        # First, try to find redirect parameters in the HTML content
        try:
            response = session.get(url, timeout=timeout, verify=False)
            if response.status_code == 200:
                discovered_params.extend(self._extract_params_from_html(response.text))
        except Exception as e:
            logger.debug(f"Error fetching URL for parameter discovery: {str(e)}")
        
        # Then try common redirect parameter names
        discovered_params.extend(self._fuzz_common_parameters(url, session, timeout))
        
        # Remove duplicates and parameters that already exist in the URL
        discovered_params = list(set(discovered_params) - set(original_params))
        
        if discovered_params:
            logger.debug(f"Discovered potential redirect parameters: {', '.join(discovered_params)}")
        
        return discovered_params
    
    def _extract_params_from_html(self, html_content):
        """Extract potential redirect parameters from HTML content."""
        discovered_params = []
        
        # Look for form fields that might be used for redirects
        form_field_pattern = r'<input\s+[^>]*name=[\'"]([^\'"]+)[\'"][^>]*>'
        form_fields = re.findall(form_field_pattern, html_content, re.IGNORECASE)
        
        # Look for query parameters in URLs
        url_pattern = r'(?:href|src|action)=[\'"](?:[^\'"]*)[\?&]([^=&]+)='
        url_params = re.findall(url_pattern, html_content, re.IGNORECASE)
        
        # Look for potential redirect parameters in JavaScript
        js_pattern = r'[\'"]((?:redirect|return|callback|goto|next|url|destination|back)[^\'"]*)[\'"]'
        js_params = re.findall(js_pattern, html_content, re.IGNORECASE)
        
        # Combine all discovered parameters
        all_params = form_fields + url_params + js_params
        
        # Filter for likely redirect parameters
        for param in all_params:
            for redirect_keyword in ['redirect', 'return', 'callback', 'goto', 'next', 
                                   'url', 'destination', 'back', 'continue', 'target']:
                if redirect_keyword in param.lower():
                    discovered_params.append(param)
                    break
        
        return discovered_params
    
    def _fuzz_common_parameters(self, url, session, timeout):
        """Test common redirect parameter names to see if they're accepted."""
        discovered_params = []
        parsed_url = urlparse(url)
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
        existing_params = parse_qs(parsed_url.query)
        
        # Test a subset of common parameters to avoid too many requests
        test_params = self.common_redirect_params[:15]  # Limit to top 15 most common
        
        for param_name in test_params:
            # Skip if parameter already exists
            if param_name in existing_params:
                continue
                
            # Create test URL with the parameter
            test_params = existing_params.copy()
            test_params[param_name] = ['https://example.com']
            test_url = f"{base_url}?{urlencode(test_params, doseq=True)}"
            
            try:
                # Send request with the parameter
                response = session.get(test_url, timeout=timeout, verify=False, allow_redirects=False)
                
                # If the server responds with a redirect, the parameter might be valid
                if response.status_code in (301, 302, 303, 307, 308):
                    redirect_url = response.headers.get('Location', '')
                    # Check if the redirect URL contains example.com (our test domain)
                    if 'example.com' in redirect_url:
                        discovered_params.append(param_name)
            except Exception:
                # Ignore errors during fuzzing
                pass
        
        return discovered_params
