"""
Parameter Discovery Module
Automatically detects injectable parameters in a web form/URL
"""

from bs4 import BeautifulSoup
import requests
from urllib.parse import urlparse, parse_qs
import logging


class ParameterDiscoverer:
    """Discovers and tests parameters for XSS injection."""
    
    def __init__(self, session=None):
        self.session = session if session else requests.Session()
        self.logger = logging.getLogger('ParameterDiscoverer')
    
    def discover_parameters(self, url: str) -> list:
        """
        Discover all potential injectable parameters.
        
        Returns:
            List of parameter names
        """
        parameters = []
        
        try:
            response = self.session.get(url, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Find from HTML form inputs
            for form in soup.find_all('form'):
                for input_tag in form.find_all('input'):
                    param_name = input_tag.get('name')
                    if param_name and param_name not in parameters:
                        parameters.append(param_name)
                        self.logger.debug(f"Found form input: {param_name}")
            
            # Find from URL query string
            parsed_url = urlparse(url)
            if parsed_url.query:
                url_params = parse_qs(parsed_url.query)
                for param in url_params.keys():
                    if param not in parameters:
                        parameters.append(param)
                        self.logger.debug(f"Found URL parameter: {param}")
            
            # Common parameter names to try
            common_params = ['q', 'search', 'name', 'id', 'comment', 'message', 
                           'query', 'text', 'input', 'email', 'title', 'description']
            for param in common_params:
                if param not in parameters:
                    parameters.append(param)
            
            return parameters
        
        except Exception as e:
            self.logger.error(f"Error discovering parameters: {e}")
            return []
    
    def is_parameter_reflected(self, url: str, param: str, probe_value: str = "XSS_PROBE_12345") -> bool:
        """Check if parameter value is reflected in response."""
        try:
            params = {param: probe_value}
            response = self.session.get(url, params=params, timeout=10)
            return probe_value in response.text
        except Exception as e:
            self.logger.debug(f"Error testing parameter {param}: {e}")
            return False
    
    def detect_context_from_response(self, html: str, probe_value: str) -> str:
        """
        Detect context from HTML response.
        
        Returns:
            'js', 'attribute', 'text', or 'unknown'
        """
        try:
            soup = BeautifulSoup(html, 'html.parser')
            
            # Check JavaScript context
            for script in soup.find_all("script"):
                if script.string and probe_value in script.string:
                    self.logger.debug(f"Detected context: JS (in script tag)")
                    return "js"
            
            # Check attribute context
            for tag in soup.find_all(True):
                for attr_val in tag.attrs.values():
                    if isinstance(attr_val, list):
                        if any(probe_value in str(v) for v in attr_val):
                            self.logger.debug(f"Detected context: attribute")
                            return "attribute"
                    else:
                        if probe_value in str(attr_val):
                            self.logger.debug(f"Detected context: attribute")
                            return "attribute"
            
            # Check text context
            if probe_value in soup.get_text():
                self.logger.debug(f"Detected context: text")
                return "text"
            
            return "unknown"
        
        except Exception as e:
            self.logger.warning(f"Error detecting context: {e}")
            return "unknown"
    
    def find_injectable_parameters(self, url: str, probe_value: str = "XSS_PROBE_12345") -> dict:
        """
        Automatically find injectable parameters and their contexts.
        
        Returns:
            Dict: {param_name: context_type, ...}
        """
        self.logger.info("Starting parameter discovery...")
        
        # Get all potential parameters
        parameters = self.discover_parameters(url)
        self.logger.info(f"Found {len(parameters)} potential parameters: {parameters}")
        
        injectable_params = {}
        
        for param in parameters:
            self.logger.info(f"Testing parameter: {param}")
            
            try:
                # Test if parameter is reflected
                if self.is_parameter_reflected(url, param, probe_value):
                    self.logger.info(f"[+] Parameter reflected: {param}")
                    
                    # Get response and detect context
                    params = {param: probe_value}
                    response = self.session.get(url, params=params, timeout=10)
                    context = self.detect_context_from_response(response.text, probe_value)
                    
                    injectable_params[param] = context
                    self.logger.info(f"[+] Injectable: {param} (context: {context})")
                else:
                    self.logger.debug(f"[-] Parameter not reflected: {param}")
            
            except Exception as e:
                self.logger.debug(f"Error testing {param}: {e}")
        
        if injectable_params:
            self.logger.info(f"Found {len(injectable_params)} injectable parameters: {injectable_params}")
        else:
            self.logger.warning("No injectable parameters found")
        
        return injectable_params
