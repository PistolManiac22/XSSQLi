"""
Parameter Discovery Module
"""

from bs4 import BeautifulSoup
from urllib.parse import urlparse, parse_qs
import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from webapp_config import WebAppConfig

class ParameterDiscoverer:
    """Discovers and tests parameters for XSS injection."""

    def __init__(self, webapp_config: 'WebAppConfig'):
        self.config = webapp_config
        self.session = webapp_config.get_session()
        self.logger = logging.getLogger('ParameterDiscoverer')

    def discover_parameters(self, url: str) -> list:
        """Discover all potential injectable parameters."""
        parameters = []
        try:
            response = self.session.get(url, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Check where we are
            if soup.title:
                self.logger.info(f"Scanning Page: [{soup.title.string.strip()}]")

            ignored_params = self.config.get_ignored_params()

            for form in soup.find_all('form'):
                for input_tag in form.find_all(['input', 'textarea']):
                    param_name = input_tag.get('name')
                    if param_name and param_name not in ignored_params:
                        if param_name not in parameters:
                            parameters.append(param_name)

            parsed_url = urlparse(url)
            if parsed_url.query:
                url_params = parse_qs(parsed_url.query)
                for param in url_params.keys():
                    if param not in parameters and param not in ignored_params:
                        parameters.append(param)

            return parameters

        except Exception as e:
            self.logger.error(f"Error discovering parameters: {e}")
            return []

    def is_parameter_reflected(self, url: str, param: str, probe_value: str = "XSS_PROBE_12345") -> bool:
        """Check if parameter value is reflected in response."""
        try:
            # 1. Start with Global Defaults (form=submit, firstname='', lastname='')
            params = self.config.get_global_params().copy()
            
            # 2. Overwrite the target parameter with our PROBE
            params[param] = probe_value
            
            response = self.session.get(url, params=params, timeout=10)
            return probe_value in response.text
        except Exception as e:
            self.logger.debug(f"Error testing parameter {param}: {e}")
            return False

    def detect_context_from_response(self, html: str, probe_value: str) -> str:
        """Detect context from HTML response."""
        try:
            soup = BeautifulSoup(html, 'html.parser')
            for script in soup.find_all("script"):
                if script.string and probe_value in script.string:
                    return "js"
            for tag in soup.find_all(True):
                for attr_val in tag.attrs.values():
                    if isinstance(attr_val, list):
                        if any(probe_value in str(v) for v in attr_val):
                            return "attribute"
                    else:
                        if probe_value in str(attr_val):
                            return "attribute"
            if probe_value in soup.get_text():
                return "text"
            return "unknown"
        except Exception as e:
            return "unknown"

    def find_injectable_parameters(self, url: str, probe_value: str = "XSS_PROBE_12345") -> dict:
        """Automatically find injectable parameters."""
        self.logger.info("Starting parameter discovery...")
        parameters = self.discover_parameters(url)
        self.logger.info(f"Found {len(parameters)} potential parameters: {parameters}")
        
        injectable_params = {}

        for param in parameters:
            self.logger.info(f"Testing parameter: {param}")
            if self.is_parameter_reflected(url, param, probe_value):
                self.logger.info(f"[+] Parameter reflected: {param}")
                
                # Context check
                params = self.config.get_global_params().copy()
                params[param] = probe_value
                
                response = self.session.get(url, params=params, timeout=10)
                context = self.detect_context_from_response(response.text, probe_value)
                injectable_params[param] = context
                self.logger.info(f"[+] Injectable: {param} (context: {context})")
            
        if not injectable_params:
            self.logger.warning("No injectable parameters found.")
            
        return injectable_params
