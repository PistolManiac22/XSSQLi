"""
Web Application Configuration Interface
Abstracts authentication and payload delivery for different web apps
"""

from abc import ABC, abstractmethod
import requests
import logging
from typing import Optional, List, Dict
from bs4 import BeautifulSoup

class WebAppConfig(ABC):
    """Abstract base class for web application configurations."""

    def __init__(self, base_url: str, username: str = "", password: str = ""):
        self.base_url = base_url
        self.username = username
        self.password = password
        self.session = requests.Session()
        self.logger = logging.getLogger(self.__class__.__name__)

    @abstractmethod
    def authenticate(self) -> Optional[requests.Session]:
        """Authenticate to the web application."""
        pass

    @abstractmethod
    def send_payload(self, url: str, param: str, payload: str) -> str:
        """Send payload to target and return response."""
        pass

    def get_session(self) -> requests.Session:
        """Get authenticated session."""
        return self.session

    # --- NEW METHODS FOR MODULARITY ---

    def get_global_params(self) -> Dict[str, str]:
        """
        Return dictionary of parameters that must be included in EVERY request.
        Override this in specific configs (e.g., bWAPP needs {'form': 'submit'}).
        """
        return {}

    def get_ignored_params(self) -> List[str]:
        """
        Return list of parameter names to ignore during discovery.
        Override this to blacklist login fields, security levels, etc.
        """
        return []

class GenericWebApp(WebAppConfig):
    """Generic web application (no authentication)."""

    def authenticate(self) -> Optional[requests.Session]:
        self.logger.info("Generic web app (no authentication required)")
        return self.session

    def send_payload(self, url: str, param: str, payload: str) -> str:
        """Hybrid approach: pattern detection + form analysis fallback."""
        try:
            data = {param: payload}
            data.update(self.get_global_params())
            
            # 1️⃣ Pattern detection dulu (cepat)
            if "sqli" in url.lower():
                method = "POST"
            elif "xss_reflected" in url.lower() or "xss_r" in url.lower():
                method = "GET"
            else:
                # 2️⃣ Fallback ke form analysis
                method = self._detect_form_method(url, param)
            
            # 3️⃣ Kirim dengan method yang sesuai
            if method == "POST":
                data["Submit"] = "Submit"
                resp = self.session.post(url, data=data, timeout=10, allow_redirects=True)
            else:
                resp = self.session.get(url, params=data, timeout=10)
            
            return resp.text
        except Exception as e:
            self.logger.warning(f"Error sending payload: {e}")
            return ""

    def _detect_form_method(self, url: str, param: str) -> str:
        """Cache form method detection."""
        if not hasattr(self, '_method_cache'):
            self._method_cache = {}
        
        if url in self._method_cache:
            return self._method_cache[url]
        
        try:
            resp = self.session.get(url, timeout=10)
            soup = BeautifulSoup(resp.text, 'html.parser')
            
            for form in soup.find_all('form'):
                for inp in form.find_all(['input', 'textarea']):
                    if inp.get('name') == param:
                        method = form.get('method', 'POST').upper()
                        self._method_cache[url] = method
                        self.logger.info(f"Form method: {method}")
                        return method
            
            # Default
            self._method_cache[url] = "POST"
            return "POST"
        except:
            return "POST"

