"""
Web Application Configuration Interface
Abstracts authentication and payload delivery for different web apps
"""

from abc import ABC, abstractmethod
import requests
import logging
from typing import Optional


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
        """Authenticate to the web application. Return authenticated session or None."""
        pass
    
    @abstractmethod
    def send_payload(self, url: str, param: str, payload: str) -> str:
        """Send payload to target and return response."""
        pass
    
    def get_session(self) -> requests.Session:
        """Get authenticated session."""
        return self.session


class GenericWebApp(WebAppConfig):
    """Generic web application (no authentication)."""
    
    def authenticate(self) -> Optional[requests.Session]:
        """No authentication needed."""
        self.logger.info("Generic web app (no authentication required)")
        return self.session
    
    def send_payload(self, url: str, param: str, payload: str) -> str:
        """Send payload via GET request."""
        try:
            params = {param: payload}
            response = self.session.get(url, params=params, timeout=10)
            return response.text
        except Exception as e:
            self.logger.warning(f"Error sending payload: {e}")
            return ""
