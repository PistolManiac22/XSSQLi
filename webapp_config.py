"""
Web Application Configuration Interface
Abstracts authentication and payload delivery for different web apps
"""

from abc import ABC, abstractmethod
import requests
import logging
from typing import Optional, List, Dict

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
        try:
            params = {param: payload}
            # Merge with any global params defined (though Generic has none by default)
            params.update(self.get_global_params())
            response = self.session.get(url, params=params, timeout=10)
            return response.text
        except Exception as e:
            self.logger.warning(f"Error sending payload: {e}")
            return ""
