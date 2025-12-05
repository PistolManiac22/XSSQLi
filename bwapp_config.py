"""
bWAPP Web Application Configuration
"""

from webapp_config import WebAppConfig
import requests
from typing import Optional, Dict, List
import logging

class BWAPPConfig(WebAppConfig):
    """bWAPP-specific configuration."""
    
    def __init__(self, base_url: str = "http://localhost:8082",
                 username: str = "bee", password: str = "bug",
                 vulnerability: str = "xss_reflected",
                 security_level: str = "low"):  # Added security_level param
        super().__init__(base_url, username, password)
        self.logger = logging.getLogger('bWAPP')
        self.vulnerability = vulnerability
        
        # Map text levels to bWAPP numeric values
        level_map = {
            "low": "0",
            "medium": "1",
            "high": "2",
            "impossible": "3"
        }
        self.security_level_code = level_map.get(security_level.lower(), "0")
        self.logger.info(f"Security Level set to: {security_level} (Code: {self.security_level_code})")

    def authenticate(self) -> Optional[requests.Session]:
        """Login to bWAPP."""
        try:
            login_url = f"{self.base_url}/login.php"
            
            # Init Session
            self.session.get(login_url)
            
            # Login with correct security level
            login_data = {
                "login": self.username,
                "password": self.password,
                "security_level": self.security_level_code, # Use the mapped code
                "form": "submit"
            }
            
            self.logger.info(f"Authenticating as {self.username}...")
            r = self.session.post(login_url, data=login_data, allow_redirects=True)
            
            if "Logout" in r.text or "portal.php" in r.url or "Welcome" in r.text:
                self.logger.info("[OK] bWAPP logged in successfully")
                # Force cookie just in case
                self.session.cookies.set("security_level", self.security_level_code)
                return self.session
            else:
                self.logger.error("Login failed.")
                return None
        except Exception as e:
            self.logger.error(f"Authentication Error: {e}")
            return None

    def send_payload(self, url: str, param: str, payload: str) -> str:
        """Send payload via GET/POST."""
        try:
            # Start with globals
            data = self.get_global_params().copy()
            # Overwrite target param
            data[param] = payload
            
            if "post" in url.lower() or "stored" in url.lower():
                response = self.session.post(url, data=data, timeout=10)
            else:
                response = self.session.get(url, params=data, timeout=10)
            return response.text
        except Exception as e:
            return ""

    # --- bWAPP SPECIFIC RULES ---

    def get_global_params(self) -> Dict[str, str]:
        """Global parameters including form submission and defaults."""
        return {
            "form": "submit",
            "firstname": "test",
            "lastname": "test"
        }

    def get_ignored_params(self) -> List[str]:
        """Ignore these fields during discovery."""
        return ["form", "security_level", "btn", "login", "password", "bug"]
