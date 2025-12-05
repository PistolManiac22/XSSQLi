"""
DVWA-Specific Web Application Configuration
Handles DVWA authentication and security levels
"""

from webapp_config import WebAppConfig
from bs4 import BeautifulSoup
import requests
from typing import Optional
import logging


class DVWAConfig(WebAppConfig):
    """DVWA-specific configuration with authentication and security levels."""
    
    def __init__(self, base_url: str = "http://localhost/dvwa", 
                 username: str = "admin", password: str = "password",
                 security_level: str = "low"):
        super().__init__(base_url, username, password)
        self.security_level = security_level
        self.logger = logging.getLogger('DVWA')
    
    def authenticate(self) -> Optional[requests.Session]:
        """Login to DVWA and set security level."""
        try:
            login_url = f"{self.base_url}/login.php"
            
            self.logger.info(f"Getting login page from {login_url}")
            r = self.session.get(login_url, timeout=10)
            soup = BeautifulSoup(r.text, 'html.parser')
            token_input = soup.find('input', {'name': 'user_token'})
            token = token_input['value'] if token_input else ""
            
            if not token:
                self.logger.warning("Could not find CSRF token, proceeding anyway")
            else:
                self.logger.info(f"Found CSRF token: {token[:20]}...")
            
            # Login
            login_data = {
                "username": self.username,
                "password": self.password,
                "Login": "Login",
                "user_token": token
            }
            
            self.logger.info(f"Attempting login with username: {self.username}")
            r = self.session.post(login_url, data=login_data, timeout=10, allow_redirects=True)
            
            if r.status_code != 200:
                self.logger.error(f"Login returned status {r.status_code}")
                return None
            
            # Set security level
            security_url = f"{self.base_url}/security.php"
            self.logger.info(f"Setting security level to {self.security_level}")
            r = self.session.get(security_url, timeout=10)
            soup = BeautifulSoup(r.text, 'html.parser')
            token_input = soup.find('input', {'name': 'user_token'})
            token = token_input['value'] if token_input else ""
            
            security_data = {
                "security": self.security_level,
                "seclev_submit": "Submit",
                "user_token": token
            }
            r = self.session.post(security_url, data=security_data, timeout=10)
            
            self.logger.info(f"[OK] DVWA logged in (security={self.security_level})")
            return self.session
        
        except Exception as e:
            self.logger.error(f"[ERROR] Login failed: {e}")
            return None
    
    def send_payload(self, url: str, param: str, payload: str) -> str:
        """Send payload via GET request (DVWA XSS Reflected uses GET)."""
        try:
            params = {param: payload}
            response = self.session.get(url, params=params, timeout=10)
            return response.text
        except Exception as e:
            self.logger.warning(f"Error sending payload: {e}")
            return ""
