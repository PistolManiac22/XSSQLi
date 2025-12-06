"""
Mutillidae Web Application Configuration
Handles Mutillidae-specific requirements for parameter preservation and security levels
"""

from webapp_config import GenericWebApp
import requests
from typing import Optional, Dict, List
import logging
from urllib.parse import urlparse, parse_qs

class MutillidaeConfig(GenericWebApp):
    """Mutillidae-specific configuration."""
    
    def __init__(self, base_url: str = "http://127.0.0.1:9000",
                 security_level: str = "0"):
        super().__init__(base_url)
        self.security_level = security_level
        self.logger = logging.getLogger('Mutillidae')
        
        # Initialize session
        self.session.get(f"{self.base_url}/index.php")
        
        # Set security level on server side
        if security_level:
            self.set_security_level(security_level)

    def set_security_level(self, level: str):
        """
        Set the security level in the server session.
        Mutillidae toggles security level using: ?do=toggle-security
        
        Observed behavior:
        - Level 0: 0 clicks (default)
        - Level 1: 1 click
        - Level 5: 2 clicks
        """
        self.logger.info(f"Setting security level to: {level}")
        
        target_level = int(level)
        
        # Map level to number of clicks needed
        click_map = {
            0: 0,
            1: 1,
            5: 2,
        }
        
        clicks_needed = click_map.get(target_level, target_level)
        
        for i in range(clicks_needed):
            toggle_url = f"{self.base_url}/index.php?do=toggle-security"
            try:
                # Disable redirects to prevent loops
                self.session.get(toggle_url, allow_redirects=False)
                self.logger.info(f"Toggled security level (click {i+1}/{clicks_needed})")
            except Exception as e:
                self.logger.warning(f"Error toggling security: {e}")
                break
        
        # Verify the level was set
        verify_response = self.session.get(f"{self.base_url}/index.php")
        if f"SL{level}" in verify_response.text or f"Security Level: {level}" in verify_response.text:
            self.logger.info(f"✓ Verified: Security Level is now {level}")
        else:
            self.logger.warning(f"⚠ Could not verify Security Level {level}. Check logs.")

    def send_payload(self, url: str, param: str, payload: str) -> str:
        """Send payload while preserving existing URL parameters."""
        try:
            parsed_url = urlparse(url)
            existing_params = parse_qs(parsed_url.query, keep_blank_values=True)
            
            params = {}
            for key, values in existing_params.items():
                if values:
                    params[key] = values[0]
            
            params[param] = payload
            
            # --- AUTOMATIC PAGE FIXES ---
            page = params.get("page", "")
            
            # Fix for user-info.php
            if "user-info.php" in url or "user-info.php" in page:
                params["user-info-php-submit-button"] = "View Account Details"
                if param != "password" and "password" not in params:
                    params["password"] = "XXX" # Known working value
            
            # Fix for add-to-your-blog.php
            elif "add-to-your-blog.php" in url or "add-to-your-blog.php" in page:
                params["add-to-your-blog-php-submit-button"] = "Save Blog Entry"
            # ----------------------------
            
            target_url = f"{self.base_url}{parsed_url.path}"
            response = self.session.get(target_url, params=params, timeout=10)
            return response.text
            
        except Exception as e:
            self.logger.warning(f"Error sending payload to Mutillidae: {e}")
            return ""

    def get_global_params(self) -> Dict[str, str]:
        """Return global parameters required for ParameterDiscoverer."""
        return {
            "password": "test",
            "user-info-php-submit-button": "View Account Details"
        }

    def get_ignored_params(self) -> List[str]:
        return ["page", "security-level", "security_level", "btn", "submit", "login", "uid", "user-info-php-submit-button"]
