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
                 security_level: str = "low"):
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
        self.security_level_text = security_level.upper()
        
        self.logger.info("=" * 60)
        self.logger.info("[DEBUG] bWAPP Configuration Initialized")
        self.logger.info(f"[DEBUG] Security Level (arg): {security_level}")
        self.logger.info(f"[DEBUG] Security Level (text): {self.security_level_text}")
        self.logger.info(f"[DEBUG] Security Level (code): {self.security_level_code}")
        self.logger.info("=" * 60)


    def authenticate(self) -> Optional[requests.Session]:
        """Login to bWAPP."""
        try:
            login_url = f"{self.base_url}/login.php"

            self.logger.info("[DEBUG] Step 1: Getting initial session...")
            init_resp = self.session.get(login_url)
            self.logger.info(f"[DEBUG] Initial cookies: {self.session.cookies.get_dict()}")

            login_data = {
                "login": self.username,
                "password": self.password,
                "security_level": self.security_level_code,
                "form": "submit"
            }

            self.logger.info("[DEBUG] Step 2: Sending login request...")
            self.logger.info(f"[DEBUG] Login data: {login_data}")
            self.logger.info(f"[DEBUG] Authenticating as {self.username}...")

            r = self.session.post(login_url, data=login_data, allow_redirects=True)

            self.logger.info(f"[DEBUG] Login response status: {r.status_code}")
            self.logger.info(f"[DEBUG] Login response URL: {r.url}")
            self.logger.info(f"[DEBUG] Cookies after login: {self.session.cookies.get_dict()}")

            if "Logout" in r.text or "portal.php" in r.url or "Welcome" in r.text:
                self.logger.info("[OK] bWAPP logged in successfully")

                # Koreksi: jangan tambahkan cookie baru jika sudah ada.
                # Kalau mau paksa, update value saja.
                if "security_level" not in self.session.cookies:
                    self.logger.info(f"[DEBUG] Setting security_level cookie to: {self.security_level_code}")
                    self.session.cookies.set("security_level", self.security_level_code)
                else:
                    # Pastikan nilainya sesuai
                    current = self.session.cookies.get("security_level")
                    if current != self.security_level_code:
                        self.logger.info(
                            f"[DEBUG] Updating security_level cookie "
                            f"from {current} to {self.security_level_code}"
                        )
                        # Hapus semua cookie security_level dulu, lalu set ulang satu
                        jar = self.session.cookies
                        to_delete = [c for c in jar if c.name == "security_level"]
                        for c in to_delete:
                            jar.clear(domain=c.domain, path=c.path, name=c.name)
                        jar.set("security_level", self.security_level_code)

                self.logger.info(f"[DEBUG] Final cookies (dict): {self.session.cookies.get_dict()}")
                self.logger.info("=" * 60)
                return self.session

            else:
                self.logger.error("[ERROR] Login failed - no 'Logout' or 'Welcome' in response")
                self.logger.error(f"[DEBUG] Response snippet: {r.text[:200]}")
                return None

        except Exception as e:
            self.logger.error(f"[ERROR] Authentication Exception: {e}")
            import traceback
            self.logger.error(traceback.format_exc())
            return None


    def send_payload(self, url: str, param: str, payload: str) -> str:
        """Send payload via GET/POST with security level verification."""
        try:
            # Verify security_level cookie before sending
            current_level = self.session.cookies.get('security_level', 'NOT_SET')
            
            self.logger.debug(f"[DEBUG] Sending payload to: {url}")
            self.logger.debug(f"[DEBUG] Target param: {param}")
            self.logger.debug(f"[DEBUG] Payload (first 50 chars): {payload[:50]}...")
            self.logger.debug(f"[DEBUG] Current security_level cookie: {current_level}")
            
            if current_level != self.security_level_code:
                self.logger.warning(
                    f"[WARNING] Security level mismatch! "
                    f"Expected: {self.security_level_code}, Got: {current_level}"
                )
                # Force re-set
                self.session.cookies.set("security_level", self.security_level_code)
                self.logger.info(f"[DEBUG] Re-set security_level to: {self.security_level_code}")
            
            # Build request data
            data = self.get_global_params().copy()
            data[param] = payload
            
            # Send request
            if "post" in url.lower() or "stored" in url.lower():
                response = self.session.post(url, data=data, timeout=10)
            else:
                response = self.session.get(url, params=data, timeout=10)
            
            # Log response details for first few requests
            self.logger.debug(f"[DEBUG] Response status: {response.status_code}")
            self.logger.debug(f"[DEBUG] Response length: {len(response.text)}")
            
            # Check if response contains HTML entities (encoded) or raw tags
            if "&lt;" in response.text and "&gt;" in response.text:
                self.logger.debug("[DEBUG] Response contains HTML entities (likely encoded/safe)")
            elif "<" in response.text and ">" in response.text and param in url:
                self.logger.debug("[DEBUG] Response contains raw HTML tags (likely unencoded)")
            
            return response.text
            
        except Exception as e:
            self.logger.error(f"[ERROR] Send payload error: {e}")
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
