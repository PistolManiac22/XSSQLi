"""
Mutillidae Web Application Configuration
Handles Mutillidae-specific requirements for parameter preservation and security levels
"""

from webapp_config import GenericWebApp
import logging
from typing import Dict, List
from urllib.parse import urlparse, parse_qs


class MutillidaeConfig(GenericWebApp):
    """Mutillidae-specific configuration."""

    def __init__(
        self,
        base_url: str = "http://127.0.0.1:9000",
        security_level: str = "0",
    ):
        super().__init__(base_url)
        self.security_level = security_level
        self.logger = logging.getLogger("Mutillidae")

        # Initialize session
        try:
            self.session.get(f"{self.base_url}/index.php", timeout=10)
        except Exception as e:
            self.logger.warning(f"Error initializing Mutillidae session: {e}")

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

        try:
            target_level = int(level)
        except ValueError:
            self.logger.warning(f"Invalid security level: {level}, using 0")
            target_level = 0

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
                self.session.get(toggle_url, allow_redirects=False, timeout=10)
                self.logger.info(
                    f"Toggled security level (click {i + 1}/{clicks_needed})"
                )
            except Exception as e:
                self.logger.warning(f"Error toggling security: {e}")
                break

        # Verify the level was set
        try:
            verify_response = self.session.get(
                f"{self.base_url}/index.php", timeout=10
            )
            if f"SL{level}" in verify_response.text or \
               f"Security Level: {level}" in verify_response.text:
                self.logger.info(f"[OK] Verified: Security Level is now {level}")
            else:
                self.logger.warning(
                    f"Could not verify Security Level {level}. Check application UI."
                )
        except Exception as e:
            self.logger.warning(f"Error verifying security level: {e}")

    def send_payload(self, url: str, param: str, payload: str) -> str:
        """
        Send payload while preserving existing URL parameters.

        Digunakan baik untuk XSS maupun SQLi pada Mutillidae, terutama
        pada endpoint: /index.php?page=user-info.php
        """
        try:
            parsed_url = urlparse(url)
            existing_params = parse_qs(parsed_url.query, keep_blank_values=True)

            # Preserve existing query parameters
            params: Dict[str, str] = {}
            for key, values in existing_params.items():
                if values:
                    params[key] = values[0]

            # Override/insert target parameter with payload
            params[param] = payload

            # --- AUTOMATIC PAGE FIXES ---
            page = params.get("page", "")

            # Fix for user-info.php (both XSS & SQLi)
            if "user-info.php" in url or "user-info.php" in page:
                params["user-info-php-submit-button"] = "View Account Details"
                # Pastikan ada password yang valid jika parameter utama bukan "password"
                if param != "password" and "password" not in params:
                    params["password"] = "XXX"  # Known working value in lab

            # Fix for add-to-your-blog.php
            elif "add-to-your-blog.php" in url or "add-to-your-blog.php" in page:
                params["add-to-your-blog-php-submit-button"] = "Save Blog Entry"
            # ----------------------------

            target_url = f"{self.base_url}{parsed_url.path}"
            self.logger.debug(f"[Mutillidae] Target URL: {target_url}")
            self.logger.debug(f"[Mutillidae] Params: {params}")

            # Mutillidae labs ini pakai GET untuk user-info.php
            response = self.session.get(target_url, params=params, timeout=10)
            return response.text

        except Exception as e:
            self.logger.warning(f"Error sending payload to Mutillidae: {e}")
            return ""

    # --- Mutillidae-specific rules for discovery ---

    def get_global_params(self) -> Dict[str, str]:
        """
        Global parameters including form submission and defaults.

        Dipakai ParameterDiscoverer dan juga send_payload bila relevan.
        """
        return {
            # Default working values untuk user-info.php
            "password": "test",
            "user-info-php-submit-button": "View Account Details",
        }

    def get_ignored_params(self) -> List[str]:
        """Ignore these fields during parameter discovery."""
        return [
            "page",
            "security-level",
            "security_level",
            "btn",
            "submit",
            "login",
            "uid",
            "user-info-php-submit-button",
        ]
