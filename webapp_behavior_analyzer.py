"""
Web Application Behavior Analyzer
Detects how a target app processes input (filters, encodes, reflects)
"""

import re
import urllib.parse
import base64
import logging
from typing import Dict, Tuple

logger = logging.getLogger('BehaviorAnalyzer')


class WebAppBehaviorAnalyzer:
    """Analyze how a web app processes and reflects user input."""
    
    def __init__(self, test_func, param_name: str):
        """
        Args:
            test_func: Function that takes payload and returns response
            param_name: Parameter name to test
        """
        self.test_func = test_func
        self.param_name = param_name
        self.behaviors = {}
        self.logger = logging.getLogger('BehaviorAnalyzer')
    
    def analyze(self) -> Dict:
        """Analyze web app behavior."""
        behaviors = {
            'reflects_input': self._test_reflection(),
            'filters_angle_brackets': self._test_angle_brackets(),
            'filters_quotes': self._test_quotes(),
            'html_encodes': self._test_html_encoding(),
            'url_decodes': self._test_url_encoding(),
            'preserves_base64': self._test_base64_encoding(),
            'case_insensitive': self._test_case_sensitivity(),
        }
        
        self.behaviors = behaviors
        self._report_behaviors(behaviors)
        
        return behaviors
    
    def _test_reflection(self) -> bool:
        """Does the app reflect input at all?"""
        try:
            test_marker = "TESTMARKER123456"
            response = self.test_func(test_marker)
            return test_marker in response
        except:
            return False
    
    def _test_angle_brackets(self) -> Tuple[bool, str]:
        """Check if < and > are filtered or encoded."""
        try:
            test_payload = "<test>"
            response = self.test_func(test_payload)
            
            if test_payload in response:
                return (False, "NOT_FILTERED")
            elif "&lt;test&gt;" in response or "&#60;" in response:
                return (True, "HTML_ENCODED")
            elif "%3Ctest%3E" in response:
                return (True, "URL_ENCODED")
            else:
                return (True, "REMOVED")
        except:
            return (True, "ERROR")
    
    def _test_quotes(self) -> Tuple[bool, str]:
        """Check if quotes are filtered or encoded."""
        try:
            test_payload = 'test"quote'
            response = self.test_func(test_payload)
            
            if test_payload in response:
                return (False, "NOT_FILTERED")
            elif "&quot;" in response or "&#34;" in response:
                return (True, "HTML_ENCODED")
            elif "%22" in response:
                return (True, "URL_ENCODED")
            else:
                return (True, "REMOVED")
        except:
            return (True, "ERROR")
    
    def _test_html_encoding(self) -> bool:
        """Does the app HTML-encode special chars?"""
        try:
            test_payload = "<script>"
            response = self.test_func(test_payload)
            return "&lt;" in response or "&#60;" in response
        except:
            return False
    
    def _test_url_encoding(self) -> bool:
        """Does the app URL-decode input?"""
        try:
            test_payload = "%3Ctest%3E"
            response = self.test_func(test_payload)
            return "<test>" in response
        except:
            return False
    
    def _test_base64_encoding(self) -> bool:
        """Does the app preserve Base64?"""
        try:
            test_payload = base64.b64encode(b"<test>").decode()
            response = self.test_func(test_payload)
            return test_payload in response
        except:
            return False
    
    def _test_case_sensitivity(self) -> bool:
        """Is the app case-insensitive for HTML tags?"""
        try:
            test_payload = "<SCRIPT>alert(1)</SCRIPT>"
            response = self.test_func(test_payload)
            return test_payload in response
        except:
            return False
    
    def _report_behaviors(self, behaviors: Dict):
        """Log detected behaviors."""
        self.logger.info("\n" + "="*70)
        self.logger.info("WEB APP BEHAVIOR ANALYSIS")
        self.logger.info("="*70)
        
        for key, value in behaviors.items():
            self.logger.info(f"[{key}]: {value}")
        
        self.logger.info("="*70 + "\n")
