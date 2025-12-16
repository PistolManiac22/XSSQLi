"""
Web Application Behavior Analyzer
Detects how a target app processes input (filters, encodes, reflects)

CORRECTED VERSION with comprehensive behavior detection per paper Section 4.1
"""

import re
import urllib.parse
import base64
import logging
from typing import Dict, Tuple, Callable, Optional

logger = logging.getLogger('BehaviorAnalyzer')


class WebAppBehaviorAnalyzer:
    """Analyze how a web app processes and reflects user input.
    
    Implements behavior detection workflow:
    1. Test basic reflection capability
    2. Detect input filtering (angle brackets, quotes)
    3. Detect encoding schemes (HTML, URL, Base64)
    4. Test case sensitivity
    5. Compile filter profile for GA fitness function
    
    Reference:
        Liu et al. (2022), Section 4.1: Web app behavior analysis
    """

    # Standard test payloads for behavior detection
    TEST_MARKERS = {
        'basic': 'TESTMARKER123456',
        'angle_brackets': '<test>',
        'double_quote': 'test"quote',
        'single_quote': "test'quote",
        'script_tag': '<script>',
        'script_upper': '<SCRIPT>',
        'event_handler': 'onclick=',
        'url_encoded': '%3Ctest%3E',
        'base64': base64.b64encode(b'<test>').decode(),
    }

    def __init__(self, test_func: Callable, param_name: str):
        """Initialize behavior analyzer.
        
        Args:
            test_func: Function that takes payload and returns response HTML
            param_name: Parameter name being tested
        """
        self.test_func = test_func
        self.param_name = param_name
        self.behaviors: Dict = {}
        self.logger = logging.getLogger('BehaviorAnalyzer')
        self.test_count = 0
        self.success_count = 0

    def analyze(self) -> Dict:
        """Analyze web application behavior comprehensively.
        
        Per paper Section 4.1:
        Detect filters and encoding schemes to inform GA fitness function
        
        Returns:
            Dict with behavior flags for use by fitness calculator
        """
        self.logger.info("=" * 70)
        self.logger.info("Web Application Behavior Analysis Starting")
        self.logger.info("=" * 70)
        self.logger.info(f"Parameter: {self.param_name}")

        behaviors = {
            # ==================== BASIC REFLECTION ====================
            'reflects_input': self._test_reflection(),
            
            # ==================== FILTERING ====================
            'filters_angle_brackets': self._test_angle_brackets(),
            'filters_quotes': self._test_quotes(),
            'filters_single_quotes': self._test_single_quotes(),
            'filters_events': self._test_event_handlers(),
            
            # ==================== ENCODING ====================
            'html_encodes': self._test_html_encoding(),
            'url_decodes': self._test_url_encoding(),
            'preserves_base64': self._test_base64_encoding(),
            
            # ==================== CASE SENSITIVITY ====================
            'case_insensitive': self._test_case_sensitivity(),
            
            # ==================== ADVANCED ====================
            'strips_tags': self._test_tag_stripping(),
            'double_encodes': self._test_double_encoding(),
        }

        self.behaviors = behaviors
        self._report_behaviors(behaviors)

        return behaviors

    def _safe_test(self, payload: str, timeout: int = 5) -> Optional[str]:
        """Safely test a payload with error handling.
        
        Args:
            payload: Payload to test
            timeout: Request timeout in seconds
            
        Returns:
            Response text or None if error
        """
        try:
            self.test_count += 1
            response = self.test_func(payload)
            
            if response:
                self.success_count += 1
            
            return response
            
        except Exception as e:
            self.logger.debug(f"Error testing payload '{payload[:50]}': {e}")
            return None

    def _test_reflection(self) -> bool:
        """Test if app reflects input at all.
        
        Per paper: Basic requirement for XSS exploitation
        
        Returns:
            Bool: True if input is reflected in response
        """
        try:
            test_marker = self.TEST_MARKERS['basic']
            response = self._safe_test(test_marker)
            
            if response and test_marker in response:
                self.logger.info(f"[OK] Input reflection: ENABLED")
                return True
            else:
                self.logger.warning(f"[X] Input reflection: DISABLED")
                return False
                
        except Exception as e:
            self.logger.error(f"Error testing reflection: {e}")
            return False

    def _test_angle_brackets(self) -> Tuple[bool, str]:
        """Check if < and > are filtered or encoded.
        
        Critical for tag injection (Type 3 payloads)
        
        Returns:
            Tuple of (is_filtered, filter_type)
            filter_type: 'NOT_FILTERED', 'HTML_ENCODED', 'URL_ENCODED', 'REMOVED'
        """
        try:
            test_payload = self.TEST_MARKERS['angle_brackets']
            response = self._safe_test(test_payload)
            
            if not response:
                return (True, 'ERROR')

            # Check if literally reflected
            if test_payload in response:
                self.logger.info(f"[OK] Angle brackets: NOT_FILTERED")
                return (False, "NOT_FILTERED")
            
            # Check if HTML-encoded
            if "&lt;" in response or "&#60;" in response or "&#x3C;" in response:
                self.logger.info(f"[OK] Angle brackets: HTML_ENCODED")
                return (True, "HTML_ENCODED")
            
            # Check if URL-encoded
            if "%3C" in response or "%3c" in response:
                self.logger.info(f"[OK] Angle brackets: URL_ENCODED")
                return (True, "URL_ENCODED")
            
            # Otherwise removed or heavily mangled
            self.logger.info(f"[OK] Angle brackets: REMOVED")
            return (True, "REMOVED")
            
        except Exception as e:
            self.logger.warning(f"Error testing angle brackets: {e}")
            return (True, "ERROR")

    def _test_quotes(self) -> Tuple[bool, str]:
        """Check if double quotes are filtered or encoded.
        
        Critical for attribute escaping (Type 2 payloads)
        
        Returns:
            Tuple of (is_filtered, filter_type)
        """
        try:
            test_payload = self.TEST_MARKERS['double_quote']
            response = self._safe_test(test_payload)
            
            if not response:
                return (True, 'ERROR')

            # Check if literally reflected
            if test_payload in response:
                self.logger.info(f"[OK] Double quotes: NOT_FILTERED")
                return (False, "NOT_FILTERED")
            
            # Check if HTML-encoded
            if "&quot;" in response or "&#34;" in response or "&#x22;" in response:
                self.logger.info(f"[OK] Double quotes: HTML_ENCODED")
                return (True, "HTML_ENCODED")
            
            # Check if URL-encoded
            if "%22" in response:
                self.logger.info(f"[OK] Double quotes: URL_ENCODED")
                return (True, "URL_ENCODED")
            
            # Otherwise removed
            self.logger.info(f"[OK] Double quotes: REMOVED")
            return (True, "REMOVED")
            
        except Exception as e:
            self.logger.warning(f"Error testing double quotes: {e}")
            return (True, "ERROR")

    def _test_single_quotes(self) -> Tuple[bool, str]:
        """Check if single quotes are filtered or encoded.
        
        Returns:
            Tuple of (is_filtered, filter_type)
        """
        try:
            test_payload = self.TEST_MARKERS['single_quote']
            response = self._safe_test(test_payload)
            
            if not response:
                return (True, 'ERROR')

            # Check if literally reflected
            if test_payload in response:
                self.logger.info(f"[OK] Single quotes: NOT_FILTERED")
                return (False, "NOT_FILTERED")
            
            # Check if HTML-encoded
            if "&#39;" in response or "&#x27;" in response or "&apos;" in response:
                self.logger.info(f"[OK] Single quotes: HTML_ENCODED")
                return (True, "HTML_ENCODED")
            
            # Check if URL-encoded
            if "%27" in response:
                self.logger.info(f"[OK] Single quotes: URL_ENCODED")
                return (True, "URL_ENCODED")
            
            # Otherwise removed
            self.logger.info(f"[OK] Single quotes: REMOVED")
            return (True, "REMOVED")
            
        except Exception as e:
            self.logger.warning(f"Error testing single quotes: {e}")
            return (True, "ERROR")

    def _test_event_handlers(self) -> Tuple[bool, str]:
        """Check if event handlers are filtered.
        
        Critical for event-based XSS
        
        Returns:
            Tuple of (is_filtered, filter_type)
        """
        try:
            test_payload = self.TEST_MARKERS['event_handler']
            response = self._safe_test(test_payload)
            
            if not response:
                return (True, 'ERROR')

            # Check if literally reflected
            if test_payload in response:
                self.logger.info(f"[OK] Event handlers: NOT_FILTERED")
                return (False, "NOT_FILTERED")
            
            # Otherwise filtered
            self.logger.info(f"[OK] Event handlers: FILTERED")
            return (True, "FILTERED")
            
        except Exception as e:
            self.logger.warning(f"Error testing event handlers: {e}")
            return (True, "ERROR")

    def _test_html_encoding(self) -> bool:
        """Check if app HTML-encodes special characters.
        
        Indicates presence of output encoding
        
        Returns:
            Bool: True if HTML-encoding detected
        """
        try:
            test_payload = self.TEST_MARKERS['script_tag']
            response = self._safe_test(test_payload)
            
            if response and ("&lt;" in response or "&#60;" in response or "&#x3C;" in response):
                self.logger.info(f"[OK] HTML encoding: DETECTED")
                return True
            else:
                self.logger.info(f"[X] HTML encoding: NOT_DETECTED")
                return False
                
        except Exception as e:
            self.logger.warning(f"Error testing HTML encoding: {e}")
            return False

    def _test_url_encoding(self) -> bool:
        """Check if app URL-decodes input before output.
        
        Indicates double-encoding bypass potential
        
        Returns:
            Bool: True if URL-decoding detected
        """
        try:
            test_payload = self.TEST_MARKERS['url_encoded']
            response = self._safe_test(test_payload)
            
            # If URL-decoded, we should see the literal characters
            if response and ("<test>" in response or "test" in response):
                self.logger.info(f"[OK] URL decoding: DETECTED")
                return True
            else:
                self.logger.info(f"[X] URL decoding: NOT_DETECTED")
                return False
                
        except Exception as e:
            self.logger.warning(f"Error testing URL encoding: {e}")
            return False

    def _test_base64_encoding(self) -> bool:
        """Check if app preserves Base64 encoding.
        
        Indicates potential for base64 payload injection
        
        Returns:
            Bool: True if Base64 preserved
        """
        try:
            test_payload = self.TEST_MARKERS['base64']
            response = self._safe_test(test_payload)
            
            if response and test_payload in response:
                self.logger.info(f"[OK] Base64 preservation: DETECTED")
                return True
            else:
                self.logger.info(f"[X] Base64 preservation: NOT_DETECTED")
                return False
                
        except Exception as e:
            self.logger.warning(f"Error testing Base64: {e}")
            return False

    def _test_case_sensitivity(self) -> bool:
        """Check if app is case-insensitive for HTML tags.
        
        Indicates bypass potential for uppercase tag variants
        
        Returns:
            Bool: True if case-insensitive (tag accepted)
        """
        try:
            test_payload = self.TEST_MARKERS['script_upper']
            response = self._safe_test(test_payload)
            
            if response and test_payload in response:
                self.logger.info(f"[OK] Case sensitivity: INSENSITIVE (uppercase tags accepted)")
                return True
            else:
                self.logger.info(f"[OK] Case sensitivity: SENSITIVE (uppercase tags blocked)")
                return False
                
        except Exception as e:
            self.logger.warning(f"Error testing case sensitivity: {e}")
            return False

    def _test_tag_stripping(self) -> bool:
        """Check if app strips HTML tags.
        
        Indicates potential for nested tag bypass
        
        Returns:
            Bool: True if tag stripping detected
        """
        try:
            test_payload = "<<script>>alert(1)<</script>>"
            response = self._safe_test(test_payload)
            
            if response and ("<script>" in response or "script" in response.lower()):
                self.logger.info(f"[OK] Tag stripping: DETECTED (nested tags work)")
                return True
            else:
                self.logger.info(f"[X] Tag stripping: NOT_DETECTED")
                return False
                
        except Exception as e:
            self.logger.warning(f"Error testing tag stripping: {e}")
            return False

    def _test_double_encoding(self) -> bool:
        """Check if app double-encodes or allows double bypasses.
        
        Indicates potential for encoding chain exploits
        
        Returns:
            Bool: True if double-encoding bypass possible
        """
        try:
            # Double-encoded angle bracket
            test_payload = "%253Ctest%253E"  # %25 = %
            response = self._safe_test(test_payload)
            
            if response and ("<test>" in response or "%3Ctest%3E" in response):
                self.logger.info(f"[OK] Double encoding bypass: POSSIBLE")
                return True
            else:
                self.logger.info(f"[X] Double encoding bypass: NOT_POSSIBLE")
                return False
                
        except Exception as e:
            self.logger.warning(f"Error testing double encoding: {e}")
            return False

    def _report_behaviors(self, behaviors: Dict):
        """Log detected behaviors in structured format.
        
        Args:
            behaviors: Dictionary of detected behaviors
        """
        self.logger.info("=" * 70)
        self.logger.info("WEB APP BEHAVIOR SUMMARY")
        self.logger.info("=" * 70)

        # ==================== REFLECTION ====================
        self.logger.info("\nReflection:")
        self.logger.info(f"  Reflects input: {behaviors['reflects_input']}")

        # ==================== FILTERING ====================
        self.logger.info("\nInput Filtering:")
        ab_filtered, ab_type = behaviors['filters_angle_brackets']
        self.logger.info(f"  Angle brackets: {ab_type}")
        
        dq_filtered, dq_type = behaviors['filters_quotes']
        self.logger.info(f"  Double quotes: {dq_type}")
        
        sq_filtered, sq_type = behaviors['filters_single_quotes']
        self.logger.info(f"  Single quotes: {sq_type}")
        
        ev_filtered, ev_type = behaviors['filters_events']
        self.logger.info(f"  Event handlers: {ev_type}")

        # ==================== ENCODING ====================
        self.logger.info("\nOutput Encoding:")
        self.logger.info(f"  HTML encoding: {behaviors['html_encodes']}")
        self.logger.info(f"  URL decoding: {behaviors['url_decodes']}")
        self.logger.info(f"  Base64 preservation: {behaviors['preserves_base64']}")

        # ==================== ADVANCED ====================
        self.logger.info("\nBypass Techniques:")
        self.logger.info(f"  Case insensitivity: {behaviors['case_insensitive']}")
        self.logger.info(f"  Tag stripping: {behaviors['strips_tags']}")
        self.logger.info(f"  Double encoding: {behaviors['double_encodes']}")

        # ==================== SUMMARY ====================
        self.logger.info("\n" + "=" * 70)
        self.logger.info(f"Tests executed: {self.test_count}")
        self.logger.info(f"Tests successful: {self.success_count}")
        if self.test_count > 0:
            success_rate = (self.success_count / self.test_count) * 100
            self.logger.info(f"Success rate: {success_rate:.1f}%")
        self.logger.info("=" * 70 + "\n")

    def get_filter_profile(self) -> Dict:
        """Get a structured filter profile for GA fitness function.
        
        Converts raw behaviors into a profile for fitness calculation
        
        Returns:
            Dict with filter characteristics
        """
        if not self.behaviors:
            return {}

        return {
            'reflects': self.behaviors.get('reflects_input', False),
            'filters': {
                'angle_brackets': self.behaviors['filters_angle_brackets'][1],
                'quotes': self.behaviors['filters_quotes'][1],
                'single_quotes': self.behaviors['filters_single_quotes'][1],
                'events': self.behaviors['filters_events'][1],
            },
            'encoding': {
                'html': self.behaviors.get('html_encodes', False),
                'url': self.behaviors.get('url_decodes', False),
                'base64': self.behaviors.get('preserves_base64', False),
            },
            'bypass': {
                'case_insensitive': self.behaviors.get('case_insensitive', False),
                'tag_stripping': self.behaviors.get('strips_tags', False),
                'double_encoding': self.behaviors.get('double_encodes', False),
            }
        }

    def get_stats(self) -> Dict:
        """Get behavior analysis statistics.
        
        Returns:
            Dict with analysis metrics
        """
        return {
            'tests_executed': self.test_count,
            'tests_successful': self.success_count,
            'success_rate': (self.success_count / self.test_count * 100) if self.test_count > 0 else 0,
            'behaviors_detected': len(self.behaviors),
        }