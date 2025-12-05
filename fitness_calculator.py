"""
GAXSS Fitness Calculator (Generic)
Adapts to detected web app behavior
"""

import re
from typing import Tuple
import urllib.parse
import base64
import logging

logger = logging.getLogger('FitnessCalculator')


class GAXSS_FitnessCalculator:
    """Calculate fitness score - web app agnostic."""

    def __init__(self, behaviors: dict = None):
        """
        Args:
            behaviors: Dict of detected app behaviors from BehaviorAnalyzer
        """
        self.behaviors = behaviors or {}

    @staticmethod
    def payload_is_xss_vector(payload: str) -> bool:
        """Check if payload is a valid XSS vector (has tags and events)."""
        has_tag = re.search(r'<\w+', payload, re.IGNORECASE)
        has_event = re.search(r'on\w+\s*=', payload, re.IGNORECASE)
        has_script = re.search(r'<script', payload, re.IGNORECASE)
        
        return bool(has_tag or has_script) and bool(has_event or has_script)

    def detect_encoding(self, payload: str, response: str) -> str:
        """Detect how payload appears in response."""
        
        # [1] Plain
        if payload in response:
            return 'plain'
        
        # [2] URL encoded
        try:
            url_encoded = urllib.parse.quote(payload, safe='')
            if url_encoded in response:
                return 'url_encoded'
        except:
            pass
        
        # [3] HTML encoded
        html_encoded = (
            payload.replace('<', '&lt;')
                   .replace('>', '&gt;')
                   .replace('"', '&quot;')
                   .replace("'", '&#x27;')
        )
        if html_encoded in response:
            return 'html_encoded'
        
        # [4] Base64
        try:
            base64_encoded = base64.b64encode(payload.encode()).decode()
            if base64_encoded in response:
                return 'base64'
        except:
            pass
        
        # [5] Not found
        return 'not_found'

    def calculate_ex(self, output: str, input_payload: str = "") -> float:
        """Calculate execution score."""
        encoding = self.detect_encoding(input_payload, output)
        
        # Only executable if plain or URL encoded (app decodes it)
        if encoding not in ['plain', 'url_encoded']:
            return 0.0
        
        # Must be valid XSS vector
        if not self.payload_is_xss_vector(input_payload):
            return 0.0
        
        # Check for execution indicators in response
        indicators = [
            r'<\w+[^>]*on\w+\s*=',
            r'<script[^>]*>',
            r'javascript:',
            r'alert\s*\(',
            r'fetch\s*\(',
            r'XMLHttpRequest',
            r'document\.write',
            r'document\.location',
        ]
        
        found = sum(1 for pattern in indicators if re.search(pattern, output, re.IGNORECASE))
        
        if found >= 2:
            return 1.0
        elif found >= 1:
            return 0.7
        else:
            return 0.3

    def calculate_closed(self, input_payload: str, output: str) -> float:
        """Calculate closure score."""
        encoding = self.detect_encoding(input_payload, output)
        
        if encoding not in ['plain', 'url_encoded']:
            return 0.0
        
        if not self.payload_is_xss_vector(input_payload):
            return 0.0
        
        # Count brackets
        open_br = input_payload.count('<')
        close_br = input_payload.count('>')
        
        if open_br == 0:
            return 1.0
        
        diff = abs(open_br - close_br)
        return max(0.0, 1.0 - (diff * 0.5))

    def calculate_dis(self, input_payload: str, output: str) -> float:
        """Calculate distance/similarity score."""
        encoding = self.detect_encoding(input_payload, output)
        
        score_map = {
            'plain': 1.0,
            'url_encoded': 0.9,
            'html_encoded': 0.1,
            'base64': 0.0,
            'not_found': 0.0,
        }
        
        return score_map.get(encoding, 0.0)

    def calculate_pu(self, output: str, input_payload: str = "") -> float:
        """Calculate penalty score."""
        encoding = self.detect_encoding(input_payload, output)
        
        penalty_map = {
            'plain': 0.0,
            'url_encoded': 0.1,
            'html_encoded': 0.9,
            'base64': 1.0,
            'not_found': 1.0,
        }
        
        return penalty_map.get(encoding, 1.0)

    def calculate_fitness(
        self,
        input_payload: str,
        output: str,
        payload_type: str = 'xss'
    ) -> Tuple[float, float, float, float, float]:
        """Calculate complete fitness score."""
        ex = self.calculate_ex(output, input_payload)
        closed = self.calculate_closed(input_payload, output)
        dis = self.calculate_dis(input_payload, output)
        pu = self.calculate_pu(output, input_payload)

        fitness = ex * closed * dis * (1.0 - pu)

        return fitness, ex, closed, dis, pu
