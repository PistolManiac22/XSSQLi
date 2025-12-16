"""
GAXSS Fitness Calculator (Generic)
Adapts to detected web app behavior

CORRECTED GA PHILOSOPHY:
- Let mutations run freely (no blocking) - diversity is GA's strength
- Fitness reflects BROWSER executability based on SERVER RESPONSE
- Natural selection will favor payloads that bypass filters

BUG FIX: Multi-layer URL encoding detection
- %3C = 1 layer (single encoding)
- %253C = 2 layers (double encoding - %25 is encoded %)
- %25253C = 3 layers (triple encoding)
"""

import re
from typing import Tuple
import urllib.parse
import base64
import logging

logger = logging.getLogger('FitnessCalculator')


class GAXSS_FitnessCalculator:
    """Calculate fitness score per GAXSS paper Section 4.2.2."""

    def __init__(self, behaviors: dict = None):
        """
        behaviors:
          - optional; can contain information from BehaviorAnalyzer
          - expected keys:
            - 'echo_marker': string marker used in normal requests
            - 'reflects_input': bool, True if app reflects input
        """
        self.behaviors = behaviors or {}
        self.baseline_response = ""
        self.baseline_length = 0

        # Echo marker & baseline tail after marker
        self.echo_marker = self.behaviors.get("echo_marker", "")
        self.baseline_tail_after_marker = ""

        logger.debug(
            f"FitnessCalculator init: echo_marker={self.echo_marker!r}, "
            f"reflects_input={self.behaviors.get('reflects_input')}"
        )

    # ==================== BASELINE HANDLING ====================

    def _extract_tail_after_marker(self, html: str) -> str:
        """Extract substring after the first occurrence of echo_marker."""
        if not self.echo_marker:
            return html

        idx = html.find(self.echo_marker)
        if idx == -1:
            return html

        return html[idx + len(self.echo_marker):]

    def set_echo_marker(self, marker: str):
        """Set the echo marker used by the web app."""
        self.echo_marker = marker or ""
        logger.debug(f"Echo marker set: {self.echo_marker!r}")

        if self.baseline_response:
            self.baseline_tail_after_marker = self._extract_tail_after_marker(
                self.baseline_response
            )

    def set_baseline(self, normal_response: str):
        """Set baseline response for comparison."""
        self.baseline_response = normal_response or ""
        self.baseline_length = len(self.baseline_response)
        
        self.baseline_tail_after_marker = self._extract_tail_after_marker(
            self.baseline_response
        )
        
        logger.debug(
            f"Baseline set: length={self.baseline_length}, "
            f"tail_length={len(self.baseline_tail_after_marker)}"
        )

    # ==================== ENCODING LAYER DETECTION (BUG FIX) ====================

    def _count_encoding_layers(self, text: str) -> int:
        """
        ⭐ BUG FIX: Count how many encoding layers exist.
        
        Examples:
        - "<body>": 0 layers (raw)
        - "%3Cbody%3E": 1 layer (single URL encoding)
        - "%253Cbody%253E": 2 layers (double encoding - %25 is encoded %)
        - "%25253Cbody%25253E": 3 layers (triple encoding)
        
        Args:
            text: Text to analyze
            
        Returns:
            Int: Number of detected encoding layers (0-4+)
        """
        layers = 0
        
        # Layer 1: Check for %3C or %3c (encoded <)
        if '%3C' in text or '%3c' in text:
            layers = 1
            
            # Layer 2: Check for %25 (encoded %) before 3C
            # %253C = encoded %3C (because %25 is encoded %)
            if '%253C' in text or '%253c' in text:
                layers = 2
                
                # Layer 3: Check for %2525 (double-encoded %)
                # %25253C = encoded %253C
                if '%25253C' in text or '%25253c' in text:
                    layers = 3
                    
                    # Layer 4+: Keep checking
                    if '%252525' in text:
                        layers = 4
        
        logger.debug(f"[ENCODING-LAYERS] Detected {layers} encoding layer(s)")
        return layers

    # ==================== ENCODING DETECTION ====================

    def _detect_how_payload_appears_in_response(self, payload: str, response: str) -> str:
        """Detect HOW payload appears in SERVER RESPONSE.
        
        CRITICAL: Distinguish between:
        - RAW: <svg onerror="...">  (EXECUTABLE)
        - PARTIAL: <svg%0aonerror="...">  (EXECUTABLE - whitespace bypass)
        - SINGLE_URL: %3Csvg%20onerror%3D  (NON-EXECUTABLE)
        - MULTI_URL: %253Csvg%2520onerror%253D  (NON-EXECUTABLE - NEW!)
        - HTML: &lt;svg onerror=  (NON-EXECUTABLE)
        - BASE64: PGltZyBvbmVycm9yPQ==  (NON-EXECUTABLE)
        
        Returns: 'raw', 'partial_url', 'single_url', 'multi_url', 'html_encoded', 'base64', or 'not_found'
        """
        # 1. Check if payload appears RAW (as-is)
        if payload in response:
            return 'raw'

        # 2. Check if server HTML-encoded it
        if '<' in payload or '>' in payload:
            if '&lt;' in response or '&gt;' in response:
                # Verify it's OUR payload that got encoded
                html_encoded = payload.replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;')
                sample = html_encoded[:50] if len(html_encoded) > 50 else html_encoded
                if sample in response:
                    logger.debug("[DETECT] Payload appears HTML-encoded in response")
                    return 'html_encoded'

        # 3. Check URL encoding status
        # Key distinction: FULL vs PARTIAL encoding, and SINGLE vs MULTI-layer
        if '%3C' in response or '%3c' in response or '%3E' in response or '%3e' in response:
            # Response contains URL-encoded angle brackets
            logger.debug("[DETECT] Response contains URL-encoded brackets")
            
            # ⭐ BUG FIX: Count encoding layers
            encoding_layers = self._count_encoding_layers(response)
            logger.debug(f"[DETECT] Encoding layers: {encoding_layers}")
            
            # Multiple encoding layers = non-executable
            if encoding_layers >= 2:
                logger.debug(f"[DETECT] => 'multi_url' (multi-layer encoding, non-executable)")
                return 'multi_url'
            
            # Single layer: check if response ALSO has raw angle brackets
            has_raw_brackets = '<' in response and '>' in response
            
            if has_raw_brackets:
                # Mixed: some encoded, some raw
                # Check if critical parts (opening tag) are raw or encoded
                
                # Look for patterns like: %3Ctagname or <tagname
                # Extract potential tag names from payload
                tag_match = re.search(r'<(\w+)', payload)
                if tag_match:
                    tag_name = tag_match.group(1)  # e.g., 'svg', 'img'
                    
                    # Check if opening tag is encoded in response
                    encoded_tag = f'%3C{tag_name}'  # e.g., %3Csvg
                    encoded_tag_lower = f'%3c{tag_name}'
                    
                    if encoded_tag in response or encoded_tag_lower in response.lower():
                        logger.debug(
                            f"[DETECT] Opening tag <{tag_name}> is URL-encoded "
                            f"as {encoded_tag} => SINGLE_URL encoding (non-executable)"
                        )
                        return 'single_url'
                    
                    # Check if opening tag is raw
                    raw_tag = f'<{tag_name}'
                    if raw_tag.lower() in response.lower():
                        logger.debug(
                            f"[DETECT] Opening tag <{tag_name}> is raw, "
                            "but has some URL encoding => PARTIAL_URL encoding (executable)"
                        )
                        return 'partial_url'
            else:
                # No raw brackets, only encoded ones => SINGLE_URL encoding
                logger.debug("[DETECT] Only URL-encoded brackets found => SINGLE_URL encoding (non-executable)")
                return 'single_url'

        # 4. Check if server kept it Base64-encoded
        try:
            base64_payload = base64.b64encode(payload.encode()).decode()
            if len(base64_payload) > 10 and base64_payload in response:
                logger.debug("[DETECT] Payload appears Base64-encoded in response")
                return 'base64'
        except:
            pass

        # 5. Not found in any recognizable form
        logger.debug("[DETECT] Payload not found in response")
        return 'not_found'

    # ==================== COMPONENT 1: EXECUTION SUCCESS ====================

    def _find_payload_window(self, payload: str, text: str, window_size: int = 300) -> str:
        """Find payload in text and return window around it."""
        # Try finding payload in various forms
        idx = text.find(payload)
        
        if idx == -1:
            # Try URL-encoded
            try:
                url_encoded = urllib.parse.quote(payload, safe='')
                idx = text.find(url_encoded)
            except:
                pass
        
        if idx == -1:
            # Try base64
            try:
                base64_encoded = base64.b64encode(payload.encode()).decode()
                idx = text.find(base64_encoded)
            except:
                pass
        
        if idx == -1:
            # Return full text as fallback
            return text
        
        # Extract window
        start = max(0, idx - window_size)
        end = min(len(text), idx + len(payload) + window_size)
        return text[start:end]

    def _extract_dangerous_keywords(self, payload: str) -> set:
        """Extract dangerous keywords that appear in payload."""
        keywords = [
            'alert', 'confirm', 'prompt',
            'onerror', 'onclick', 'onload', 'onmouseover', 'onmouseenter',
            'onkeydown', 'onkeyup', 'onfocus', 'onblur', 'onchange',
            'onwheel', 'ondrag', 'onpaste', 'ontouchstart',
            'script', 'img', 'iframe', 'embed', 'svg', 'body', 'input',
            'video', 'audio', 'link', 'object', 'details',
            'eval', 'fetch', 'XMLHttpRequest',
            'document.location', 'document.write', 'document.domain',
            'window.location', 'location.href',
            'console.log', 'throw ', 'Function',
        ]
        
        lower_payload = payload.lower()
        present = {kw for kw in keywords if kw in lower_payload}
        return present

    def _detect_code_execution(self, payload: str, response: str) -> bool:
        """Detect if XSS code was executed based on SERVER RESPONSE."""
        logger.debug("[DEBUG-EX] Start | payload_len=%d", len(payload))

        # STEP 1: Determine how server handled our payload
        appearance = self._detect_how_payload_appears_in_response(payload, response)
        logger.debug(f"[DEBUG-EX] Payload appears as: {appearance}")

        # STEP 2: Apply GA-friendly fitness rules
        # Only RAW and PARTIAL_URL are executable
        
        if appearance == 'html_encoded':
            logger.debug("[DEBUG-EX] Server HTML-encoded payload => Safe => Ex=0")
            return False
        
        if appearance == 'single_url':
            logger.debug("[DEBUG-EX] Server kept SINGLE URL-encoding => Non-executable => Ex=0")
            return False
        
        if appearance == 'multi_url':
            logger.debug("[DEBUG-EX] Server kept MULTI-layer URL-encoding => Non-executable => Ex=0")
            return False
        
        if appearance == 'base64':
            logger.debug("[DEBUG-EX] Server kept Base64 encoding => Non-executable => Ex=0")
            return False
        
        if appearance == 'not_found':
            logger.debug("[DEBUG-EX] Payload not found in response => Ex=0")
            return False

        # STEP 3: Payload appears RAW or PARTIAL-encoded (potentially executable)
        logger.debug(f"[DEBUG-EX] Payload potentially executable (appearance={appearance})")
        
        response_tail = self._extract_tail_after_marker(response)
        response_window = self._find_payload_window(payload, response_tail)

        # Decode URL-encoded whitespace for pattern matching
        response_decoded = response_window
        for enc, dec in [('%0a', '\n'), ('%0A', '\n'), ('%0d', '\r'), 
                        ('%0D', '\r'), ('%09', '\t'), ('%0c', '\f'), 
                        ('%0C', '\f'), ('%20', ' ')]:
            response_decoded = response_decoded.replace(enc, dec)

        # METHOD 1: Regex pattern matching
        dangerous_patterns = [
            r'<script[^>]*>',
            r'<\w+[^>]*[\s%]+on\w+\s*=',
            r'javascript:\s*\w+',
            r'<iframe[^>]*[\s%]+on\w+\s*=',
        ]

        baseline_window = self._find_payload_window(
            payload, 
            self.baseline_tail_after_marker or ""
        )
        
        baseline_matches = set()
        for pattern in dangerous_patterns:
            for m in re.finditer(pattern, baseline_window, re.IGNORECASE):
                baseline_matches.add(m.group().lower())

        response_matches = set()
        for pattern in dangerous_patterns:
            for m in re.finditer(pattern, response_decoded, re.IGNORECASE):
                response_matches.add(m.group().lower())

        new_patterns = response_matches - baseline_matches

        if new_patterns:
            payload_keywords = self._extract_dangerous_keywords(payload)
            
            for pattern in new_patterns:
                for kw in payload_keywords:
                    if kw in pattern.lower():
                        logger.debug(
                            f"[DEBUG-EX] METHOD 1: Dangerous pattern => Ex=2 | "
                            f"pattern={pattern[:50]}"
                        )
                        return True

        # METHOD 2: Keyword-based fallback
        dangerous_keywords = [
            '<script', '<img', '<iframe', '<svg', '<body', '<input', 
            '<video', '<audio', '<object', '<embed',
            'onerror=', 'onload=', 'onclick=', 'onmouseover=', 'onfocus=',
            'onkeydown=', 'onchange=', 'onwheel=', 'ondrag=',
            'javascript:', 'alert(', 'console.', 'document.location',
            'document.write', 'eval(', 'fetch(', 'Function(',
        ]

        response_lower = response_window.lower()
        baseline_lower = baseline_window.lower()

        new_keywords = []
        for kw in dangerous_keywords:
            resp_count = response_lower.count(kw)
            base_count = baseline_lower.count(kw)
            
            if resp_count > base_count:
                new_keywords.append(kw)

        if len(new_keywords) >= 2:
            payload_lower = payload.lower()
            matched = [kw for kw in new_keywords if kw.strip('<>=') in payload_lower]
            
            if matched:
                logger.debug(
                    f"[DEBUG-EX] METHOD 2: Keyword fallback => Ex=2 | "
                    f"keywords={matched}"
                )
                return True

        logger.debug("[DEBUG-EX] No execution detected => Ex=0")
        return False

    def calculate_ex(self, payload: str, response: str) -> float:
        """Ex(I,O) = 2 if execution indication, 0 otherwise."""
        if not self.behaviors.get('reflects_input', True):
            logger.debug("App doesn't reflect input => Ex=0")
            return 0.0

        if self._detect_code_execution(payload, response):
            return 2.0
        return 0.0

    # ==================== COMPONENT 2: CLOSURE COMPLETENESS ====================

    def _count_unclosed_symbols(self, text: str) -> Tuple[int, int]:
        """Count unclosed brackets and quotes."""
        open_angle = text.count('<')
        close_angle = text.count('>')
        unclosed_angle = abs(open_angle - close_angle)

        double_quotes = text.count('"') % 2
        single_quotes = text.count("'") % 2

        total_symbols = open_angle + close_angle + text.count('"') + text.count("'")
        unclosed = unclosed_angle + double_quotes + single_quotes

        return total_symbols, unclosed

    def calculate_closed(self, payload: str, response: str) -> float:
        """Calculate closure completeness score."""
        # Find payload context in response
        payload_idx = response.find(payload)
        
        if payload_idx == -1:
            # Try to find any form of payload
            appearance = self._detect_how_payload_appears_in_response(payload, response)
            if appearance == 'not_found':
                return 0.0
            context = response[:200]  # Use beginning as fallback
        else:
            context_start = max(0, payload_idx - 100)
            context_end = min(len(response), payload_idx + len(payload) + 100)
            context = response[context_start:context_end]

        total_symbols, unclosed = self._count_unclosed_symbols(context)
        
        if total_symbols == 0:
            return 1.0

        closure_score = (total_symbols - unclosed) / (total_symbols + 0.001)
        return max(0.0, min(1.0, closure_score))

    # ==================== COMPONENT 3: INPUT-OUTPUT SIMILARITY ====================

    def _levenshtein_distance(self, s1: str, s2: str) -> int:
        """Calculate Levenshtein distance between two strings."""
        if len(s1) < len(s2):
            return self._levenshtein_distance(s2, s1)

        if len(s2) == 0:
            return len(s1)

        previous_row = range(len(s2) + 1)

        for i, c1 in enumerate(s1):
            current_row = [i + 1]

            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))

            previous_row = current_row

        return previous_row[-1]

    def calculate_dis(self, payload: str, response: str) -> float:
        """Calculate input-output similarity."""
        payload_sample = payload[:100]
        response_sample = response[:100]

        distance = self._levenshtein_distance(payload_sample, response_sample)
        max_len = max(len(payload_sample), len(response_sample))

        if max_len == 0:
            return 1.0

        normalized_distance = float(distance) / float(max_len)
        similarity_score = 1.0 / (1.0 + normalized_distance)
        return similarity_score

    # ==================== COMPONENT 4: PENALTY FOR FILTERING ====================

    def calculate_pu(self, payload: str, response: str) -> float:
        """Calculate penalty for payload usability (filtering indicators)."""
        penalty = 0.0

        appearance = self._detect_how_payload_appears_in_response(payload, response)

        # Penalty based on how payload was handled
        if appearance == 'not_found':
            penalty += 0.5  # Payload completely stripped
        elif appearance == 'html_encoded':
            penalty += 0.3  # Safely encoded
        elif appearance == 'single_url':
            penalty += 0.3  # Full URL encoding
        elif appearance == 'multi_url':
            penalty += 0.4  # ⭐ Higher penalty for multi-layer encoding
        elif appearance == 'base64':
            penalty += 0.2  # Base64 encoded

        # Check for keyword stripping
        dangerous_keywords = [
            'alert', 'script', 'onerror', 'onclick', 'onload',
            'eval', 'fetch', 'XMLHttpRequest', 'location', 'href'
        ]

        stripped_count = 0
        for kw in dangerous_keywords:
            if kw in payload.lower() and kw not in response.lower():
                stripped_count += 1

        if stripped_count > 0:
            keyword_penalty = 0.2 * (stripped_count / len(dangerous_keywords))
            penalty += min(0.3, keyword_penalty)

        # Check for unusual response length change
        if self.baseline_length > 0:
            length_change = abs(len(response) - self.baseline_length) / float(self.baseline_length)
            if length_change > 0.5:
                penalty += 0.1

        return min(1.0, penalty)

    # ==================== COMPLETE FITNESS CALCULATION ====================

    def calculate_fitness(
        self,
        input_payload: str,
        output: str,
        payload_type: str = 'xss'
    ) -> Tuple[float, float, float, float, float]:
        """Calculate complete fitness score."""
        try:
            ex = self.calculate_ex(input_payload, output)
            closed = self.calculate_closed(input_payload, output)
            dis = self.calculate_dis(input_payload, output)
            pu = self.calculate_pu(input_payload, output)

            # Weights per paper
            w1, w2, w3, w4 = 2.0, 1.0, 0.5, 1.0

            fitness = (w1 * (ex / 2.0) +
                       w2 * closed +
                       w3 * dis -
                       w4 * pu)

            fitness = max(0.0, min(2.0, fitness))

            logger.debug(
                f"Fitness: ex={ex:.2f}, closed={closed:.2f}, "
                f"dis={dis:.2f}, pu={pu:.2f} => fitness={fitness:.2f}"
            )

            return fitness, ex, closed, dis, pu

        except Exception as e:
            logger.error(f"Error calculating fitness: {e}", exc_info=True)
            return 0.0, 0.0, 0.0, 0.0, 1.0

    # ==================== LEGACY HELPER METHODS ====================

    @staticmethod
    def payload_is_xss_vector(payload: str) -> bool:
        """Check if payload looks like XSS attempt."""
        has_tag = re.search(r'<\w+', payload, re.IGNORECASE)
        has_event = re.search(r'on\w+\s*=', payload, re.IGNORECASE)
        has_script = re.search(r'<script', payload, re.IGNORECASE)
        has_javascript = re.search(r'javascript:', payload, re.IGNORECASE)

        return bool((has_tag or has_script) and
                    (has_event or has_script or has_javascript))
