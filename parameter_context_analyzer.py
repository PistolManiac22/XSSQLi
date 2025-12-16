"""
Parameter Injection Context Analyzer

Detects where and how a parameter is reflected in web application response.
Implements taint-tracking untuk menentukan injection context (script/attribute/outside).

Reference: GAXSS paper Section 3.1 - Injection Context Detection
"""

import re
import logging
from enum import Enum
from typing import Optional

logger = logging.getLogger('ParameterContextAnalyzer')


class InjectionContext(Enum):
    """Injection context types per GAXSS paper Section 3.1"""
    BETWEEN_SCRIPT = 0      # Inside <script>...</script> tags
    INSIDE_HTML_TAG = 1     # Inside HTML tag attribute: <tag attr="VALUE">
    OUTSIDE_TAG = 2         # Outside any tag: plain text context


class ParameterContextAnalyzer:
    """Analyze where parameter is reflected in HTML response.
    
    Uses taint-tracking approach:
    1. Send unique marker as parameter value
    2. Examine HTML response for marker position
    3. Determine context based on surrounding HTML structure
    
    Reference:
        GAXSS paper Section 3.1: Injection Context Detection
    """
    
    def __init__(self, test_func, param_name: str = "search"):
        """Initialize context analyzer.
        
        Args:
            test_func: Function that takes payload and returns HTML response
            param_name: Name of parameter to analyze (default: "search")
        """
        self.test_func = test_func
        self.param_name = param_name
        self.marker = "GAXSS_MARKER_" + "".join([str(i) for i in range(16)])
        self.detected_context = None
        logger.info(f"ParameterContextAnalyzer initialized for param '{param_name}'")
    
    def detect_context(self) -> InjectionContext:
        """Detect injection context for the parameter.
        
        Returns:
            InjectionContext enum: BETWEEN_SCRIPT, INSIDE_HTML_TAG, or OUTSIDE_TAG
        """
        try:
            # Send marker as parameter value
            response = self.test_func(self.marker)
            
            # Find marker position in response
            marker_pos = response.find(self.marker)
            if marker_pos == -1:
                logger.warning(f"Marker not found in response; assuming OUTSIDE_TAG")
                self.detected_context = InjectionContext.OUTSIDE_TAG
                return InjectionContext.OUTSIDE_TAG
            
            # Extract context window around marker (500 chars before/after)
            window_start = max(0, marker_pos - 500)
            window_end = min(len(response), marker_pos + len(self.marker) + 500)
            window = response[window_start:window_end]
            
            logger.debug(f"Context window: ...{window[:100]}...{window[-100:]}...")
            
            # --- Check for BETWEEN_SCRIPT context ---
            # Count <script> and </script> tags before marker
            before_marker = response[:marker_pos]
            script_open_count = len(re.findall(r'<script[^>]*>', before_marker, re.IGNORECASE))
            script_close_count = len(re.findall(r'</script>', before_marker, re.IGNORECASE))
            
            # If more opens than closes, we're inside <script>
            if script_open_count > script_close_count:
                logger.info(f"✓ Detected BETWEEN_SCRIPT context (script tags: open={script_open_count}, close={script_close_count})")
                self.detected_context = InjectionContext.BETWEEN_SCRIPT
                return InjectionContext.BETWEEN_SCRIPT
            
            # --- Check for INSIDE_HTML_TAG context ---
            # Look for pattern: attr="...MARKER..."> or attr='...MARKER...'> or attr=...MARKER... space/</
            
            before_marker_context = response[max(0, marker_pos-200):marker_pos]
            after_marker_context = response[marker_pos + len(self.marker):min(len(response), marker_pos + len(self.marker) + 200)]
            
            # Pattern 1: Inside double quotes
            if re.search(r'[a-z_-]+\s*=\s*"[^"]*$', before_marker_context, re.IGNORECASE) and \
               re.search(r'^[^"]*"', after_marker_context):
                logger.info(f"✓ Detected INSIDE_HTML_TAG context (inside double quotes)")
                self.detected_context = InjectionContext.INSIDE_HTML_TAG
                return InjectionContext.INSIDE_HTML_TAG
            
            # Pattern 2: Inside single quotes
            if re.search(r"[a-z_-]+\s*=\s*'[^']*$", before_marker_context, re.IGNORECASE) and \
               re.search(r"^[^']*'", after_marker_context):
                logger.info(f"✓ Detected INSIDE_HTML_TAG context (inside single quotes)")
                self.detected_context = InjectionContext.INSIDE_HTML_TAG
                return InjectionContext.INSIDE_HTML_TAG
            
            # Pattern 3: Inside unquoted attribute (space or > or / after marker)
            if re.search(r'[a-z_-]+\s*=\s*[^\s>"\']*$', before_marker_context, re.IGNORECASE) and \
               re.search(r'^[^\s>"\']*[\s>/]', after_marker_context):
                logger.info(f"✓ Detected INSIDE_HTML_TAG context (inside unquoted attribute)")
                self.detected_context = InjectionContext.INSIDE_HTML_TAG
                return InjectionContext.INSIDE_HTML_TAG
            
            # --- Default: OUTSIDE_TAG ---
            logger.info(f"✓ Detected OUTSIDE_TAG context (not in script or attribute)")
            self.detected_context = InjectionContext.OUTSIDE_TAG
            return InjectionContext.OUTSIDE_TAG
            
        except Exception as e:
            logger.error(f"Error detecting context: {e}")
            logger.warning(f"Defaulting to OUTSIDE_TAG")
            self.detected_context = InjectionContext.OUTSIDE_TAG
            return InjectionContext.OUTSIDE_TAG
    
    def get_context_name(self) -> str:
        """Get human-readable context name."""
        if self.detected_context == InjectionContext.BETWEEN_SCRIPT:
            return "Between Script Tags (JavaScript context)"
        elif self.detected_context == InjectionContext.INSIDE_HTML_TAG:
            return "Inside HTML Tag Attribute"
        else:
            return "Outside Tags (Plain Text)"