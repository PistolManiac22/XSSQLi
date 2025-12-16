"""
Parameter Discovery Module
Automatically discovers and analyzes injectable parameters

CORRECTED VERSION with proper error handling and context detection per paper Section 4.1
"""

from bs4 import BeautifulSoup
from urllib.parse import urlparse, parse_qs
import logging
from typing import TYPE_CHECKING, Dict, List, Optional, Set

if TYPE_CHECKING:
    from webapp_config import WebAppConfig


logger = logging.getLogger('ParameterDiscoverer')


class ParameterDiscoverer:
    """Discovers and tests parameters for XSS injection.
    
    Implements parameter discovery workflow:
    1. Extract parameters from URL and forms
    2. Test parameter reflection in response
    3. Detect injection context (script/attribute/text)
    4. Return injectable parameters with context info
    
    Reference:
        Liu et al. (2022), Section 4.1: Parameter discovery
    """

    def __init__(self, webapp_config: 'WebAppConfig'):
        """Initialize parameter discoverer.
        
        Args:
            webapp_config: Web application configuration object
        """
        self.config = webapp_config
        self.session = webapp_config.get_session()
        self.logger = logging.getLogger('ParameterDiscoverer')
        self.probed_params: Set[str] = set()  # Track tested parameters
        self.probe_value = "XSS_PROBE_12345"  # Standard probe marker

    def discover_parameters(self, url: str) -> List[str]:
        """Discover all potential injectable parameters from URL and HTML forms.
        
        Per paper Section 4.1:
        1. Extract parameters from URL query string
        2. Extract parameters from HTML forms (input, textarea)
        3. Filter out ignored/protected parameters
        
        Args:
            url: Target URL to scan
            
        Returns:
            List of parameter names found
        """
        parameters = []
        
        try:
            # Fetch page with timeout
            response = self.session.get(url, timeout=10)
            response.raise_for_status()
            
            # Parse HTML
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Log page title for context
            if soup.title:
                self.logger.info(f"Scanning Page: [{soup.title.string.strip()}]")
            else:
                self.logger.info(f"Scanning Page: {url}")

            # Get ignored parameters from config
            ignored_params = self.config.get_ignored_params()
            self.logger.debug(f"Ignored parameters: {ignored_params}")

            # ==================== EXTRACT FROM FORMS ====================
            
            form_params = []
            for form in soup.find_all('form'):
                try:
                    for input_tag in form.find_all(['input', 'textarea', 'select']):
                        param_name = input_tag.get('name')
                        
                        # Validate parameter name
                        if not param_name or not isinstance(param_name, str):
                            continue
                        
                        param_name = param_name.strip()
                        
                        # Skip ignored parameters
                        if param_name in ignored_params:
                            self.logger.debug(f"Skipping ignored parameter: {param_name}")
                            continue
                        
                        # Add if not duplicate
                        if param_name not in parameters:
                            parameters.append(param_name)
                            form_params.append(param_name)
                            
                except Exception as e:
                    self.logger.warning(f"Error parsing form element: {e}")
                    continue
            
            if form_params:
                self.logger.info(f"Found {len(form_params)} form parameters: {form_params}")

            # ==================== EXTRACT FROM URL ====================
            
            url_params = []
            try:
                parsed_url = urlparse(url)
                
                if parsed_url.query:
                    query_params = parse_qs(parsed_url.query)
                    
                    for param in query_params.keys():
                        # Skip ignored parameters
                        if param in ignored_params:
                            self.logger.debug(f"Skipping ignored URL parameter: {param}")
                            continue
                        
                        # Add if not duplicate
                        if param not in parameters:
                            parameters.append(param)
                            url_params.append(param)
                
                if url_params:
                    self.logger.info(f"Found {len(url_params)} URL parameters: {url_params}")
                    
            except Exception as e:
                self.logger.warning(f"Error parsing URL parameters: {e}")

            self.logger.info(f"Total parameters discovered: {len(parameters)}")
            return parameters

        except Exception as e:
            self.logger.error(f"[ERROR] Error discovering parameters: {e}")
            return []

    def is_parameter_reflected(self, 
                               url: str, 
                               param: str, 
                               probe_value: str = "XSS_PROBE_12345") -> bool:
        """Check if parameter value is reflected in response.
        
        Per paper Section 4.1:
        1. Inject probe value into target parameter
        2. Submit request with all global parameters
        3. Check if probe appears in response
        
        Args:
            url: Target URL
            param: Parameter name to test
            probe_value: Marker value to inject (default: "XSS_PROBE_12345")
            
        Returns:
            Bool: True if probe is reflected in response
        """
        try:
            # Get global parameters as baseline
            params = self.config.get_global_params().copy()
            
            # Inject probe value into target parameter
            params[param] = probe_value
            
            # Send request with timeout
            response = self.session.get(url, params=params, timeout=10)
            response.raise_for_status()
            
            # Check if probe value is in response
            is_reflected = probe_value in response.text
            
            if is_reflected:
                self.logger.info(f"[OK] Parameter '{param}' is REFLECTED in response")
            else:
                self.logger.debug(f"[X] Parameter '{param}' is NOT reflected in response")
            
            return is_reflected
            
        except Exception as e:
            self.logger.debug(f"Error testing parameter reflection for '{param}': {e}")
            return False

    def detect_context_from_response(self, 
                                     html: str, 
                                     probe_value: str) -> str:
        """Detect injection context from HTML response.
        
        Per paper Section 4.1:
        Determine where probe value appears:
        - 'js': Inside <script> tag
        - 'attribute': Inside HTML attribute
        - 'text': In text content (DOM context)
        - 'unknown': Cannot determine
        
        Args:
            html: HTML response containing probe
            probe_value: Marker value to locate
            
        Returns:
            String: Context type ('js', 'attribute', 'text', 'unknown')
        """
        try:
            soup = BeautifulSoup(html, 'html.parser')
            
            # ==================== CHECK SCRIPT CONTEXT ====================
            
            for script in soup.find_all('script'):
                try:
                    if script.string and probe_value in script.string:
                        self.logger.info(f"Detected 'js' context: probe in <script> tag")
                        return 'js'
                except Exception as e:
                    self.logger.debug(f"Error checking script context: {e}")
                    continue

            # ==================== CHECK ATTRIBUTE CONTEXT ====================
            
            for tag in soup.find_all(True):
                try:
                    for attr_name, attr_val in tag.attrs.items():
                        # Handle list-type attributes (e.g., class)
                        if isinstance(attr_val, list):
                            if any(probe_value in str(v) for v in attr_val):
                                self.logger.info(f"Detected 'attribute' context: probe in {attr_name}={attr_val}")
                                return 'attribute'
                        else:
                            # Handle string attributes
                            if attr_val and probe_value in str(attr_val):
                                self.logger.info(f"Detected 'attribute' context: probe in {attr_name}=\"{attr_val}\"")
                                return 'attribute'
                except Exception as e:
                    self.logger.debug(f"Error checking attribute context for tag {tag.name}: {e}")
                    continue

            # ==================== CHECK TEXT CONTEXT ====================
            
            try:
                text_content = soup.get_text()
                if probe_value in text_content:
                    self.logger.info(f"Detected 'text' context: probe in DOM text")
                    return 'text'
            except Exception as e:
                self.logger.debug(f"Error checking text context: {e}")

            # ==================== UNKNOWN CONTEXT ====================
            
            self.logger.warning(f"Could not determine context for probe value")
            return 'unknown'
            
        except Exception as e:
            self.logger.error(f"Error detecting context: {e}")
            return 'unknown'

    def find_injectable_parameters(self, 
                                   url: str, 
                                   probe_value: Optional[str] = None) -> Dict[str, str]:
        """Automatically find injectable parameters and their contexts.
        
        Per paper Section 4.1: Complete parameter discovery workflow
        1. Discover all potential parameters
        2. Test each for reflection
        3. Detect injection context
        4. Return injectable parameters with context
        
        Args:
            url: Target URL to test
            probe_value: Optional custom probe marker (default: "XSS_PROBE_12345")
            
        Returns:
            Dict mapping parameter names to their context types:
            {
                'param1': 'js',
                'param2': 'attribute',
                'param3': 'text'
            }
        """
        # Use custom probe or default
        if probe_value is None:
            probe_value = self.probe_value
        
        self.logger.info("=" * 70)
        self.logger.info("Starting Parameter Discovery Workflow")
        self.logger.info("=" * 70)
        self.logger.info(f"Target URL: {url}")
        self.logger.info(f"Probe value: {probe_value}")

        # STEP 1: Discover parameters
        parameters = self.discover_parameters(url)
        
        if not parameters:
            self.logger.error("[ERROR] No parameters discovered!")
            return {}

        self.logger.info(f"[OK] Discovered {len(parameters)} potential parameters")

        # STEP 2 & 3: Test each parameter for reflection and detect context
        injectable_params: Dict[str, str] = {}
        tested_count = 0
        injectable_count = 0

        for param in parameters:
            try:
                self.logger.info(f"Testing parameter: {param}")
                tested_count += 1

                # Test if parameter is reflected
                if not self.is_parameter_reflected(url, param, probe_value):
                    self.logger.debug(f"Parameter '{param}' not reflected, skipping context detection")
                    continue

                # Parameter is reflected - detect context
                try:
                    params = self.config.get_global_params().copy()
                    params[param] = probe_value
                    response = self.session.get(url, params=params, timeout=10)
                    response.raise_for_status()
                except Exception as e:
                    self.logger.warning(f"Error fetching response for context detection: {e}")
                    continue

                # Detect context
                context = self.detect_context_from_response(response.text, probe_value)
                
                # Store injectable parameter
                injectable_params[param] = context
                injectable_count += 1
                
                self.logger.info(f"[OK] Injectable: {param} (context: {context})")
                
            except Exception as e:
                self.logger.warning(f"Error testing parameter '{param}': {e}")
                continue

        # SUMMARY
        self.logger.info("=" * 70)
        self.logger.info("Parameter Discovery Complete")
        self.logger.info("=" * 70)
        self.logger.info(f"Tested: {tested_count} parameters")
        self.logger.info(f"Found: {injectable_count} injectable parameter(s)")
        
        if injectable_params:
            self.logger.info("Injectable parameters:")
            for param, context in injectable_params.items():
                self.logger.info(f"  • {param}: {context}")
        else:
            self.logger.warning("[ERROR] No injectable parameters found.")

        return injectable_params

    def get_discovery_stats(self) -> Dict:
        """Get parameter discovery statistics.
        
        Returns:
            Dict with discovery metrics
        """
        return {
            'probed_parameters': len(self.probed_params),
            'probe_value': self.probe_value,
        }