"""
Parameter Discovery Module
Automatically discovers and analyzes injectable parameters

CORRECTED VERSION:
- Proper error handling
- Context detection per paper Section 4.1
- Basic method detection (GET vs POST) per form
"""

from bs4 import BeautifulSoup
from urllib.parse import urlparse, parse_qs
import logging
from typing import TYPE_CHECKING, Dict, List, Optional, Set

if TYPE_CHECKING:
    from webapp_config import WebAppConfig

logger = logging.getLogger("ParameterDiscoverer")


class ParameterDiscoverer:
    """
    Discovers and tests parameters for XSS/SQLi injection.
    Now tracks the preferred HTTP method per parameter.
    """

    def __init__(self, webapp_config: "WebAppConfig"):
        self.config = webapp_config
        self.session = webapp_config.get_session()
        self.logger = logging.getLogger("ParameterDiscoverer")
        self.probed_params: Set[str] = set()
        self.probe_value = "XSS_PROBE_12345"

        # param -> ("GET" or "POST")
        self.param_methods: Dict[str, str] = {}

    # ==================== DISCOVERY ====================

    def discover_parameters(self, url: str) -> List[str]:
        """
        Discover potential parameters from URL and HTML forms.
        Also populates self.param_methods with preferred method.
        """
        parameters: List[str] = []

        try:
            response = self.session.get(url, timeout=10)
            response.raise_for_status()
            soup = BeautifulSoup(response.text, "html.parser")

            if soup.title:
                self.logger.info(f"Scanning Page: [{soup.title.string.strip()}]")
            else:
                self.logger.info(f"Scanning Page: {url}")

            ignored_params = self.config.get_ignored_params()
            self.logger.debug(f"Ignored parameters: {ignored_params}")

            # -------- FROM FORMS (GET / POST) --------
            form_params: List[str] = []

            for form in soup.find_all("form"):
                try:
                    method = form.get("method", "GET").upper()
                    if method not in ("GET", "POST"):
                        method = "GET"

                    for input_tag in form.find_all(["input", "textarea", "select"]):
                        param_name = input_tag.get("name")
                        if not param_name or not isinstance(param_name, str):
                            continue

                        param_name = param_name.strip()
                        if not param_name:
                            continue

                        if param_name in ignored_params:
                            self.logger.debug(f"Skipping ignored parameter: {param_name}")
                            continue

                        if param_name not in parameters:
                            parameters.append(param_name)
                            form_params.append(param_name)
                            self.param_methods[param_name] = method
                        else:
                            # If already known but no method stored yet, set it
                            self.param_methods.setdefault(param_name, method)

                except Exception as e:
                    self.logger.warning(f"Error parsing form element: {e}")
                    continue

            if form_params:
                self.logger.info(f"Found {len(form_params)} form parameters: {form_params}")

            # -------- FROM URL QUERY (GET) --------
            url_params: List[str] = []
            try:
                parsed_url = urlparse(url)

                if parsed_url.query:
                    query_params = parse_qs(parsed_url.query)

                    for param in query_params.keys():
                        if param in ignored_params:
                            self.logger.debug(f"Skipping ignored URL parameter: {param}")
                            continue

                        if param not in parameters:
                            parameters.append(param)
                            url_params.append(param)
                            # URL params are accessed via GET
                            self.param_methods.setdefault(param, "GET")

                if url_params:
                    self.logger.info(f"Found {len(url_params)} URL parameters: {url_params}")

            except Exception as e:
                self.logger.warning(f"Error parsing URL parameters: {e}")

            self.logger.info(f"Total parameters discovered: {len(parameters)}")
            return parameters

        except Exception as e:
            self.logger.error(f"[ERROR] Error discovering parameters: {e}")
            return []

    # ==================== METHOD-AWARE PROBING ====================

    def _send_probe_request(
        self,
        url: str,
        param: str,
        value: str,
        method: Optional[str] = None,
    ):
        """
        Send a single probe request, respecting detected method when possible.
        Falls back to GET if method is unknown.
        """
        try:
            effective_method = (method or self.param_methods.get(param, "GET")).upper()
            global_params = self.config.get_global_params().copy()

            if effective_method == "POST":
                data = global_params.copy()
                data[param] = value
                resp = self.session.post(url, data=data, timeout=10)
            else:
                params = global_params.copy()
                params[param] = value
                resp = self.session.get(url, params=params, timeout=10)

            resp.raise_for_status()
            return resp
        except Exception as e:
            self.logger.debug(
                f"Error sending probe request for '{param}' via {method}: {e}"
            )
            return None

    def is_parameter_reflected(
        self,
        url: str,
        param: str,
        probe_value: str = "XSS_PROBE_12345",
    ) -> bool:
        """
        Check if parameter value is reflected in response.
        Tries the method inferred during discovery (GET/POST).
        """
        # Remember we probed this parameter
        self.probed_params.add(param)

        # Preferred method (from forms/URL); default GET
        method = self.param_methods.get(param, "GET").upper()

        # First attempt with preferred method
        resp = self._send_probe_request(url, param, probe_value, method=method)

        # If preferred method fails, try the opposite as a fallback
        if resp is None:
            alt_method = "POST" if method == "GET" else "GET"
            resp = self._send_probe_request(url, param, probe_value, method=alt_method)

        if resp is None:
            self.logger.debug(f"Both methods failed for parameter '{param}'")
            return False

        is_reflected = probe_value in resp.text

        if is_reflected:
            self.logger.info(
                f"[OK] Parameter '{param}' is REFLECTED in response (method={method})"
            )
        else:
            self.logger.debug(
                f"[X] Parameter '{param}' is NOT reflected in response (method={method})"
            )

        return is_reflected

    # ==================== CONTEXT DETECTION ====================

    def detect_context_from_response(
        self,
        html: str,
        probe_value: str,
    ) -> str:
        """
        Detect injection context from HTML response.
        """
        try:
            soup = BeautifulSoup(html, "html.parser")

            # --- JS context ---
            for script in soup.find_all("script"):
                try:
                    if script.string and probe_value in script.string:
                        self.logger.info("Detected 'js' context: probe in <script> tag")
                        return "js"
                except Exception as e:
                    self.logger.debug(f"Error checking script context: {e}")
                    continue

            # --- Attribute context ---
            for tag in soup.find_all(True):
                try:
                    for attr_name, attr_val in tag.attrs.items():
                        if isinstance(attr_val, list):
                            if any(probe_value in str(v) for v in attr_val):
                                self.logger.info(
                                    f"Detected 'attribute' context: probe in {attr_name}={attr_val}"
                                )
                                return "attribute"
                        else:
                            if attr_val and probe_value in str(attr_val):
                                self.logger.info(
                                    f"Detected 'attribute' context: probe in {attr_name}=\"{attr_val}\""
                                )
                                return "attribute"
                except Exception as e:
                    self.logger.debug(
                        f"Error checking attribute context for tag {tag.name}: {e}"
                    )
                    continue

            # --- Text context ---
            try:
                text_content = soup.get_text()
                if probe_value in text_content:
                    self.logger.info("Detected 'text' context: probe in DOM text")
                    return "text"
            except Exception as e:
                self.logger.debug(f"Error checking text context: {e}")

            self.logger.warning("Could not determine context for probe value")
            return "unknown"

        except Exception as e:
            self.logger.error(f"Error detecting context: {e}")
            return "unknown"

    # ==================== MAIN WORKFLOW ====================

    def find_injectable_parameters(
        self,
        url: str,
        probe_value: Optional[str] = None,
    ) -> Dict[str, str]:
        """
        Find injectable parameters and their contexts.
        Returns {param_name: context_type}.
        """
        if probe_value is None:
            probe_value = self.probe_value

        self.logger.info("=" * 70)
        self.logger.info("Starting Parameter Discovery Workflow")
        self.logger.info("=" * 70)
        self.logger.info(f"Target URL: {url}")
        self.logger.info(f"Probe value: {probe_value}")

        parameters = self.discover_parameters(url)

        if not parameters:
            self.logger.error("[ERROR] No parameters discovered!")
            return {}

        self.logger.info(f"[OK] Discovered {len(parameters)} potential parameters")

        injectable_params: Dict[str, str] = {}
        tested_count = 0
        injectable_count = 0

        for param in parameters:
            try:
                self.logger.info(f"Testing parameter: {param}")
                tested_count += 1

                if not self.is_parameter_reflected(url, param, probe_value):
                    self.logger.debug(
                        f"Parameter '{param}' not reflected, skipping context detection"
                    )
                    continue

                # Fetch again for context detection, using preferred method
                method = self.param_methods.get(param, "GET").upper()
                resp = self._send_probe_request(url, param, probe_value, method=method)
                if resp is None:
                    self.logger.warning(
                        f"Error fetching response for context detection on '{param}'"
                    )
                    continue

                context = self.detect_context_from_response(resp.text, probe_value)

                injectable_params[param] = context
                injectable_count += 1

                self.logger.info(
                    f"[OK] Injectable: {param} (context: {context}, method={method})"
                )

            except Exception as e:
                self.logger.warning(f"Error testing parameter '{param}': {e}")
                continue

        self.logger.info("=" * 70)
        self.logger.info("Parameter Discovery Complete")
        self.logger.info("=" * 70)
        self.logger.info(f"Tested: {tested_count} parameters")
        self.logger.info(f"Found: {injectable_count} injectable parameter(s)")

        if injectable_params:
            self.logger.info("Injectable parameters:")
            for param, context in injectable_params.items():
                method = self.param_methods.get(param, "GET")
                self.logger.info(f"  • {param}: {context} (method={method})")
        else:
            self.logger.warning("[ERROR] No injectable parameters found.")

        return injectable_params

    def get_param_method(self, param: str) -> str:
        """Return preferred HTTP method for a parameter, default GET."""
        return self.param_methods.get(param, "GET").upper()

    def get_discovery_stats(self) -> Dict:
        """Get parameter discovery statistics."""
        return {
            "probed_parameters": len(self.probed_params),
            "probe_value": self.probe_value,
        }
