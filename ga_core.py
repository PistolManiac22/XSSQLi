"""
GAXSS Genetic Algorithm Core Module
Implements DNA encoding and genetic operators as per Liu et al. (2022)
"""

import random
from typing import List, Tuple, Optional


class GAXSS_DNA:
    """DNA representation for GAXSS chromosomes."""

    def __init__(self, closing: List[int], main: List[int], mutations: Optional[List[int]] = None):
        self.closing = closing[:4]
        self.main = main[:6]
        self.mutations = mutations if mutations else []

    def to_list(self) -> List[int]:
        return self.closing + self.main + self.mutations

    @staticmethod
    def from_list(genes: List[int]) -> 'GAXSS_DNA':
        return GAXSS_DNA(
            closing=genes[:4],
            main=genes[4:10],
            mutations=genes[10:] if len(genes) > 10 else []
        )

    def copy(self) -> 'GAXSS_DNA':
        return GAXSS_DNA(
            closing=self.closing.copy(),
            main=self.main.copy(),
            mutations=self.mutations.copy()
        )

    def __repr__(self) -> str:
        return f"DNA(C={self.closing},M={self.main})"


class GAXSS_Mutations:
    """15 mutation methods from GAXSS paper Table 7."""

    @staticmethod
    def html_encoding(payload: str) -> str:
        return payload.replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;')

    @staticmethod
    def unicode_encoding(payload: str) -> str:
        return ''.join(f'\\u{ord(c):04x}' if ord(c) > 127 else c for c in payload)

    @staticmethod
    def url_encoding(payload: str) -> str:
        import urllib.parse
        return urllib.parse.quote(payload, safe="")

    @staticmethod
    def base64_encoding(payload: str) -> str:
        import base64
        return base64.b64encode(payload.encode()).decode()

    @staticmethod
    def event_replacement(payload: str) -> str:
        return payload.replace('onclick', 'onload').replace('onerror', 'onmouseover')

    @staticmethod
    def function_replacement(payload: str) -> str:
        return payload.replace('alert', 'eval').replace('console.log', 'fetch')

    @staticmethod
    def blank_replacement(payload: str) -> str:
        return payload.replace(' ', '\t')

    @staticmethod
    def bracket_replacement(payload: str) -> str:
        return payload.replace('(', '[').replace(')', ']')

    @staticmethod
    def position_swap(payload: str) -> str:
        parts = payload.split('"')
        if len(parts) >= 2:
            parts[0], parts[-1] = parts[-1], parts[0]
        return '"'.join(parts)

    @staticmethod
    def case_change(payload: str) -> str:
        return ''.join(c.upper() if random.random() > 0.5 else c for c in payload)

    @staticmethod
    def shape_transformation(payload: str) -> str:
        return payload.replace('alert(', 'confirm(')

    @staticmethod
    def add_spaces(payload: str) -> str:
        return payload.replace('(', '( ').replace(')', ' )')

    @staticmethod
    def insert_tag_recursive(payload: str) -> str:
        return f'<script>{payload}</script>'

    @staticmethod
    def add_comment_symbols(payload: str) -> str:
        return f'{payload}/**//'

    @staticmethod
    def add_random_chars(payload: str) -> str:
        if len(payload) > 0:
            pos = random.randint(0, len(payload))
            return payload[:pos] + random.choice('abcxyz') + payload[pos:]
        return payload

    @staticmethod
    def apply_mutation(payload: str, mutation_type: int) -> str:
        mutations = [
            GAXSS_Mutations.html_encoding,
            GAXSS_Mutations.unicode_encoding,
            GAXSS_Mutations.url_encoding,
            GAXSS_Mutations.base64_encoding,
            GAXSS_Mutations.event_replacement,
            GAXSS_Mutations.function_replacement,
            GAXSS_Mutations.blank_replacement,
            GAXSS_Mutations.bracket_replacement,
            GAXSS_Mutations.position_swap,
            GAXSS_Mutations.case_change,
            GAXSS_Mutations.shape_transformation,
            GAXSS_Mutations.add_spaces,
            GAXSS_Mutations.insert_tag_recursive,
            GAXSS_Mutations.add_comment_symbols,
            GAXSS_Mutations.add_random_chars,
        ]
        return mutations[mutation_type % 15](payload)


def crossover_uniform(parent1: GAXSS_DNA, parent2: GAXSS_DNA) -> Tuple[GAXSS_DNA, GAXSS_DNA]:
    """Uniform crossover operator."""
    child1 = GAXSS_DNA(
        closing=[parent1.closing[i] if random.random() > 0.5 else parent2.closing[i] for i in range(4)],
        main=[parent1.main[i] if random.random() > 0.5 else parent2.main[i] for i in range(6)],
        mutations=parent1.mutations.copy() if random.random() > 0.5 else parent2.mutations.copy()
    )

    child2 = GAXSS_DNA(
        closing=[parent2.closing[i] if random.random() > 0.5 else parent1.closing[i] for i in range(4)],
        main=[parent2.main[i] if random.random() > 0.5 else parent1.main[i] for i in range(6)],
        mutations=parent2.mutations.copy() if random.random() > 0.5 else parent1.mutations.copy()
    )

    return child1, child2


def mutate_gaxss(dna: GAXSS_DNA, mutation_rate: float = 0.5) -> GAXSS_DNA:
    """Apply random mutations to DNA."""
    mutated = dna.copy()

    if random.random() < mutation_rate:
        idx = random.randint(0, 5)
        mutated.main[idx] = random.randint(0, 20)

    if random.random() < mutation_rate:
        new_mutation = random.randint(0, 14)
        mutated.mutations.append(new_mutation)
        if len(mutated.mutations) > 5:
            mutated.mutations = mutated.mutations[-5:]

    return mutated
