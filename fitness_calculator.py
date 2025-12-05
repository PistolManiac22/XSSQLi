"""
GAXSS Fitness Calculator (Optimized v2)
Better execution detection for DVWA
"""

import re
from typing import Tuple


class GAXSS_FitnessCalculator:
    """Calculate fitness score for XSS payloads (optimized)."""

    @staticmethod
    def levenshtein_distance_fast(s1: str, s2: str, max_len: int = 500) -> int:
        """Fast Levenshtein distance on truncated strings."""
        if len(s1) > max_len:
            s1 = s1[:max_len]
        if len(s2) > max_len:
            pos = s2.find(s1[:50]) if len(s1) > 50 else 0
            if pos > 0:
                start = max(0, pos - 200)
                end = min(len(s2), pos + 300)
                s2 = s2[start:end]
            else:
                s2 = s2[:max_len]

        if len(s1) < len(s2):
            return GAXSS_FitnessCalculator.levenshtein_distance_fast(s2, s1, max_len)

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

    @staticmethod
    def calculate_ex(output: str) -> float:
        """Calculate execution score Ex(I,O)."""
        execution_indicators = [
            (r'<\w+[^>]*on\w+\s*=', 1.0),
            (r'<script[^>]*>', 0.9),
            (r'<img[^>]*onerror', 0.9),
            (r'<svg[^>]*on\w+', 0.9),
            (r'<body[^>]*on\w+', 0.9),
            (r'<iframe[^>]*on\w+', 0.9),
            (r'javascript:', 0.8),
            (r'alert\s*\(', 0.85),
            (r'console\.log\s*\(', 0.8),
            (r'fetch\s*\(', 0.8),
            (r'XMLHttpRequest', 0.7),
            (r'document\.location', 0.7),
        ]
        
        max_score = 0.0
        for pattern, score in execution_indicators:
            if re.search(pattern, output, re.IGNORECASE):
                max_score = max(max_score, score)
        
        return max_score

    @staticmethod
    def calculate_closed(input_payload: str, output: str) -> float:
        """Calculate closure score CLOSED(I,O)."""
        c1 = 0
        c2 = 0
        
        brackets = [
            ('<', '>'),
            ('{', '}'),
            ('(', ')'),
            ('[', ']'),
            ('"', '"'),
        ]

        for open_char, close_char in brackets:
            open_count = input_payload.count(open_char)
            close_count = output.count(close_char)
            c1 += open_count
            c2 += close_count

        if c1 == 0:
            return 1.0

        ratio = (c1 - c2) / (c1 + 0.001)
        return max(0.0, min(1.0, ratio))

    @staticmethod
    def calculate_dis(input_payload: str, output: str) -> float:
        """Calculate similarity/distance score Dis(I,O)."""
        if input_payload in output:
            return 1.0
        
        key_parts = ['<', '>', '=', 'on', 'alert', 'script']
        found_parts = sum(1 for part in key_parts if part in output.lower())
        if found_parts >= 4:
            return 0.8
        elif found_parts >= 2:
            return 0.6
        
        payload_parts = input_payload.split()
        if len(payload_parts) > 0:
            first_part = payload_parts[0][:20]
            if first_part in output:
                return 0.7
        
        encoded = (
            input_payload.replace('<', '&lt;')
                         .replace('>', '&gt;')
                         .replace('"', '&quot;')
        )
        if encoded in output:
            return 0.3
        
        distance = GAXSS_FitnessCalculator.levenshtein_distance_fast(
            input_payload, 
            output, 
            max_len=300
        )
        max_len = min(len(input_payload), len(output), 300)
        
        if max_len == 0:
            return 0.1
        
        normalized_distance = distance / max(max_len, 1)
        similarity = 1.0 / (1.0 + normalized_distance * 2)
        return max(0.1, similarity)

    @staticmethod
    def calculate_pu(output: str, input_payload: str = "", payload_type: str = 'xss') -> float:
        """Calculate penalty score Pu(I,O)."""
        penalty = 0.0

        if payload_type == 'xss':
            if input_payload and input_payload not in output:
                if len(input_payload) > 10:
                    if input_payload[:10] not in output:
                        penalty += 0.4
            
            if '&lt;' in output or '&gt;' in output or '&quot;' in output:
                penalty += 0.3
            
            if '<script' not in output.lower() and 'script' in input_payload.lower():
                penalty += 0.2
            
            if 'on' in input_payload.lower() and not re.search(r'on\w+=', output, re.IGNORECASE):
                penalty += 0.2

        return min(1.0, penalty)

    @staticmethod
    def calculate_fitness(
        input_payload: str,
        output: str,
        payload_type: str = 'xss'
    ) -> Tuple[float, float, float, float, float]:
        """Calculate complete fitness score."""
        ex = GAXSS_FitnessCalculator.calculate_ex(output)
        closed = GAXSS_FitnessCalculator.calculate_closed(input_payload, output)
        dis = GAXSS_FitnessCalculator.calculate_dis(input_payload, output)
        pu = GAXSS_FitnessCalculator.calculate_pu(output, input_payload, payload_type)

        fitness = ex * closed * dis * (1.0 - pu)

        return fitness, ex, closed, dis, pu
