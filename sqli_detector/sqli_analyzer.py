"""
SQLi Analyzer - FIXED VERSION (OPTIMIZED)

Fixes:
1. Updated weights - response_diff dari 0.25 → 0.35 (PRIMARY)
2. Improved thresholds dalam _detect_response_difference()
3. Better error detection
4. More sensitive scoring untuk GA evolution
"""

import re
from typing import Dict


class SQLiAnalyzer:
    """
    Analyze SQLi responses dan calculate fitness score
    FIXED VERSION - Lebih akurat & sensitif
    """

    def __init__(self, baseline_response: str = ""):
        """
        Initialize analyzer dengan baseline response

        Args:
            baseline_response: Response dari normal request (no injection)
        """
        self.baseline_response = baseline_response or ""
        self.baseline_size = len(self.baseline_response) if self.baseline_response else 1

        # SQL error patterns - expanded & optimized
        self.sql_error_patterns = [
            r"SQL syntax",
            r"XPATH syntax",
            r"Duplicate entry",
            r"Unknown column",
            r"invalid input syntax",
            r"You have an error in your SQL",
            r"mysql_fetch",
            r"mysqli_result",
            r"Warning.*mysql",
            r"Prepared statement",
            r"SQLSTATE",
            r"ORA-\d+",
            r"PostgreSQL.*error",
            r"column count doesn't match",
            r"Subquery returned",
            r"Syntax error",
            r"error in your SQL syntax",
            r"mysql_num_fields",
            r"division by zero",
        ]

        # Data extraction keywords - optimized
        self.data_keywords = [
            r"admin",
            r"root",
            r"password",
            r"user",
            r"username",
            r"email",
            r"version",
            r"database",
            r"mysql",
            r"information_schema",
        ]

    def calculate_fitness(self, response: str, payload: str) -> float:
        """
        Calculate fitness score (0.0 - 1.0)

        IMPROVED SCORING:
        - Response difference: 35% weight (PRIMARY)
        - Error detection: 30% weight
        - Data extraction: 20% weight
        - Payload analysis: 15% weight

        Args:
            response: Response dari server
            payload: Payload yang dikirim

        Returns:
            Fitness score (0.0 - 1.0)
        """
        if response is None or len(response) == 0:
            return 0.0

        fitness = 0.0

        weights = {
            "error_detection": 0.30,
            "response_diff": 0.35,
            "data_extraction": 0.20,
            "payload_analysis": 0.15,
        }

        # Score 1: Error Detection (30%)
        error_score = self._detect_sql_error(response)
        fitness += error_score * weights["error_detection"]

        # Score 2: Response Difference (35%) - PRIMARY INDICATOR
        diff_score = self._detect_response_difference(response)
        fitness += diff_score * weights["response_diff"]

        # Score 3: Data Extraction (20%)
        data_score = self._detect_extracted_data(response)
        fitness += data_score * weights["data_extraction"]

        # Score 4: Payload Type Analysis (15%)
        payload_score = self._analyze_payload(response, payload)
        fitness += payload_score * weights["payload_analysis"]

        return min(max(fitness, 0.0), 1.0)

    def _detect_sql_error(self, response: str) -> float:
        """
        Detect SQL error dalam response.

        Returns: Score 0.0-1.0 (lebih banyak error patterns = lebih tinggi)
        """
        error_count = 0

        for pattern in self.sql_error_patterns:
            try:
                if re.search(pattern, response, re.IGNORECASE):
                    error_count += 1
            except Exception:
                continue

        if error_count == 0:
            return 0.0

        max_patterns = len(self.sql_error_patterns)
        score = min(float(error_count) / max_patterns, 1.0)

        # Boost score sedikit - error adalah good indicator
        return min(score * 1.2, 1.0)

    def _detect_response_difference(self, response: str) -> float:
        """
        Detect response difference dengan improved thresholds.

        New thresholds:
        - 50%+ → 1.0
        - 30%+ → 0.9
        - 20%  → 0.75
        - 15%  → 0.65
        - 8%   → 0.45
        - 4%   → 0.25
        - >0%  → 0.1
        """
        resp_len = len(response)
        baseline_len = self.baseline_size

        if baseline_len == 0:
            return 0.3

        size_diff_pct = abs(resp_len - baseline_len) / baseline_len

        if size_diff_pct >= 0.5:
            return 1.0
        elif size_diff_pct >= 0.3:
            return 0.9
        elif size_diff_pct >= 0.2:
            return 0.75
        elif size_diff_pct >= 0.15:
            return 0.65
        elif size_diff_pct >= 0.08:
            return 0.45
        elif size_diff_pct >= 0.04:
            return 0.25
        elif size_diff_pct > 0.0:
            return 0.1
        else:
            return 0.0

    def _detect_extracted_data(self, response: str) -> float:
        """
        Detect jika response mengandung extracted data.

        Returns: Score 0.0-1.0 (lebih banyak keywords = lebih tinggi)
        """
        matched_keywords = 0

        for keyword in self.data_keywords:
            try:
                if re.search(keyword, response, re.IGNORECASE):
                    matched_keywords += 1
            except Exception:
                continue

        if len(self.data_keywords) == 0:
            return 0.0

        keyword_ratio = float(matched_keywords) / len(self.data_keywords)
        return min(keyword_ratio, 1.0)

    def _analyze_payload(self, response: str, payload: str) -> float:
        """
        Analyze payload type dan detect keberhasilan.

        Returns: Score 0.0-1.0
        """
        score = 0.0
        payload_upper = payload.upper()
        size_diff = (
            abs(len(response) - self.baseline_size) / self.baseline_size
            if self.baseline_size > 0
            else 0
        )

        # Type 1: UNION SELECT
        if "UNION SELECT" in payload_upper:
            if size_diff >= 0.3:
                score = 0.9
            elif size_diff >= 0.15:
                score = 0.7
            elif size_diff > 0.05:
                score = 0.5
            else:
                score = 0.2

        # Type 2: ORDER BY
        elif "ORDER BY" in payload_upper:
            error_detected = self._detect_sql_error(response) > 0

            if error_detected:
                score = 0.6
            elif size_diff >= 0.2:
                score = 0.5
            elif size_diff > 0:
                score = 0.2
            else:
                score = 0.05

        # Type 3: GROUP BY
        elif "GROUP BY" in payload_upper:
            if size_diff >= 0.2:
                score = 0.5
            elif size_diff > 0:
                score = 0.2
            else:
                score = 0.05

        # Type 4: HAVING
        elif "HAVING" in payload_upper:
            has_error = self._detect_sql_error(response) > 0

            if has_error or size_diff >= 0.15:
                score = 0.6
            elif size_diff > 0.05:
                score = 0.3
            else:
                score = 0.1

        # Type 5: boolean-based (OR/AND)
        elif ("OR" in payload_upper or "AND" in payload_upper) and "=" in payload:
            if size_diff >= 0.3:
                score = 0.8
            elif size_diff >= 0.15:
                score = 0.6
            elif size_diff >= 0.05:
                score = 0.3
            else:
                score = 0.1

        return score

    def is_vulnerable(self, response: str, threshold: float = 0.4) -> bool:
        """
        Quick check: Apakah response menunjukkan vulnerability?
        """
        if self._detect_sql_error(response) > 0.25:
            return True

        if self._detect_extracted_data(response) > 0.3:
            return True

        if self._detect_response_difference(response) > 0.35:
            return True

        # Fallback: full fitness (opsional, kalau mau pakai threshold argumen)
        if self.calculate_fitness(response, "") >= threshold:
            return True

        return False

    def get_details(self, response: str, payload: str) -> Dict:
        """
        Get detailed breakdown dari fitness calculation.
        """
        return {
            "payload": payload,
            "response_length": len(response),
            "baseline_length": self.baseline_size,
            "size_difference_pct": (
                abs(len(response) - self.baseline_size) / self.baseline_size * 100
                if self.baseline_size > 0
                else 0
            ),
            "error_score": self._detect_sql_error(response),
            "diff_score": self._detect_response_difference(response),
            "data_score": self._detect_extracted_data(response),
            "payload_score": self._analyze_payload(response, payload),
            "total_fitness": self.calculate_fitness(response, payload),
            "is_vulnerable": self.is_vulnerable(response),
        }
