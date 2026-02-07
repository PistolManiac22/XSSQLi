"""
GAXSS Genetic Algorithm Engine (Generic)
Main GA loop with population management, selection, crossover, mutation

CORRECTED VERSION dengan implementasi GA sesuai paper Section 4.2
XSS + SQLi (DNA dict) kompatibel, siap produksi
"""

import random
import logging
import requests
from typing import List, Tuple, Optional, Dict, Union

from ga_core import GAXSS_DNA, crossover_uniform, mutate_gaxss
from payload_generator import GAXSS_PayloadGenerator
from fitness_calculator import GAXSS_FitnessCalculator

from sqli_detector.column_detector import ColumnDetector
from sqli_detector.sqli_payload_generator import SQLiPayloadGenerator
from sqli_detector.sqli_analyzer import SQLiAnalyzer


class GAXSS_Engine:
    """Main GAXSS genetic algorithm engine."""

    def __init__(
        self,
        population_size: int = 60,
        generations: int = 30,
        crossover_prob: float = 0.5,
        mutation_prob: float = 0.1,
        tournament_size: int = 7,
        elite_size: int = 0,
        patience: int = 10,
        behaviors: dict = None,
        test_func=None,
        param_name: str = "search",
        sqli_mode: bool = False,
        sqli_column_count: int = None,
    ):
        self.logger = logging.getLogger("GAXSSEngine")

        # GA parameters
        self.population_size = population_size
        self.generations = generations
        self.crossover_prob = crossover_prob
        self.mutation_prob = mutation_prob
        self.tournament_size = tournament_size
        self.elite_size = elite_size
        self.patience = patience  # kept for API compatibility
        self.behaviors = behaviors or {}

        # XSS components
        self.payload_generator = GAXSS_PayloadGenerator(
            test_func=test_func,
            param_name=param_name,
        )
        self.fitness_calc = GAXSS_FitnessCalculator(behaviors=self.behaviors)

        # Auto context detection (XSS)
        if test_func and self.payload_generator.context_analyzer:
            self.auto_context = (
                self.payload_generator.context_analyzer.detect_context().value
            )
            self.logger.info(f"Auto-detected context: {self.auto_context}")
        else:
            self.auto_context = None

        # SQLi state
        self.sqli_mode = sqli_mode
        self.sqli_column_count = sqli_column_count
        self.sqli_generator: Optional[SQLiPayloadGenerator] = None
        self.sqli_analyzer: Optional[SQLiAnalyzer] = None

        if sqli_mode:
            if sqli_column_count is None:
                # default, akan dioverride oleh ColumnDetector
                sqli_column_count = 2
            self.sqli_generator = SQLiPayloadGenerator(column_count=sqli_column_count)
            self.sqli_analyzer = SQLiAnalyzer("")
            self.logger.info("SQLi mode enabled")

        # Evolution state
        self.population: List[GAXSS_DNA] = []
        self.fitness_scores: List[float] = []
        self.generation: int = 0
        # XSS: GAXSS_DNA, SQLi: payload str
        self.best_individual: Optional[Union[GAXSS_DNA, str]] = None
        self.best_fitness: float = 0.0
        self.best_fitness_per_gen: List[float] = []
        self.avg_fitness_per_gen: List[float] = []

    # ========================= XSS PART =========================

    def initialize_population(self) -> List[GAXSS_DNA]:
        """Create initial random population (XSS DNA)."""
        population: List[GAXSS_DNA] = []

        CLOSING_RANGE = (0, 4)
        MAIN_GENES_RANGES = [
            (0, 14),  # Tag
            (0, 14),  # Event
            (0, 5),   # Function
            (0, 11),  # Attribute
            (0, 1),   # Protocol
            (0, 4),   # Backward closing
        ]

        for i in range(self.population_size):
            try:
                closing = [random.randint(*CLOSING_RANGE) for _ in range(4)]
                main = [
                    random.randint(min_val, max_val)
                    for (min_val, max_val) in MAIN_GENES_RANGES
                ]
                num_mutations = random.randint(0, 3)
                mutations = [random.randint(0, 14) for _ in range(num_mutations)]
                dna = GAXSS_DNA(closing, main, mutations)
                population.append(dna)
            except Exception as e:
                self.logger.error(f"Error initializing individual {i}: {e}")
                continue

        self.logger.info(
            f"[OK] Initialized population of size {len(population)} with CORRECT gene ranges"
        )
        return population

    def evaluate_population(
        self,
        population: List[GAXSS_DNA],
        test_func,
        context: int = 2,
    ) -> List[Tuple[float, float, float, float, float]]:
        """Evaluate fitness for entire XSS population."""
        fitness_data: List[Tuple[float, float, float, float, float]] = []
        evaluated_count = 0
        failed_count = 0

        for idx, dna in enumerate(population):
            try:
                payload = self.payload_generator.generate_payload(dna, context)
                response = test_func(payload)
                fitness, ex, closed, dis, pu = self.fitness_calc.calculate_fitness(
                    payload, response, "xss"
                )
                fitness_data.append((fitness, ex, closed, dis, pu))
                evaluated_count += 1
            except Exception as e:
                self.logger.debug(f"Error evaluating DNA {idx}: {e}")
                fitness_data.append((0.0, 0.0, 0.0, 0.0, 1.0))
                failed_count += 1

        self.logger.debug(
            f"Evaluated {evaluated_count}/{len(population)} individuals, failed {failed_count}"
        )
        return fitness_data

    def tournament_selection(self, fitness_scores: List[float]) -> int:
        """Tournament selection (XSS)."""
        tournament_size = min(self.tournament_size, len(fitness_scores))
        tournament_indices = random.sample(range(len(fitness_scores)), tournament_size)
        best_idx = tournament_indices[0]
        for idx in tournament_indices[1:]:
            if fitness_scores[idx] > fitness_scores[best_idx]:
                best_idx = idx
        return best_idx

    def evolve(
        self,
        test_func,
        context: Optional[int] = None,
        verbose: bool = True,
    ) -> Tuple[List[GAXSS_DNA], List[float]]:
        """Run XSS GA evolution."""
        if (
            context is None
            and self.auto_context is not None
            and 0 <= self.auto_context <= 2
        ):
            context = self.auto_context
            self.logger.info(f"Using auto-detected context: {context}")
        elif context is None:
            context = 2

        self.logger.info("=" * 70)
        self.logger.info("GAXSS Genetic Algorithm Evolution Starting")
        self.logger.info("=" * 70)
        self.logger.info(f"Population size: {self.population_size}")
        self.logger.info(f"Generations: {self.generations}")
        self.logger.info(f"Crossover prob: {self.crossover_prob}")
        self.logger.info(f"Mutation prob: {self.mutation_prob}")
        self.logger.info(f"Tournament size: {self.tournament_size}")
        self.logger.info(f"Elite size: {self.elite_size}")
        self.logger.info(f"Context: {context} (0=script, 1=attribute, 2=outside)")
        self.logger.info(
            f"Early stopping: DISABLED (run full {self.generations} gens)"
        )

        # Baseline
        baseline_marker = self.behaviors.get("echo_marker", "TESTMARKER123456")
        try:
            self.logger.info(f"Setting baseline with marker: {baseline_marker!r}")
            baseline_response = test_func(baseline_marker)
            self.fitness_calc.set_echo_marker(baseline_marker)
            self.fitness_calc.set_baseline(baseline_response)
            self.logger.info(
                f"[OK] Baseline set: length={len(baseline_response) if baseline_response else 0}"
            )
        except Exception as e:
            self.logger.warning(
                f"Failed to set baseline using marker {baseline_marker!r}: {e}. "
                "Continuing without baseline; execution detection may be noisy."
            )

        # Initialize
        population = self.initialize_population()
        best_fitness_per_gen: List[float] = []
        avg_fitness_per_gen: List[float] = []

        # Evolution loop
        for gen in range(self.generations):
            self.generation = gen + 1
            fitness_data = self.evaluate_population(population, test_func, context)
            fitness_scores = [f[0] for f in fitness_data]

            best_idx = fitness_scores.index(max(fitness_scores))
            best_fitness = fitness_scores[best_idx]
            avg_fitness = (
                sum(fitness_scores) / len(fitness_scores) if fitness_scores else 0.0
            )

            best_fitness_per_gen.append(best_fitness)
            avg_fitness_per_gen.append(avg_fitness)

            if verbose:
                self.logger.info(
                    f"Gen {self.generation:3d}: Best={best_fitness:6.4f} | Avg={avg_fitness:6.4f}"
                )

            if best_fitness > self.best_fitness:
                self.best_fitness = best_fitness
                self.best_individual = population[best_idx].copy()
                if verbose:
                    self.logger.info(f"  [OK] New best fitness: {best_fitness:.4f}")

            # Next generation
            new_population: List[GAXSS_DNA] = []

            elite_indices = sorted(
                range(len(fitness_scores)),
                key=lambda i: fitness_scores[i],
                reverse=True,
            )[: self.elite_size]

            for elite_idx in elite_indices:
                new_population.append(population[elite_idx].copy())
                self.logger.debug(
                    f"  Preserved elite individual {elite_idx} "
                    f"(fitness={fitness_scores[elite_idx]:.4f})"
                )

            while len(new_population) < self.population_size:
                p1_idx = self.tournament_selection(fitness_scores)
                p2_idx = self.tournament_selection(fitness_scores)
                parent1 = population[p1_idx]
                parent2 = population[p2_idx]

                if random.random() < self.crossover_prob:
                    child1, child2 = crossover_uniform(parent1, parent2)
                else:
                    child1 = parent1.copy()
                    child2 = parent2.copy()

                if random.random() < self.mutation_prob:
                    child1 = mutate_gaxss(child1, mutation_rate=self.mutation_prob)
                if random.random() < self.mutation_prob:
                    child2 = mutate_gaxss(child2, mutation_rate=self.mutation_prob)

                new_population.append(child1)
                if len(new_population) < self.population_size:
                    new_population.append(child2)

            population = new_population[: self.population_size]
            self.population = population
            self.fitness_scores = fitness_scores

        self.logger.info("=" * 70)
        self.logger.info("GAXSS Genetic Algorithm Evolution Complete")
        self.logger.info("=" * 70)
        self.logger.info(f"Total generations: {self.generation}")
        self.logger.info(f"Best fitness: {self.best_fitness:.4f}")
        if isinstance(self.best_individual, GAXSS_DNA):
            self.logger.info(f"  Closing: {self.best_individual.closing}")
            self.logger.info(f"  Main: {self.best_individual.main}")
            self.logger.info(f"  Mutations: {self.best_individual.mutations}")

        self.best_fitness_per_gen = best_fitness_per_gen
        self.avg_fitness_per_gen = avg_fitness_per_gen
        return population, best_fitness_per_gen

    # ========================= SQLi PART =========================

    def evolve_sqli(
        self,
        test_func,  # tidak dipakai, ada demi kompatibilitas
        app_config,
        target_url: str,
        param_name: str = "id",
        verbose: bool = True,
    ) -> Tuple[List, List[float]]:
        """Run genetic algorithm evolution for SQL Injection."""
        self.logger.info("=" * 70)
        self.logger.info("GAXSS Genetic Algorithm - SQLi Mode")
        self.logger.info("=" * 70)

        self.logger.info(f"Target: {target_url}")
        self.logger.info(f"Parameter: {param_name}")
        self.logger.info("Mode: SQL Injection")

        # ===== PHASE 1: Detect column count =====
        self.logger.info("\n[Phase 1] Detecting database column count...")

        try:
            detector = ColumnDetector(app_config, param_name)
            col_count = detector.detect_column_count()

            if col_count is None:
                self.logger.error("[-] Column detection failed")
                return [], []

            self.sqli_column_count = col_count
            self.sqli_generator = SQLiPayloadGenerator(column_count=col_count)
            self.logger.info(f"[+] Detected {col_count} columns")

        except Exception as e:
            self.logger.error(f"Column detection error: {e}")
            return [], []

        # ===== PHASE 2: Get baseline response =====
        self.logger.info("[Phase 2] Getting baseline response...")

        baseline_payloads = [
            "1",
            "1' AND '1'='1",
            "1' AND '1'='2",
        ]

        baseline_responses = []
        for bp in baseline_payloads:
            try:
                resp = self._sqli_send_payload(app_config, target_url, param_name, bp)
                baseline_responses.append(resp)
                self.logger.debug(f"Baseline response ({bp}): {len(resp)} bytes")
            except Exception as e:
                self.logger.debug(f"Error getting baseline: {e}")

        baseline_response = (
            max(baseline_responses, key=len) if baseline_responses else ""
        )
        self.sqli_analyzer = SQLiAnalyzer(baseline_response)
        self.logger.info(
            f"[+] Baseline: {len(baseline_response) if baseline_response else 0} bytes"
        )

        # ===== PHASE 3: Initialize population =====
        self.logger.info("[Phase 3] Initializing GA population...")

        population = self._sqli_initialize_population(self.population_size)
        self.logger.info(f"[+] Population initialized: {len(population)} individuals")

        best_fitness_per_gen: List[float] = []
        best_payload: Optional[str] = None
        best_fitness = 0.0

        # ===== PHASE 4: Evolution loop =====
        self.logger.info(f"[Phase 4] Evolution starting ({self.generations} generations)")
        self.logger.info("=" * 70)

        for gen in range(self.generations):
            self.generation = gen + 1
            fitness_data = []

            for dna in population:
                try:
                    payload = self.sqli_generator.dna_to_payload(dna)
                    response = self._sqli_send_payload(
                        app_config, target_url, param_name, payload
                    )
                    fitness = self.sqli_analyzer.calculate_fitness(response, payload)
                    fitness_data.append((dna, fitness, payload))
                except Exception:
                    fitness_data.append((dna, 0.0, ""))

            fitness_scores = [f[1] for f in fitness_data]

            if fitness_scores:
                gen_best = max(fitness_scores)
                gen_avg = sum(fitness_scores) / len(fitness_scores)
                best_idx = fitness_scores.index(gen_best)

                best_fitness_per_gen.append(gen_best)

                if verbose:
                    self.logger.info(
                        f"Gen {self.generation:3d}: Best={gen_best:6.4f} | Avg={gen_avg:6.4f}"
                    )

                if gen_best > best_fitness:
                    best_fitness = gen_best
                    best_payload = fitness_data[best_idx][2]
                    if verbose:
                        self.logger.info(f"  [+] NEW BEST! Fitness: {best_fitness:.4f}")
                        if best_payload:
                            self.logger.info(
                                f"      Payload: {str(best_payload)[:70]}..."
                            )

                if best_fitness >= 0.9:
                    self.logger.info(
                        f"\n[+] VULNERABLE DETECTED! (fitness: {best_fitness:.4f})"
                    )
                    if best_payload:
                        self.logger.info(f"[+] Payload: {best_payload}")
                    self.best_fitness = best_fitness
                    self.best_individual = best_payload
                    self.best_fitness_per_gen = best_fitness_per_gen
                    return population, best_fitness_per_gen

            # Selection & reproduction
            new_population: List[Dict] = []

            elite_indices = sorted(
                range(len(fitness_scores)),
                key=lambda i: fitness_scores[i],
                reverse=True,
            )[: self.elite_size]

            for elite_idx in elite_indices:
                indiv = population[elite_idx]
                new_population.append(indiv.copy())

            while len(new_population) < self.population_size:
                parent1_dna = self._sqli_tournament_selection(
                    fitness_scores, population
                )
                parent2_dna = self._sqli_tournament_selection(
                    fitness_scores, population
                )

                if random.random() < self.crossover_prob:
                    child1, child2 = self._sqli_crossover(parent1_dna, parent2_dna)
                else:
                    child1 = parent1_dna.copy()
                    child2 = parent2_dna.copy()

                if random.random() < self.mutation_prob:
                    child1 = self._mutate_sqli_dna(child1)
                if random.random() < self.mutation_prob:
                    child2 = self._mutate_sqli_dna(child2)

                new_population.append(child1)
                if len(new_population) < self.population_size:
                    new_population.append(child2)

            population = new_population[: self.population_size]

        # END OF EVOLUTION

        self.logger.info("=" * 70)
        self.logger.info("GA Evolution Complete")
        self.logger.info("=" * 70)
        self.logger.info(f"Best fitness: {best_fitness:.4f}")

        if best_payload:
            self.logger.info(f"Best payload:\n{best_payload}")
            self.best_fitness = best_fitness
            self.best_individual = best_payload

        self.best_fitness_per_gen = best_fitness_per_gen
        return population, best_fitness_per_gen

    # ===== SQLi HELPER METHODS =====

    def _sqli_initialize_population(self, size: int) -> List[Dict]:
        """Initialize random SQLi DNA population (dict format)."""
        population = []
        for _ in range(size):
            dna = self.sqli_generator.generate_dna()
            population.append(dna)
        return population

    def _sqli_send_payload(
        self,
        app_config,
        target_url: str,
        param_name: str,
        payload: str,
    ) -> str:
        """
        Send SQLi payload and get response.

        FIX: gunakan send_payload milik app_config kalau ada;
        kalau tidak, fallback ke requests GET/POST dengan query tunggal.
        """
        try:
            # Kalau config punya send_payload (DVWA/bWAPP/GenericWebApp), pakai itu saja
            if hasattr(app_config, "send_payload"):
                return app_config.send_payload(target_url, param_name, payload)

            # Fallback: object dengan session (tanpa method-awareness)
            if hasattr(app_config, "session"):
                r = app_config.session.get(
                    target_url,
                    params={param_name: payload},
                    timeout=5,
                )
                return r.text

            # Fallback dict config
            if isinstance(app_config, dict):
                url = app_config.get("url", target_url)
                method = app_config.get("method", "GET").upper()
                session = app_config.get("session")
                cookies = app_config.get("cookies")

                if session is not None:
                    if method == "GET":
                        r = session.get(url, params={param_name: payload}, timeout=5)
                    else:
                        r = session.post(url, data={param_name: payload}, timeout=5)
                    return r.text

                if cookies is not None:
                    if method == "GET":
                        r = requests.get(
                            url,
                            params={param_name: payload},
                            cookies=cookies,
                            timeout=5,
                        )
                    else:
                        r = requests.post(
                            url,
                            data={param_name: payload},
                            cookies=cookies,
                            timeout=5,
                        )
                    return r.text

                # No session/cookies
                if method == "GET":
                    r = requests.get(url, params={param_name: payload}, timeout=5)
                else:
                    r = requests.post(url, data={param_name: payload}, timeout=5)
                return r.text

            # Generic fallback: treat target_url as full URL
            r = requests.get(target_url, params={param_name: payload}, timeout=5)
            return r.text

        except Exception as e:
            self.logger.debug(f"Error sending payload: {e}")
            return ""

    def _sqli_tournament_selection(
        self, fitness_scores: List[float], population: List[Dict]
    ) -> Dict:
        """Select SQLi individual via tournament (dict format)."""
        tournament_size = min(self.tournament_size, len(fitness_scores))
        tournament_indices = random.sample(range(len(fitness_scores)), tournament_size)
        best_idx = tournament_indices[0]
        for idx in tournament_indices[1:]:
            if fitness_scores[idx] > fitness_scores[best_idx]:
                best_idx = idx
        indiv = population[best_idx]
        return indiv.copy()

    def _sqli_crossover(self, parent1: Dict, parent2: Dict) -> Tuple[Dict, Dict]:
        """
        Single-point crossover for SQLi DNA (dict format).
        Converts dict to list, does crossover, converts back.
        """
        keys = [
            "injection_type",
            "quote_style",
            "comment_style",
            "extract_type",
            "table_name",
        ]

        p1_list = [parent1.get(k) for k in keys if k in parent1]
        p2_list = [parent2.get(k) for k in keys if k in parent2]

        min_len = min(len(p1_list), len(p2_list))
        if min_len <= 1:
            return parent1.copy(), parent2.copy()

        point = random.randint(1, min_len - 1)
        c1_list = p1_list[:point] + p2_list[point:]
        c2_list = p2_list[:point] + p1_list[point:]

        child1 = {k: c1_list[i] for i, k in enumerate(keys[: len(c1_list)])}
        child2 = {k: c2_list[i] for i, k in enumerate(keys[: len(c2_list)])}

        return child1, child2

    def _mutate_sqli_dna(self, dna: Dict) -> Dict:
        """Mutate SQLi DNA (dict format)."""
        mutated = dna.copy()

        if random.random() < 0.6:
            mutation_type = random.randint(0, 3)

            if mutation_type == 0 and "injection_type" in mutated:
                mutated["injection_type"] = random.randint(0, 4)
            elif mutation_type == 1 and "quote_style" in mutated:
                mutated["quote_style"] = random.randint(0, 2)
            elif mutation_type == 2 and "comment_style" in mutated:
                mutated["comment_style"] = (mutated["comment_style"] + 1) % 3
            elif mutation_type == 3 and "extract_type" in mutated:
                mutated["extract_type"] = random.randint(0, 5)

        return mutated

    def get_statistics(self) -> dict:
        """Get evolution statistics."""
        return {
            "total_generations": self.generation,
            "best_fitness": self.best_fitness,
            "best_individual": self.best_individual,
            "best_fitness_per_gen": self.best_fitness_per_gen,
            "avg_fitness_per_gen": self.avg_fitness_per_gen,
        }
