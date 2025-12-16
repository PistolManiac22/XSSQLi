"""
GAXSS Genetic Algorithm Engine (Generic)
Main GA loop with population management, selection, crossover, mutation

CORRECTED VERSION with proper GA implementation per paper Section 4.2
"""

import random
import logging
from typing import List, Tuple, Optional

from ga_core import GAXSS_DNA, crossover_uniform, mutate_gaxss
from payload_generator import GAXSS_PayloadGenerator
from fitness_calculator import GAXSS_FitnessCalculator


class GAXSS_Engine:
    """Main GAXSS genetic algorithm engine.
    
    Implements complete GA workflow per paper Section 4.2:
    1. Population initialization
    2. Fitness evaluation
    3. Selection (tournament)
    4. Crossover and mutation
    5. Elitism
    
    Reference:
        Liu et al. (2022), Section 4.2: Genetic Algorithm
    """

    def __init__(self,
                 population_size: int = 60,
                 generations: int = 30,
                 crossover_prob: float = 0.7,
                 mutation_prob: float = 0.2,
                 tournament_size: int = 3,
                 elite_size: int = 2,
                 patience: int = 10,
                 behaviors: dict = None,
                 test_func=None,
                 param_name: str = "search"):
        """Initialize GA engine with parameters.
        
        Args:
            population_size: Number of individuals per generation (default: 60)
            generations: Maximum number of generations (default: 30)
            crossover_prob: Probability of crossover (default: 0.7)
            mutation_prob: Probability of mutation (default: 0.2, per paper)
            tournament_size: Tournament selection size (default: 3)
            elite_size: Number of elites to preserve (default: 2)
            patience: (IGNORED now, early stopping disabled; kept for API compat)
            behaviors: Web app behavior dictionary (optional)
            test_func: Optional function for context detection
            param_name: Parameter name for context analysis
        """
        # ✅ LOGGER FIRST! (FIX #1)
        self.logger = logging.getLogger('GAXSS_Engine')
        
        # GA Parameters (per paper)
        self.population_size = population_size
        self.generations = generations
        self.crossover_prob = crossover_prob
        self.mutation_prob = mutation_prob  # per paper
        self.tournament_size = tournament_size
        self.elite_size = elite_size
        # early stopping dimatikan; tetap simpan supaya API tidak berubah
        self.patience = patience
        self.behaviors = behaviors or {}

        # Components
        self.payload_generator = GAXSS_PayloadGenerator(
            test_func=test_func,
            param_name=param_name
        )
        self.fitness_calc = GAXSS_FitnessCalculator(behaviors=self.behaviors)

        # ✅ Auto-detect context (NOW self.logger exists!)
        if test_func and self.payload_generator.context_analyzer:
            self.auto_context = self.payload_generator.context_analyzer.detect_context().value
            self.logger.info(f"Auto-detected context: {self.auto_context}")
        else:
            self.auto_context = None

        # State tracking
        self.population: List[GAXSS_DNA] = []
        self.fitness_scores: List[float] = []
        self.generation: int = 0
        self.best_fitness: float = 0.0
        self.best_individual: Optional[GAXSS_DNA] = None
        self.best_fitness_per_gen: List[float] = []
        self.avg_fitness_per_gen: List[float] = []

    def initialize_population(self) -> List[GAXSS_DNA]:
        """Create initial random population.

        CORRECTED per paper Section 4.2.1:

        DNA structure: C1C2C3C4 | B1B2B3B4B5B6 | M1...Mn

        - Closing (4 genes): each 0–4  (5 closing characters)
        - Main (6 genes): per-gene ranges
            B1: Tag index        0–14  (15 tags)
            B2: Event index      0–14  (15 events)
            B3: Function index   0–5   (6 functions)
            B4: Attribute index  0–11  (12 attributes)
            B5: Protocol index   0–1   (2 protocols)
            B6: Backward closing 0–4   (same as closing chars)
        - Mutations: 0–3 items, each 0–14 (15 mutation types)

        Returns:
            List of GAXSS_DNA individuals
        """
        population: List[GAXSS_DNA] = []

        # Correct ranges per paper
        CLOSING_RANGE = (0, 4)  # instead of (0, 7)
        MAIN_GENES_RANGES = [
            (0, 14),  # B1: Tag
            (0, 14),  # B2: Event
            (0, 5),   # B3: Function
            (0, 11),  # B4: Attribute
            (0, 1),   # B5: Protocol
            (0, 4),   # B6: Backward closing
        ]

        for i in range(self.population_size):
            try:
                # Closing: 4 genes, 0–4
                closing = [
                    random.randint(*CLOSING_RANGE)
                    for _ in range(4)
                ]

                # Main: 6 genes with specific ranges
                main = [
                    random.randint(min_val, max_val)
                    for (min_val, max_val) in MAIN_GENES_RANGES
                ]

                # Mutations: 0–3 mutation types, each 0–14
                num_mutations = random.randint(0, 3)
                mutations = [random.randint(0, 14) for _ in range(num_mutations)]

                dna = GAXSS_DNA(closing, main, mutations)
                population.append(dna)

            except Exception as e:
                self.logger.error(f"Error initializing individual {i}: {e}")
                continue

        self.logger.info(f"[OK] Initialized population of size {len(population)} "
                         f"with CORRECT gene ranges")
        return population

    def evaluate_population(
        self,
        population: List[GAXSS_DNA],
        test_func,
        context: int = 2
    ) -> List[Tuple[float, float, float, float, float]]:
        """Evaluate fitness for entire population.
        
        Per paper Section 4.2.2:
        For each individual:
        1. Generate payload from DNA
        2. Test payload on web app
        3. Calculate fitness score
        
        Args:
            population: List of DNA individuals
            test_func: Function to test payload (returns response)
            context: Injection context (0=script, 1=attribute, 2=outside)
            
        Returns:
            List of (fitness, ex, closed, dis, pu) tuples
        """
        fitness_data: List[Tuple[float, float, float, float, float]] = []
        evaluated_count = 0
        failed_count = 0

        for idx, dna in enumerate(population):
            try:
                # Generate payload from DNA
                payload = self.payload_generator.generate_payload(dna, context)

                # Test payload
                response = test_func(payload)

                # Calculate fitness
                fitness, ex, closed, dis, pu = self.fitness_calc.calculate_fitness(
                    payload, response, 'xss'
                )

                fitness_data.append((fitness, ex, closed, dis, pu))
                evaluated_count += 1

            except Exception as e:
                self.logger.debug(f"Error evaluating DNA {idx}: {e}")
                # Return zero fitness for failed evaluations
                fitness_data.append((0.0, 0.0, 0.0, 0.0, 1.0))
                failed_count += 1

        self.logger.debug(
            f"Evaluated {evaluated_count}/{len(population)} individuals, "
            f"failed {failed_count}"
        )

        return fitness_data

    def tournament_selection(self, fitness_scores: List[float]) -> int:
        """Select individual via tournament selection.
        
        Per paper: Tournament size = 3
        Selects tournament_size individuals randomly, returns best
        
        Args:
            fitness_scores: List of fitness scores
            
        Returns:
            Index of selected individual
        """
        # Random sample of tournament_size individuals
        tournament_size = min(self.tournament_size, len(fitness_scores))
        tournament_indices = random.sample(
            range(len(fitness_scores)),
            tournament_size
        )

        # Find best in tournament
        best_idx = tournament_indices[0]
        for idx in tournament_indices[1:]:
            if fitness_scores[idx] > fitness_scores[best_idx]:
                best_idx = idx

        return best_idx

    def evolve(
        self,
        test_func,
        context: Optional[int] = None,
        verbose: bool = True
    ) -> Tuple[List[GAXSS_DNA], List[float]]:
        """Run genetic algorithm evolution loop.
        
        Per paper Section 4.2:
        Repeat for fixed number of generations:
        1. Evaluate population fitness
        2. Select parents (tournament)
        3. Crossover with probability
        4. Mutate with probability
        5. Preserve elite
        
        Args:
            test_func: Function to test payload (returns response)
            context: Injection context (default: 2 = outside)
            verbose: Log progress (default: True)
            
        Returns:
            Tuple of (final_population, best_fitness_per_generation)
        """
        # ✅ Use auto-detected context if available
        if context is None and self.auto_context is not None:
            if 0 <= self.auto_context <= 2:
                context = self.auto_context
                self.logger.info(f"Using auto-detected context: {context}")
            else:
                self.logger.warning(f"Invalid auto_context {self.auto_context}, using default")
                context = 2
        elif context is None:
            context = 2  # Default to outside tag

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
        self.logger.info(f"Early stopping: DISABLED (run full {self.generations} gens)")

        # ============== BASELINE & ECHO MARKER INITIALIZATION ==============
        baseline_marker = self.behaviors.get('echo_marker', 'TESTMARKER123456')
        try:
            self.logger.info(f"Setting baseline with marker: {baseline_marker!r}")
            baseline_response = test_func(baseline_marker)

            # Configure fitness calculator
            self.fitness_calc.set_echo_marker(baseline_marker)
            self.fitness_calc.set_baseline(baseline_response)

            self.logger.info(
                f"[OK] Baseline set: length="
                f"{len(baseline_response) if baseline_response else 0}"
            )
        except Exception as e:
            self.logger.warning(
                f"Failed to set baseline using marker {baseline_marker!r}: {e}. "
                "Continuing without baseline; execution detection may be noisy."
            )
        # ====================================================================

        # Initialize population
        population = self.initialize_population()
        best_fitness_per_gen: List[float] = []
        avg_fitness_per_gen: List[float] = []

        # EVOLUTION LOOP (full fixed number of generations)
        for gen in range(self.generations):
            self.generation = gen + 1

            # STEP 1: Evaluate population
            fitness_data = self.evaluate_population(population, test_func, context)
            fitness_scores = [f[0] for f in fitness_data]

            # Calculate statistics
            best_idx = fitness_scores.index(max(fitness_scores))
            best_fitness = fitness_scores[best_idx]
            avg_fitness = (
                sum(fitness_scores) / len(fitness_scores)
                if fitness_scores else 0.0
            )

            best_fitness_per_gen.append(best_fitness)
            avg_fitness_per_gen.append(avg_fitness)

            # Log progress
            if verbose:
                self.logger.info(
                    f"Gen {self.generation:3d}: "
                    f"Best={best_fitness:6.4f} | "
                    f"Avg={avg_fitness:6.4f}"
                )

            # Track global best (no early stopping, hanya track)
            if best_fitness > self.best_fitness:
                self.best_fitness = best_fitness
                self.best_individual = population[best_idx].copy()
                if verbose:
                    self.logger.info(
                        f"  [OK] New best fitness: {best_fitness:.4f}"
                    )

            # STEP 4: Create next generation
            new_population: List[GAXSS_DNA] = []

            # Elitism: Preserve best individuals
            elite_indices = sorted(
                range(len(fitness_scores)),
                key=lambda i: fitness_scores[i],
                reverse=True
            )[:self.elite_size]

            for elite_idx in elite_indices:
                new_population.append(population[elite_idx].copy())
                self.logger.debug(
                    f"  Preserved elite individual {elite_idx} "
                    f"(fitness={fitness_scores[elite_idx]:.4f})"
                )

            # Fill rest of population via selection, crossover, mutation
            while len(new_population) < self.population_size:
                # Tournament selection for parents
                parent1_idx = self.tournament_selection(fitness_scores)
                parent2_idx = self.tournament_selection(fitness_scores)

                parent1 = population[parent1_idx]
                parent2 = population[parent2_idx]

                # Crossover
                if random.random() < self.crossover_prob:
                    child1, child2 = crossover_uniform(parent1, parent2)
                else:
                    child1 = parent1.copy()
                    child2 = parent2.copy()

                # Mutation
                if random.random() < self.mutation_prob:
                    child1 = mutate_gaxss(child1, mutation_rate=self.mutation_prob)
                if random.random() < self.mutation_prob:
                    child2 = mutate_gaxss(child2, mutation_rate=self.mutation_prob)

                # Add to next generation
                new_population.append(child1)
                if len(new_population) < self.population_size:
                    new_population.append(child2)

            # Ensure exact population size
            population = new_population[:self.population_size]
            self.population = population
            self.fitness_scores = fitness_scores

        # END OF EVOLUTION

        self.logger.info("=" * 70)
        self.logger.info("GAXSS Genetic Algorithm Evolution Complete")
        self.logger.info("=" * 70)
        self.logger.info(f"Total generations: {self.generation}")
        self.logger.info(f"Best fitness: {self.best_fitness:.4f}")
        self.logger.info("Final best individual:")
        if self.best_individual:
            self.logger.info(f"  Closing: {self.best_individual.closing}")
            self.logger.info(f"  Main: {self.best_individual.main}")
            self.logger.info(f"  Mutations: {self.best_individual.mutations}")

        self.best_fitness_per_gen = best_fitness_per_gen
        self.avg_fitness_per_gen = avg_fitness_per_gen

        return population, best_fitness_per_gen

    def get_statistics(self) -> dict:
        """Get evolution statistics.
        
        Returns:
            Dict with evolution metrics
        """
        return {
            'total_generations': self.generation,
            'best_fitness': self.best_fitness,
            'best_individual': self.best_individual,
            'best_fitness_per_gen': self.best_fitness_per_gen,
            'avg_fitness_per_gen': self.avg_fitness_per_gen,
        }