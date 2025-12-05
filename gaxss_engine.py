"""
GAXSS Genetic Algorithm Engine
Main GA loop with population management, selection, crossover, mutation
"""

import random
import logging
from typing import List, Tuple, Optional
from ga_core import GAXSS_DNA, crossover_uniform, mutate_gaxss
from payload_generator import GAXSS_PayloadGenerator
from fitness_calculator import GAXSS_FitnessCalculator


class GAXSS_Engine:
    """Main GAXSS genetic algorithm engine."""

    def __init__(self, population_size: int = 60, generations: int = 30,
                 crossover_prob: float = 0.7, mutation_prob: float = 0.5,
                 tournament_size: int = 3, elite_size: int = 2, patience: int = 10):
        self.population_size = population_size
        self.generations = generations
        self.crossover_prob = crossover_prob
        self.mutation_prob = mutation_prob
        self.tournament_size = tournament_size
        self.elite_size = elite_size
        self.patience = patience

        self.payload_generator = GAXSS_PayloadGenerator()
        self.fitness_calc = GAXSS_FitnessCalculator()

        self.logger = logging.getLogger('GAXSS_Engine')
        self.population = []
        self.fitness_scores = []
        self.generation = 0
        self.best_fitness = 0.0
        self.best_individual = None

    def initialize_population(self) -> List[GAXSS_DNA]:
        """Create initial random population."""
        population = []
        for _ in range(self.population_size):
            closing = [random.randint(0, 7) for _ in range(4)]
            main = [random.randint(0, 20) for _ in range(6)]
            mutations = [random.randint(0, 14) for _ in range(random.randint(0, 3))]

            dna = GAXSS_DNA(closing, main, mutations)
            population.append(dna)

        self.logger.info(f"Initialized population of size {len(population)}")
        return population

    def evaluate_population(self, population: List[GAXSS_DNA], test_func, context: int = 2):
        """Evaluate fitness for entire population."""
        fitness_data = []

        for dna in population:
            try:
                payload = self.payload_generator.generate_payload(dna, context)
                response = test_func(payload)
                fitness, ex, closed, dis, pu = self.fitness_calc.calculate_fitness(payload, response, 'xss')
                fitness_data.append((fitness, ex, closed, dis, pu))
            except Exception as e:
                self.logger.warning(f"Error evaluating DNA: {e}")
                fitness_data.append((0.0, 0.0, 0.0, 0.0, 1.0))

        return fitness_data

    def tournament_selection(self, fitness_scores: List[float]) -> int:
        """Select individual via tournament selection."""
        tournament_indices = random.sample(
            range(len(fitness_scores)),
            min(self.tournament_size, len(fitness_scores))
        )

        best_idx = tournament_indices[0]
        for idx in tournament_indices[1:]:
            if fitness_scores[idx] > fitness_scores[best_idx]:
                best_idx = idx

        return best_idx

    def evolve(self, test_func, context: int = 2, verbose: bool = True):
        """Run genetic algorithm evolution loop."""
        population = self.initialize_population()
        best_fitness_per_gen = []
        no_improvement_count = 0

        for gen in range(self.generations):
            self.generation = gen + 1

            fitness_data = self.evaluate_population(population, test_func, context)
            fitness_scores = [f[0] for f in fitness_data]

            best_idx = fitness_scores.index(max(fitness_scores))
            best_fitness = fitness_scores[best_idx]
            avg_fitness = sum(fitness_scores) / len(fitness_scores)
            best_fitness_per_gen.append(best_fitness)

            if verbose:
                self.logger.info(f"Gen {self.generation}: Best={best_fitness:.4f}, Avg={avg_fitness:.4f}")

            if best_fitness > self.best_fitness:
                self.best_fitness = best_fitness
                self.best_individual = population[best_idx].copy()
                no_improvement_count = 0
            else:
                no_improvement_count += 1

            if no_improvement_count >= self.patience:
                if verbose:
                    self.logger.info(f"Early stopping at generation {self.generation}")
                break

            new_population = []

            elite_indices = sorted(
                range(len(fitness_scores)),
                key=lambda i: fitness_scores[i],
                reverse=True
            )[:self.elite_size]

            for elite_idx in elite_indices:
                new_population.append(population[elite_idx].copy())

            while len(new_population) < self.population_size:
                parent1_idx = self.tournament_selection(fitness_scores)
                parent2_idx = self.tournament_selection(fitness_scores)

                parent1 = population[parent1_idx]
                parent2 = population[parent2_idx]

                if random.random() < self.crossover_prob:
                    child1, child2 = crossover_uniform(parent1, parent2)
                else:
                    child1 = parent1.copy()
                    child2 = parent2.copy()

                if random.random() < self.mutation_prob:
                    child1 = mutate_gaxss(child1)
                if random.random() < self.mutation_prob:
                    child2 = mutate_gaxss(child2)

                new_population.append(child1)
                if len(new_population) < self.population_size:
                    new_population.append(child2)

            population = new_population[:self.population_size]
            self.population = population
            self.fitness_scores = fitness_scores

        return population, best_fitness_per_gen
