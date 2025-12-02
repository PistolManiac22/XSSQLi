# main_moga.py
from src.send_request import login_dvwa
from src.ga_engine import setup_ga, component_render
from src.fitness import evaluate
from src.seed_loader import load_seed_pools
import random
from deap import tools

# ---------------------------
# CONFIG
# ---------------------------
POP = 50
GEN = 30

if __name__ == "__main__":
    login_dvwa(security_level="impossible")
    print("[+] Logged in.")

    url = "http://localhost/dvwa/vulnerabilities/xss_r/"
    param = "name"

    pools = load_seed_pools("payload_base/xss_seed.txt")
    tag_pool, event_pool, js_pool = pools["tags"], pools["events"], pools["js"]

    toolbox = setup_ga(tag_pool, event_pool, js_pool)

    # initial population
    pop = toolbox.population(n=POP)

    # assign fitness
    fitness = [evaluate(ind, url, param) for ind in pop]
    for ind, fit in zip(pop, fitness):
        ind.fitness.values = fit

    print("[+] Starting NSGA-II evolution...\n")

    for gen in range(GEN):
        offspring = tools.selNSGA2(pop, len(pop))
        offspring = list(map(toolbox.clone, offspring))

        # crossover + mutation
        for c1, c2 in zip(offspring[::2], offspring[1::2]):
            toolbox.mate(c1, c2)
            del c1.fitness.values
            del c2.fitness.values

        for mut in offspring:
            toolbox.mutate(mut)
            del mut.fitness.values

        # evaluate invalid fitnesses
        invalid = [ind for ind in offspring if not ind.fitness.valid]
        for ind, fit in zip(invalid, [evaluate(i, url, param) for i in invalid]):
            ind.fitness.values = fit

        pop = offspring

        print(f"Gen {gen}:")
        print("  top survivability:", max(ind.fitness.values[0] for ind in pop))
        print("  top structure:", max(ind.fitness.values[1] for ind in pop))

    # extract Pareto Front
    pareto = tools.sortNondominated(pop, k=len(pop), first_front_only=True)[0]

    print("\n=== FINAL PARETO FRONT ===")
    for ind in pareto:
        print("Payload:", component_render(ind))
        print("Survivability:", ind.fitness.values[0])
        print("Structure:", ind.fitness.values[1])
        print()
