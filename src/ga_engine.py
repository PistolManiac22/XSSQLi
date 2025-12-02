# ga_engine_moga.py
from deap import base, creator, tools
import random

def setup_ga(tag_pool, event_pool, js_pool):
    # Multi-objective GA: (survivability, structure)
    creator.create("FitnessMulti", base.Fitness, weights=(1.0, 1.0))
    creator.create("Individual", list, fitness=creator.FitnessMulti)

    toolbox = base.Toolbox()

    # gene generators
    toolbox.register("tag_gene", lambda: random.choice(tag_pool))
    toolbox.register("event_gene", lambda: random.choice(event_pool))
    toolbox.register("js_gene", lambda: random.choice(js_pool))

    # an individual is [tag, event, js]
    toolbox.register("individual", tools.initCycle, creator.Individual,
                     (toolbox.tag_gene, toolbox.event_gene, toolbox.js_gene), n=1)

    toolbox.register("population", tools.initRepeat, list, toolbox.individual)

    # genetic operators
    toolbox.register("mate", cx_components)
    toolbox.register("mutate", mut_components,
                     tag_pool=tag_pool, event_pool=event_pool, js_pool=js_pool,
                     indpb=0.25)

    # NSGA-II selection
    toolbox.register("select", tools.selNSGA2)

    return toolbox


def cx_components(ind1, ind2):
    """Crossover: swap components."""
    index = random.randint(0, 2)
    ind1[index], ind2[index] = ind2[index], ind1[index]
    return ind1, ind2


def mut_components(ind, tag_pool, event_pool, js_pool, indpb=0.25):
    """Mutation: occasionally replace components."""
    if random.random() < indpb:
        ind[0] = random.choice(tag_pool)
    if random.random() < indpb:
        ind[1] = random.choice(event_pool)
    if random.random() < indpb:
        ind[2] = mutate_js(ind[2], js_pool)
    return (ind,)


def mutate_js(js, js_pool):
    """Safe JS mutation: shuffle, splice, or append."""
    if random.random() < 0.33:
        return js[::-1]  # reverse
    if random.random() < 0.33:
        return js + random.choice(js_pool)
    return random.choice(js_pool)


def component_render(ind):
    """Convert components into a final payload."""
    tag, event, js = ind
    return f"{tag} {event}\"{js}\">"
