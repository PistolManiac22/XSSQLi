from deap import base, creator, tools
import random

def setup_ga():
    creator.create("FitnessMax", base.Fitness, weights=(1.0,))
    creator.create("Individual", list, fitness=creator.FitnessMax)

    toolbox = base.Toolbox()
    toolbox.register("char", lambda: chr(random.randint(32, 126)))
    toolbox.register("individual", tools.initRepeat, creator.Individual, toolbox.char, 40)
    toolbox.register("population", tools.initRepeat, list, toolbox.individual)

    toolbox.register("select", tools.selTournament, tournsize=3)
    toolbox.register("mate", tools.cxTwoPoint)
    toolbox.register("mutate", tools.mutShuffleIndexes, indpb=0.05)

    return toolbox

def create_individual_from_seed(seed):
    return creator.Individual(list(seed))