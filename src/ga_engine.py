from deap import base, creator, tools
import random
import urllib.parse

try:
    creator.create("FitnessMultiExec", base.Fitness, weights=(1.0, 1.0, 10.0))
except: pass

try:
    creator.create("Individual", list, fitness=creator.FitnessMultiExec)
except: pass

def component_render(ind):
    tag, event, js = ind
    if tag and "script" in tag.lower():
        t = tag if tag.startswith("<") else "<" + tag
        if not t.endswith(">"):
            t += ">"
        return f"{t}{js}</script>"
    elif tag and event:
        t = tag if tag.startswith("<") else "<" + tag
        if not t.endswith(">"):
            t += ">"
        return f'{t[:-1]} {event}"{js}">'
    elif js:
        return f"javascript:{js}"
    else:
        return tag or event or js

def mut_case_random(s, prob=0.5):
    if not s: return s
    return "".join(ch.swapcase() if ch.isalpha() and random.random() < prob else ch for ch in s)

def mut_split_insert(s):
    if not s or len(s) < 2:
        return s
    pos = random.randint(1, len(s)-1)
    return s[:pos] + random.choice(["", "/", "/*x*/", " "]) + s[pos:]

def encode_html_ent(s):
    return s.replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;").replace("'", "&#39;")

def percent_encode(s):
    return urllib.parse.quote(s, safe='')

def mut_structured_universal(ind, tag_pool, event_pool, js_pool):
    idx = random.randrange(3)

    if idx == 0:
        ind[0] = random.choice(tag_pool)
    elif idx == 1:
        ind[1] = random.choice(event_pool)
    else:
        ind[2] = random.choice(js_pool)

    return (ind,)

def cx_components_swap(ind1, ind2):
    i = random.randrange(3)
    ind1[i], ind2[i] = ind2[i], ind1[i]
    return ind1, ind2

def setup_ga(tag_pool, event_pool, js_pool):
    toolbox = base.Toolbox()
    toolbox.register("tag_gene", lambda: random.choice(tag_pool))
    toolbox.register("event_gene", lambda: random.choice(event_pool))
    toolbox.register("js_gene", lambda: random.choice(js_pool))
    
    def gen_ind():
        return creator.Individual([toolbox.tag_gene(), toolbox.event_gene(), toolbox.js_gene()])
    
    toolbox.register("individual", gen_ind)
    toolbox.register("population", tools.initRepeat, list, toolbox.individual)
    toolbox.register("mate", cx_components_swap)
    toolbox.register("mutate", lambda ind: mut_structured_universal(ind, tag_pool, event_pool, js_pool))
    toolbox.register("select", tools.selNSGA2)

    return toolbox
