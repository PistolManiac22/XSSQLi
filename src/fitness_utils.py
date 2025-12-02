import difflib
import re

def compute_survivability(payload, reflected_html):
    if not reflected_html:
        return 0.0
    ratio = difflib.SequenceMatcher(None, payload, reflected_html).ratio()
    return ratio * 30.0

def compute_structure(payload):
    score = 0
    p = payload.lower()

    if "<" in p: score += 2
    if ">" in p: score += 2
    if "=" in p: score += 2

    if payload.count('"') % 2 == 0: score += 2
    if payload.count("'") % 2 == 0: score += 2

    if re.search(r"\w+\s*=", payload): score += 4

    if "(" in payload and ")" in payload: score += 3

    return score
