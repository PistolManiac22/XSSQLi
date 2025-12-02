# fitness_moga.py
from src.send_request import send_payload
import re
import math
from difflib import SequenceMatcher

def evaluate(ind, url, param):
    payload = f"{ind[0]} {ind[1]}\"{ind[2]}\">"
    html = send_payload(url, param, payload)

    survivability = score_survivability(payload, html)
    structure = score_structure(payload)

    return (survivability, structure)


# -----------------------------
# Objective 1 — survivability
# -----------------------------
def score_survivability(payload, html):
    score = 0.0

    # reflected?
    if payload in html:
        score += 15

    # char survival
    survived = sum(1 for c in payload if c in html)
    score += survived * 0.1

    # encoding survival
    enc_count = len(re.findall(r"%[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4}", payload))
    score += enc_count * 0.2

    # transformation similarity
    ratio = SequenceMatcher(None, payload.lower(), html.lower()).ratio()
    score += ratio * 5

    return score


# -----------------------------
# Objective 2 — structure
# -----------------------------
def score_structure(payload):
    score = 0.0
    lower = payload.lower()

    # Reward meaningful structure
    if "<script" in lower: score += 8
    if "<img" in lower: score += 6
    if "<svg" in lower: score += 6

    # event handlers
    events = ["onerror=", "onload=", "onmouseover=", "onclick="]
    score += sum(5 for e in events if e in lower)

    # JS atoms
    if "alert" in lower: score += 5
    if "console.log" in lower: score += 5

    # penalties for over-encoding
    enc_ratio = len(re.findall(r"%[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4}", payload)) / max(len(payload), 1)
    if enc_ratio > 0.5: score -= 10

    # shorter payloads preferred
    if len(payload) > 120: score -= 20
    elif len(payload) > 80: score -= 10

    return score
