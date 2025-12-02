# seed_loader.py
def load_seed_pools(path):
    tags = []
    events = []
    js = []

    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line: continue

            if line.startswith("TAG:"):
                tags.append(line.replace("TAG:", "").strip())
            elif line.startswith("EVENT:"):
                events.append(line.replace("EVENT:", "").strip())
            elif line.startswith("JS:"):
                js.append(line.replace("JS:", "").strip())

    return {"tags": tags, "events": events, "js": js}
