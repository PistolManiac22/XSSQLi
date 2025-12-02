def load_seed_payloads(filepath):
    with open(filepath, "r", encoding="utf-8") as file:
        payloads = [line.strip() for line in file.readlines()]
    return payloads