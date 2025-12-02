from src.send_request import send_payload

def evaluate(individual, url, param):
    payload = "".join(individual)
    response = send_payload(url, param, payload)

    # Fitness check: apakah payload muncul kembali di response
    if payload.lower() in response.lower():
        return 1.0,   # success
    return 0.0,       # fail