from flask import Flask, request
import threading

app = Flask(__name__)
EXECUTED = {}

@app.route("/beacon")
def beacon():
    token = request.args.get("token")
    if token:
        EXECUTED[token] = True
    return "OK", 200

def start_beacon_server(host="0.0.0.0", port=5005):
    thread = threading.Thread(
        target=lambda: app.run(host=host, port=port, debug=False, use_reloader=False),
        daemon=True
    )
    thread.start()
    return thread
