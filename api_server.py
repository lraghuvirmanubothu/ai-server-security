import os
from flask import Flask, jsonify, request

app = Flask(__name__)
BLOCKED_FILE = "blocked_ips.txt"

def is_ip_blocked(client_ip):
    if os.path.exists(BLOCKED_FILE):
        with open(BLOCKED_FILE, "r") as f:
            blocked_ips = [line.strip() for line in f.readlines()]
            return client_ip in blocked_ips or "::1" in blocked_ips or "127.0.0.1" in blocked_ips
    return False

@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def catch_all(path):
    if is_ip_blocked(request.remote_addr):
        return jsonify({
            "error": "HTTP 429 Too Many Requests",
            "message": "Blocked by AI Anomaly Detection Engine"
        }), 429
    return jsonify({"status": "success", "endpoint": path}), 200

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000)
