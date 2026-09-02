import os
import time
from collections import defaultdict
from flask import Flask, jsonify, request

app = Flask(__name__)

# Configuration
BLOCKED_FILE = os.path.expanduser("~/ai_server_defense/blocked_ips.txt")
DEFENSE_LOG = os.path.expanduser("~/ai_server_defense/defense_log.txt")

# Rate Limiting Configuration (Sliding Window)
RATE_LIMIT_WINDOW = 5.0  # Time window in seconds
MAX_REQUESTS_PER_WINDOW = 10  # Maximum requests allowed per window per IP
ip_request_history = defaultdict(list)

def log_request(client_ip, status_code):
    timestamp = time.strftime("[%d/%b/%Y:%H:%M:%S %z]")
    log_entry = f"{client_ip} - - {timestamp} \"{request.method} {request.path} HTTP/1.1\" {status_code} 0\n"
    with open(DEFENSE_LOG, "a") as f:
        f.write(log_entry)

@app.before_request
def apply_defense_layers():
    client_ip = request.remote_addr
    current_time = time.time()

    # Layer 1: Check AI Blocklist File
    if os.path.exists(BLOCKED_FILE):
        with open(BLOCKED_FILE, "r") as f:
            blocked_ips = {line.strip() for line in f if line.strip()}
            if client_ip in blocked_ips:
                log_request(client_ip, 429)
                return jsonify({
                    "error": "HTTP 429 Too Many Requests",
                    "message": "Blocked by AI Anomaly Detection Engine"
                }), 429

    # Layer 2: Sliding Window Rate Limiter
    timestamps = ip_request_history[client_ip]
    # Remove timestamps older than the window threshold
    ip_request_history[client_ip] = [t for t in timestamps if current_time - t <= RATE_LIMIT_WINDOW]

    if len(ip_request_history[client_ip]) >= MAX_REQUESTS_PER_WINDOW:
        log_request(client_ip, 429)
        return jsonify({
            "error": "HTTP 429 Too Many Requests",
            "message": "Rate limit exceeded. Please slow down your requests."
        }), 429

    # Record current valid request timestamp
    ip_request_history[client_ip].append(current_time)

@app.after_request
def log_successful_request(response):
    if response.status_code != 429:
        log_request(request.remote_addr, response.status_code)
    return response

@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def catch_all(path):
    return jsonify({"status": "success", "endpoint": path}), 200

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000)
