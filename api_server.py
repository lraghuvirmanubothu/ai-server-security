import os
from flask import Flask, jsonify, request

app = Flask(__name__)
BLOCKED_FILE = os.path.expanduser("~/ai_server_defense/blocked_ips.txt")

@app.before_request
def check_ip_block():
    client_ip = request.remote_addr
    
    if os.path.exists(BLOCKED_FILE):
        with open(BLOCKED_FILE, "r") as f:
            blocked_ips = [line.strip() for line in f.readlines() if line.strip()]
            
            print(f"[FIREWALL CHECK] Client IP: {client_ip} | Blocklist: {blocked_ips}")
            
            if client_ip in blocked_ips or "127.0.0.1" in blocked_ips or "::1" in blocked_ips or "localhost" in blocked_ips:
                print("🚫 ACCESS DENIED: Returning 429")
                return jsonify({
                    "error": "HTTP 429 Too Many Requests",
                    "message": "Blocked by AI Anomaly Detection Engine"
                }), 429

@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def catch_all(path):
    return jsonify({"status": "success", "endpoint": path}), 200

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000)
