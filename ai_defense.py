import os
import time
from sklearn.ensemble import IsolationForest

CONFIG = {
    "DEFENSE_LOG": os.path.expanduser("~/ai_server_defense/defense_log.txt"),
    "BLOCKED_FILE": os.path.expanduser("~/ai_server_defense/blocked_ips.txt"),
    "THRESHOLD_COUNT": 15,
    "SLEEP_INTERVAL": 0.2
}

model = IsolationForest(contamination=0.1, random_state=42)
X_train = [[1, 2000], [2, 1500], [3, 1000], [50, 2], [100, 1]]
model.fit(X_train)

print("🛡️ AI Anomaly Detection Engine Started...")

while True:
    log_path = CONFIG["DEFENSE_LOG"]
    if os.path.exists(log_path):
        try:
            with open(log_path, "r") as f:
                lines = [line.strip() for line in f.readlines()[-200:] if line.strip()]

            if lines:
                ip_counts = {}
                for line in lines:
                    parts = line.split()
                    if parts:
                        ip = parts[0]
                        ip_counts[ip] = ip_counts.get(ip, 0) + 1

                blocked_ips = set()
                if os.path.exists(CONFIG["BLOCKED_FILE"]):
                    with open(CONFIG["BLOCKED_FILE"], "r") as bf:
                        blocked_ips.update([line.strip() for line in bf if line.strip()])

                for ip, count in ip_counts.items():
                    estimated_gap = 1000 / count if count > 0 else 5000
                    prediction = model.predict([[count, estimated_gap]])

                    if prediction[0] == -1 and count > CONFIG["THRESHOLD_COUNT"]:
                        blocked_ips.add(ip)
                        print(f"⚠️ [ATTACK DETECTED] IP {ip} exceeded rate thresholds! Count: {count}")

                with open(CONFIG["BLOCKED_FILE"], "w") as bf:
                    for b_ip in blocked_ips:
                        bf.write(f"{b_ip}\n")

        except Exception as e:
            print(f"ERROR: {e}")

    time.sleep(CONFIG["SLEEP_INTERVAL"])
