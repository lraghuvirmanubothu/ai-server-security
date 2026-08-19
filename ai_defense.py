import os
import time
import pandas as pd
from sklearn.ensemble import IsolationForest

LOG_FILE = "/var/log/apache2/access.log"
BLOCKED_FILE = "blocked_ips.txt"

model = IsolationForest(contamination=0.1, random_state=42)

# Training data: [Request Count, Avg Time Gap (ms)]
X_train = [
    [1, 2000], [2, 1500], [1, 3000], [3, 1000],  # Normal traffic
    [50, 2],   [100, 1],  [200, 0.5]             # DoS traffic
]
model.fit(X_train)

print("🛡️ AI Anomaly Detection Engine Started...")

while True:
    if os.path.exists(LOG_FILE):
        try:
            with open(LOG_FILE, "r") as f:
                lines = [line.strip() for line in f.readlines()[-100:] if line.strip()]

            if lines:
                ip_counts = {}
                for line in lines:
                    parts = line.split()
                    if parts:
                        ip = parts[0]
                        ip_counts[ip] = ip_counts.get(ip, 0) + 1

                blocked = []
                for ip, count in ip_counts.items():
                    estimated_gap = 1000 / count if count > 0 else 5000
                    prediction = model.predict([[count, estimated_gap]])

                    if prediction[0] == -1 and count > 15:
                        blocked.append(ip)
                        print(f"⚠️ [ANOMALY DETECTED] IP {ip} triggered DoS pattern! Recent requests: {count}")

                with open(BLOCKED_FILE, "w") as bf:
                    for b_ip in blocked:
                        bf.write(f"{b_ip}\n")

        except Exception as e:
            print(f"Error processing log: {e}")

    time.sleep(1)
