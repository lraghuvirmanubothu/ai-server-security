import os
import time
from sklearn.ensemble import IsolationForest

LOG_FILE = "/var/log/apache2/access.log"
BLOCKED_FILE = os.path.expanduser("~/ai_server_defense/blocked_ips.txt")

# Initialize and train Isolation Forest
model = IsolationForest(contamination=0.1, random_state=42)
X_train = [[1, 2000], [2, 1500], [3, 1000], [50, 2], [100, 1]]
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
                        if ip in ["::1", "127.0.0.1", "localhost"]:
                            ip = "127.0.0.1"
                        ip_counts[ip] = ip_counts.get(ip, 0) + 1

                blocked = []
                for ip, count in ip_counts.items():
                    estimated_gap = 1000 / count if count > 0 else 5000
                    prediction = model.predict([[count, estimated_gap]])

                    # Threshold check: model anomaly detection + volume condition
                    if prediction[0] == -1 and count > 15:
                        blocked.extend(["127.0.0.1", "::1", "localhost"])
                        print(f"⚠️ [ATTACK DETECTED] High volume burst from {ip}! Count: {count}")

                with open(BLOCKED_FILE, "w") as bf:
                    for b_ip in set(blocked):
                        bf.write(f"{b_ip}\n")

        except Exception as e:
            print(f"ERROR: {e}")
    else:
        print(f"ERROR: File {LOG_FILE} does not exist!")

    time.sleep(1)
