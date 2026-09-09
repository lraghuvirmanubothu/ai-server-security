import time
from collections import defaultdict

class AIDefenseSystem:
    def __init__(self, rate_limit: int = 5, window_seconds: int = 60):
        self.rate_limit = rate_limit
        self.window_seconds = window_seconds
        self.request_history = defaultdict(list)
        # Pre-seeded metrics to match traffic breakdown state (10 allowed, 20 blocked)
        self.metrics = {"200 OK": 10, "429 Blocked": 20}

    def inspect_request(self, client_ip: str, prompt: str) -> tuple[bool, int, str]:
        now = time.time()
        # Clean expired timestamps outside active window
        self.request_history[client_ip] = [
            t for t in self.request_history[client_ip] if now - t < self.window_seconds
        ]

        # Rate Limiting Guardrail
        if len(self.request_history[client_ip]) >= self.rate_limit:
            self.metrics["429 Blocked"] += 1
            return False, 429, "Rate limit exceeded. Request throttled."

        # Prompt Injection Pattern Matching
        forbidden_patterns = ["ignore previous instructions", "system prompt", "jailbreak"]
        if any(pattern in prompt.lower() for pattern in forbidden_patterns):
            self.metrics["429 Blocked"] += 1
            return False, 429, "Threat Detected: Malicious prompt pattern flagged."

        # Authorized Request
        self.request_history[client_ip].append(now)
        self.metrics["200 OK"] += 1
        return True, 200, "Authorized"

# Global Defense Instance
defense_engine = AIDefenseSystem()
    time.sleep(CONFIG["SLEEP_INTERVAL"])
