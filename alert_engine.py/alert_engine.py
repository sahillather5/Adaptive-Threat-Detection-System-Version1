import time
from datetime import datetime


class AlertEngine:

    def __init__(self):
        self.suppression_window = 300  # 5 minutes
        self.recent_alerts      = {}

    def map_severity(self, risk_score):
        if risk_score <= 20:   return "VERY LOW"
        elif risk_score <= 40: return "LOW"
        elif risk_score <= 60: return "MEDIUM"
        elif risk_score <= 80: return "HIGH"
        else:                  return "CRITICAL"

    def should_alert(self, risk_score):
        return risk_score > 40

    def suppress_duplicate(self, user_hash, severity):
        key = f"{user_hash}:{severity}"
        now = time.time()
        if key in self.recent_alerts:
            if (now - self.recent_alerts[key]
                    < self.suppression_window):
                return True  # suppress
        self.recent_alerts[key] = now
        return False

    def generate_alert(self, risk_output):
        risk_score = risk_output["risk_score"]
        user_hash  = risk_output["user_hash"]

        if not self.should_alert(risk_score):
            return None

        severity = self.map_severity(risk_score)

        if self.suppress_duplicate(user_hash, severity):
            return None

        return {
            "alert_id":  f"ALERT-{int(time.time())}",
            "timestamp": datetime.utcnow().isoformat(),
            "user_hash": user_hash,
            "severity":  severity,
            "risk_score": risk_score,
            "risk_level": risk_output["risk_level"],
            "confidence": risk_output["confidence"],
            # FIX: v > 0 catches binary 1 values correctly
            # Old code used v > 0.5 which was inconsistent
            "anomaly_sources": [
                k for k, v
                in risk_output["anomaly_vector"].items()
                if v > 0
            ],
            "status":          "OPEN",
            "category":        "Behavioral Anomaly",
            "action_required": self.recommended_action(
                severity),
        }

    def recommended_action(self, severity):
        policy = {
            "VERY LOW": "LOG_ONLY",
            "LOW":      "MONITOR",
            "MEDIUM":   "FLAG_FOR_REVIEW",
            "HIGH":     "SOC_ALERT",
            "CRITICAL": "IMMEDIATE_RESPONSE",
        }
        return policy.get(severity, "LOG_ONLY")


if __name__ == "__main__":
    engine = AlertEngine()
    sample = {
        "user_hash":   "H123",
        "risk_score":  73.4,
        "risk_level":  "HIGH",
        "confidence":  0.86,
        "anomaly_vector": {
            "time": 1, "geo": 1, "device": 1,
            "fail": 1, "frequency": 0,
            "session": 0, "sequence": 0
        },
        "timestamp": time.time()
    }
    alert = engine.generate_alert(sample)
    print("\n--- ALERT OUTPUT ---")
    print(alert)