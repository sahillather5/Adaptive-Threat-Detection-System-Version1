import math


class RiskScoringEngine:

    def __init__(self):
        # Weight matrix — must sum ≈ 1.0
        self.weights = {
            "time":      0.12,
            "geo":       0.22,
            "device":    0.18,
            "fail":      0.25,
            "frequency": 0.08,
            "session":   0.07,
            "sequence":  0.08,
        }
        self.alpha         = 0.6   # recency bias
        self.previous_risk = 0.0   # temporal memory

    def calculate_risk(self, features):
        """
        features: dict with keys matching self.weights.
        Values should be 0–1 (binary or normalized).
        Returns risk score 0–100.
        """
        score = sum(
            self.weights[k] * features.get(k, 0)
            for k in self.weights
        ) * 100

        # Temporal accumulation — recent events carry more weight
        final_risk = (
            self.alpha * score +
            (1 - self.alpha) * self.previous_risk
        )
        self.previous_risk = final_risk
        return round(final_risk, 2)

    def risk_level(self, score):
        if score <= 20:   return "VERY LOW"
        elif score <= 40: return "LOW"
        elif score <= 60: return "MEDIUM"
        elif score <= 80: return "HIGH"
        else:             return "CRITICAL"

    def confidence_score(self, features):
        """
        Higher confidence = more anomaly signals agree.
        Low variance = consistent signal = higher confidence.
        """
        values   = list(features.values())
        mean     = sum(values) / len(values)
        variance = sum(
            (x - mean) ** 2 for x in values
        ) / len(values)
        # Normalize: 0 variance = 1.0 confidence
        confidence = 1 - min(variance, 1.0)
        return round(max(confidence, 0), 2)


if __name__ == "__main__":
    engine   = RiskScoringEngine()
    features = {
        "time": 0.9, "geo": 1.0, "device": 1.0,
        "fail": 0.7, "frequency": 0.2,
        "session": 0.1, "sequence": 0.4
    }
    risk_score = engine.calculate_risk(features)
    level      = engine.risk_level(risk_score)
    confidence = engine.confidence_score(features)

    print("\n--- Behavioral Risk Output ---")
    print({
        "risk_score": risk_score,
        "risk_level": level,
        "confidence": confidence,
        "features":   features,
    })