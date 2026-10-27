"""
ELPATI AI ANALYZER - Local Behavioral AI & Anomaly Detection
Uses statistical models and heuristics (no internet required)
"""
import math, time, json
from collections import defaultdict, deque
from datetime import datetime

class ElpatiAIAnalyzer:
    def __init__(self, threat_intel=None):
        from elpati.elpati_log import ElpatiLog
        self.log = ElpatiLog()
        self._baselines = {}
        self._anomaly_scores = deque(maxlen=1000)
        self._model_file = None
        self._stats = {"analyzed": 0, "anomalies": 0}
        from elpati.elpati_threat_intel import ElpatiThreatIntel
        self._threat_intel = threat_intel if threat_intel is not None else ElpatiThreatIntel()

    def calculate_threat_score(self, indicators: dict) -> dict:
        """
        Multi-factor threat scoring engine.
        Aggregates indicators into a unified risk score 0-100.
        """
        score = 0
        reasons = []
        weights = {
            "known_malware_hash": 100,
            "malicious_process": 95,
            "ransomware_extension": 90,
            "memory_injection": 85,
            "privilege_escalation": 85,
            "yara_rule_match": 80,
            "suspicious_network": 70,
            "high_entropy_file": 65,
            "suspicious_string": 60,
            "anomalous_behavior": 55,
            "high_cpu_spike": 30,
            "new_autorun": 50,
            "unsigned_executable": 35,
            "hidden_file": 40,
            "suspicious_extension": 45,
            "extension_mismatch": 45,
            "suspicious_location": 20,
            "anomalous_size": 15,
        }

        for indicator, value in indicators.items():
            if indicator in weights and value:
                w = weights[indicator]
                if isinstance(value, bool):
                    contribution = w
                elif isinstance(value, (int, float)):
                    contribution = min(w, max(0, w * value / 100))
                else:
                    contribution = w
                score += contribution
                reasons.append(f"{indicator}: +{contribution:.0f}")

        final_score = min(int(score), 100)
        self._stats["analyzed"] += 1
        if final_score > 60:
            self._stats["anomalies"] += 1

        return {
            "score": final_score,
            "risk_level": self._score_to_level(final_score),
            "reasons": reasons,
            "recommendation": self._get_recommendation(final_score),
            "ts": datetime.utcnow().isoformat()
        }

    def _score_to_level(self, score: int) -> str:
        if score >= 80: return "CRITICAL"
        if score >= 60: return "HIGH"
        if score >= 40: return "MEDIUM"
        if score >= 20: return "LOW"
        return "CLEAN"

    def _get_recommendation(self, score: int) -> str:
        if score >= 80: return "IMMEDIATE ACTION: Isolate and quarantine. Possible active infection."
        if score >= 60: return "HIGH RISK: Investigate immediately. Block and monitor."
        if score >= 40: return "SUSPICIOUS: Detailed analysis recommended."
        if score >= 20: return "LOW RISK: Monitor for further activity."
        return "No action required."

    def analyze_file_heuristic(self, filepath: str) -> dict:
        """Collect bounded static observations; these never confirm infection."""
        from pathlib import Path
        try:
            p = Path(filepath)
            with open(filepath, "rb") as stream:
                sample = stream.read(1024 * 1024)
            from collections import Counter
            entropy_sample = sample[:65536]
            counts = Counter(entropy_sample)
            size = len(entropy_sample)
            entropy = -sum((count / size) * math.log2(count / size) for count in counts.values()) if size else 0
            evidence = self._threat_intel.file_review_patterns(sample.decode("utf-8", errors="replace"), p.suffix.lower())
            score = max((item["score"] for item in evidence), default=0)
            self._stats["analyzed"] += 1
            if evidence:
                self._stats["anomalies"] += 1
            return {"filepath": filepath, "score": score, "risk_level": self._score_to_level(score),
                    "confirmed": False, "review_required": bool(evidence), "evidence": evidence,
                    "sample_entropy": round(entropy, 4), "sample_bytes": len(sample),
                    "notes": [item["name"] for item in evidence],
                    "recommendation": "Examiner les indices statiques; aucune execution ni infection confirmee.",
                    "ts": datetime.utcnow().isoformat()}
        except Exception as e:
            return {"error": str(e), "filepath": filepath}

    def get_stats(self):
        return self._stats
