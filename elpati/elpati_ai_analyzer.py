"""
ELPATI AI ANALYZER - Local Behavioral AI & Anomaly Detection
Uses statistical models and heuristics (no internet required)
"""
import math, time, json
from collections import defaultdict, deque
from datetime import datetime

class ElpatiAIAnalyzer:
    def __init__(self):
        from elpati.elpati_log import ElpatiLog
        self.log = ElpatiLog()
        self._baselines = {}
        self._anomaly_scores = deque(maxlen=1000)
        self._model_file = None
        self._stats = {"analyzed": 0, "anomalies": 0}

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
        }

        for indicator, value in indicators.items():
            if indicator in weights and value:
                w = weights[indicator]
                if isinstance(value, (int, float)):
                    contribution = min(w, w * value / 100)
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
        """Heuristic file analysis without signature matching."""
        import os
        from pathlib import Path
        indicators = {}
        notes = []

        try:
            p = Path(filepath)
            if not p.exists():
                return {"error": "File not found"}

            stat = p.stat()
            ext = p.suffix.lower()
            size = stat.st_size

            # Check extension vs content mismatch
            try:
                with open(filepath, "rb") as f:
                    magic = f.read(4)
                if ext in [".jpg", ".jpeg"] and magic[:2] != b'\xff\xd8':
                    indicators["extension_mismatch"] = True
                    notes.append("Extension mismatch: not a real JPEG")
                if ext in [".pdf"] and magic[:4] != b'%PDF':
                    indicators["extension_mismatch"] = True
                    notes.append("Extension mismatch: not a real PDF")
                if ext in [".png"] and magic[:4] != b'\x89PNG':
                    indicators["extension_mismatch"] = True
            except:
                pass

            # Check for executable in unexpected location
            if ext in [".exe", ".dll", ".sys", ".scr"]:
                suspicious_paths = ["temp", "tmp", "appdata", "downloads", "documents"]
                path_lower = str(p).lower()
                if any(s in path_lower for s in suspicious_paths):
                    indicators["suspicious_location"] = True
                    notes.append(f"Executable in suspicious path: {filepath}")

            # Check file size anomalies
            if ext in [".txt", ".log"] and size > 50 * 1024 * 1024:
                indicators["anomalous_size"] = True

            # Entropy check
            from elpati.elpati_ransom_guard import ElpatiRansomGuard
            entropy_result = ElpatiRansomGuard().check_file_entropy(filepath)
            if entropy_result.get("suspected_encrypted"):
                indicators["high_entropy_file"] = True
                notes.append(f"High entropy: {entropy_result['entropy']:.2f}")

            # String scan
            try:
                with open(filepath, "rb") as f:
                    content = f.read(1024 * 1024)  # First 1MB
                from elpati.elpati_threat_intel import ElpatiThreatIntel
                ti_results = ElpatiThreatIntel().scan_strings(
                    content.decode("utf-8", errors="replace"))
                if ti_results:
                    indicators["suspicious_string"] = True
                    notes.extend([r.get("name", r.get("match", "")) for r in ti_results[:3]])
            except:
                pass

            result = self.calculate_threat_score(indicators)
            result["filepath"] = filepath
            result["notes"] = notes
            return result

        except Exception as e:
            return {"error": str(e), "filepath": filepath}

    def get_stats(self):
        return self._stats
