"""
ELPATI BACKEND - Core Application Logic & State Management
Central backend orchestration
"""
import json, time, threading
from pathlib import Path
from datetime import datetime

class ElpatiBackend:
    def __init__(self):
        from elpati.elpati_log import ElpatiLog
        from elpati.elpati_crypto import ElpatiCrypto
        self.log = ElpatiLog()
        self.crypto = ElpatiCrypto()
        self._state = {
            "started_at": datetime.utcnow().isoformat(),
            "scan_count": 0, "threats_found": 0, "quarantined": 0,
            "protection_active": False, "current_user": None,
            "license": "COMMUNITY"
        }
        self._lock = threading.Lock()
        self._state_file = Path(__file__).parent.parent / "security" / "state.json"
        self._load_state()

    def _load_state(self):
        if self._state_file.exists():
            try:
                saved = json.loads(self._state_file.read_text())
                self._state.update({k: v for k, v in saved.items()
                                    if k in ("scan_count", "threats_found", "quarantined", "license")})
            except:
                pass

    def _save_state(self):
        try:
            self._state_file.parent.mkdir(parents=True, exist_ok=True)
            self._state_file.write_text(json.dumps(self._state, indent=2))
        except:
            pass

    def update_state(self, key: str, value):
        with self._lock:
            self._state[key] = value
            self._save_state()

    def increment(self, key: str, by: int = 1):
        with self._lock:
            self._state[key] = self._state.get(key, 0) + by
            self._save_state()

    def get_state(self) -> dict:
        with self._lock:
            return dict(self._state)

    def set_license(self, tier: str):
        valid = ("COMMUNITY", "PROFESSIONAL", "ENTERPRISE")
        if tier not in valid:
            raise ValueError(f"Invalid license tier: {tier}")
        self.update_state("license", tier)
        self.log.audit(f"License updated to: {tier}")

    def get_license_features(self) -> dict:
        tier = self._state.get("license", "COMMUNITY")
        features = {
            "COMMUNITY": {
                "quick_scan": True, "full_scan": True, "realtime_monitor": False,
                "memory_scan": False, "network_guard": False, "ai_analyzer": False,
                "forensic": False, "max_schedules": 0
            },
            "PROFESSIONAL": {
                "quick_scan": True, "full_scan": True, "realtime_monitor": True,
                "memory_scan": True, "network_guard": True, "ai_analyzer": True,
                "forensic": True, "max_schedules": 5
            },
            "ENTERPRISE": {
                "quick_scan": True, "full_scan": True, "realtime_monitor": True,
                "memory_scan": True, "network_guard": True, "ai_analyzer": True,
                "forensic": True, "max_schedules": -1, "siem_export": True,
                "multi_endpoint": True
            }
        }
        return features.get(tier, features["COMMUNITY"])
