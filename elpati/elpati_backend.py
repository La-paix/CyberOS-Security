"""
ELPATI BACKEND - Core Application Logic & State Management
Central backend orchestration
"""
import json, time, threading
from utils.storage import write_json
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
                saved = json.loads(self._state_file.read_text(encoding="utf-8"))
                self._state.update({k: v for k, v in saved.items()
                                    if k in ("scan_count", "threats_found", "quarantined", "license")})
            except:
                pass

    def _save_state(self):
        write_json(self._state_file, self._state)

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

    def get_license_features(self):
        from elpati.elpati_payment import ElpatiPayment
        return dict(ElpatiPayment().get_info()["matrix"])
