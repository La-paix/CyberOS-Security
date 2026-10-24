"""
ELPATI PAYMENT v2 - Advanced License Management
Auto-generation, anti-crack, tiered access, offline validation
"""
import json, hashlib, time, base64, uuid, platform
from pathlib import Path
from datetime import datetime, timedelta

LIC_DIR = Path(__file__).parent.parent / "security" / "keys"
LIC_DIR.mkdir(parents=True, exist_ok=True)

# License tiers with feature matrix
LICENSE_MATRIX = {
    "FREE": {
        "display": "Gratuit / Free",
        "price": "0€",
        "quick_scan": True,
        "full_scan": False,
        "realtime_monitor": False,
        "memory_scan": False,
        "network_guard": False,
        "ai_analyzer": False,
        "forensic": False,
        "ransomguard": False,
        "sandbox": False,
        "api_ai": False,
        "quarantine": True,
        "max_files_scan": 5000,
        "max_schedules": 0,
        "reports": False,
        "multi_lang": True,
        "themes": True,
        "support": "Community",
        "updates": "Manual",
        "description": "Protection de base - Scan rapide uniquement",
    },
    "PRO": {
        "display": "Professionnel / Professional",
        "price": "49€/an",
        "quick_scan": True,
        "full_scan": True,
        "realtime_monitor": True,
        "memory_scan": True,
        "network_guard": True,
        "ai_analyzer": True,
        "forensic": True,
        "ransomguard": True,
        "sandbox": True,
        "api_ai": True,
        "quarantine": True,
        "max_files_scan": -1,
        "max_schedules": 10,
        "reports": True,
        "multi_lang": True,
        "themes": True,
        "support": "Email 48h",
        "updates": "Automatique",
        "description": "EDR complet - Toutes fonctionnalités de protection",
    },
    "ENTERPRISE": {
        "display": "Entreprise / Enterprise",
        "price": "199€/an",
        "quick_scan": True,
        "full_scan": True,
        "realtime_monitor": True,
        "memory_scan": True,
        "network_guard": True,
        "ai_analyzer": True,
        "forensic": True,
        "ransomguard": True,
        "sandbox": True,
        "api_ai": True,
        "quarantine": True,
        "max_files_scan": -1,
        "max_schedules": -1,
        "reports": True,
        "multi_lang": True,
        "themes": True,
        "support": "Priorité 24h",
        "updates": "Automatique",
        "siem_export": True,
        "multi_endpoint": True,
        "white_label": True,
        "description": "Solution complète entreprise multi-postes",
    }
}

SECRET = "CYBEROS_ELPATI_2026_LICENSE_SECRET_KEY_v2_ANTICRACK"

class ElpatiPayment:
    _instance = None
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._init_done = False
        return cls._instance

    def __init__(self):
        if self._init_done: return
        self._init_done = True
        from elpati.elpati_crypto import ElpatiCrypto
        from elpati.elpati_log import ElpatiLog
        self.crypto = ElpatiCrypto()
        self.log = ElpatiLog()
        self._lic_file = LIC_DIR / "license.lic"
        self._current = self._load()

    def _load(self) -> dict:
        if self._lic_file.exists():
            try:
                raw = self.crypto.decrypt(self._lic_file.read_bytes())
                return json.loads(raw)
            except: pass
        return {"tier": "FREE", "issued": datetime.utcnow().isoformat(),
                "expires": None, "key": "", "machine_id": self._machine_id(),
                "activations": 0}

    def _save(self):
        data = json.dumps(self._current).encode()
        self._lic_file.write_bytes(self.crypto.encrypt(data))

    def _machine_id(self) -> str:
        """Generate a hardware-bound machine fingerprint."""
        parts = [platform.node(), platform.machine(), platform.processor()]
        raw = "|".join(parts).encode()
        return hashlib.sha256(raw).hexdigest()[:16]

    def _make_key_hash(self, tier_code: str, expiry_hex: str, machine_id: str = "") -> str:
        payload = f"{tier_code}:{expiry_hex}:{machine_id}:{SECRET}"
        return hashlib.sha3_256(payload.encode()).hexdigest()[:12].upper()

    # ─── KEY GENERATION ──────────────────────────────────────────────────────

    def generate_key(self, tier: str = "PRO", days: int = 365,
                     bind_machine: bool = False) -> str:
        """
        Generate a license key.
        Format: CYBEROS-{TIER}-{DAYS_HEX}-{HASH}-{SUFFIX}
        """
        tier_code = {"FREE": "FRE", "PRO": "PRO", "ENTERPRISE": "ENT"}.get(tier, "PRO")
        expiry_hex = format(days, "04X")
        machine = self._machine_id() if bind_machine else "GLOBAL"
        key_hash = self._make_key_hash(tier_code, expiry_hex, machine)
        suffix = base64.b32encode(uuid.uuid4().bytes[:5]).decode().rstrip("=")
        key = f"CYBEROS-{tier_code}-{expiry_hex}-{key_hash}-{suffix}"
        self.log.audit(f"License key generated: tier={tier} days={days} bind={bind_machine}")
        return key

    def generate_demo_key(self) -> str:
        """Generate a 7-day PRO demo key."""
        return self.generate_key("PRO", 7)

    def generate_trial_key(self, days: int = 30) -> str:
        return self.generate_key("PRO", days)

    def generate_enterprise_key(self, days: int = 365) -> str:
        return self.generate_key("ENTERPRISE", days)

    # ─── KEY VALIDATION ──────────────────────────────────────────────────────

    def validate_key(self, key: str) -> dict:
        """Validate a license key offline."""
        try:
            parts = key.strip().upper().split("-")
            if len(parts) != 5 or parts[0] != "CYBEROS":
                return {"valid": False, "error": "Format invalide"}
            _, tier_code, expiry_hex, key_hash, suffix = parts
            # Try global first, then machine-bound
            expected_global = self._make_key_hash(tier_code, expiry_hex, "GLOBAL")
            expected_machine = self._make_key_hash(tier_code, expiry_hex, self._machine_id())
            if key_hash not in (expected_global, expected_machine):
                return {"valid": False, "error": "Clé invalide ou falsifiée"}
            tier_map = {"FRE": "FREE", "PRO": "PRO", "ENT": "ENTERPRISE"}
            tier = tier_map.get(tier_code)
            if not tier:
                return {"valid": False, "error": "Tier inconnu"}
            days = int(expiry_hex, 16)
            return {"valid": True, "tier": tier, "days": days,
                    "machine_bound": key_hash == expected_machine}
        except Exception as e:
            return {"valid": False, "error": str(e)}

    def activate(self, key: str) -> dict:
        """Activate a license key."""
        result = self.validate_key(key)
        if not result["valid"]:
            self.log.warning(f"License activation failed: {result['error']}")
            return {"success": False, "error": result["error"]}
        expiry = (datetime.utcnow() + timedelta(days=result["days"])).isoformat()
        self._current = {
            "tier": result["tier"], "key": key,
            "issued": datetime.utcnow().isoformat(),
            "expires": expiry, "machine_id": self._machine_id(),
            "activations": self._current.get("activations", 0) + 1
        }
        self._save()
        self.log.audit(f"License activated: {result['tier']} expires={expiry}")
        return {"success": True, "tier": result["tier"],
                "expires": expiry, "days": result["days"]}

    def is_valid(self) -> bool:
        if self._current["tier"] == "FREE": return True
        if not self._current.get("expires"): return True
        try:
            return datetime.utcnow() < datetime.fromisoformat(self._current["expires"])
        except: return False

    def get_tier(self) -> str:
        return self._current["tier"] if self.is_valid() else "FREE"

    def has_feature(self, feature: str) -> bool:
        tier = self.get_tier()
        matrix = LICENSE_MATRIX.get(tier, LICENSE_MATRIX["FREE"])
        return bool(matrix.get(feature, False))

    def get_info(self) -> dict:
        info = dict(self._current)
        info.pop("key", None)
        info["valid"] = self.is_valid()
        info["matrix"] = LICENSE_MATRIX.get(self.get_tier(), {})
        info["days_remaining"] = self._days_remaining()
        return info

    def _days_remaining(self) -> int:
        if not self._current.get("expires"): return 9999
        try:
            delta = datetime.fromisoformat(self._current["expires"]) - datetime.utcnow()
            return max(0, delta.days)
        except: return 0

    def get_matrix(self) -> dict:
        return LICENSE_MATRIX

    def get_all_keys_preview(self) -> list:
        """Generate preview keys for all tiers (admin use)."""
        return [
            {"tier": "FREE",       "key": self.generate_key("FREE", 36500), "note": "Perpétuel"},
            {"tier": "PRO",        "key": self.generate_key("PRO", 365),    "note": "1 an"},
            {"tier": "PRO",        "key": self.generate_key("PRO", 30),     "note": "30 jours"},
            {"tier": "ENTERPRISE", "key": self.generate_key("ENTERPRISE", 365), "note": "1 an"},
        ]
