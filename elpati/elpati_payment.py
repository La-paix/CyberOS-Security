"""Offline Ed25519 license verification. Issuer private keys never ship here."""
import base64
import hashlib
import json
import platform
from pathlib import Path
from datetime import datetime, timezone
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from utils.storage import atomic_write

ROOT = Path(__file__).resolve().parent.parent
LIC_DIR = ROOT / "security" / "keys"
LIC_DIR.mkdir(parents=True, exist_ok=True)
PUBLIC_KEY_FILE = ROOT / "security" / "license_public_key.pub"

LICENSE_MATRIX = {
    "FREE": {
        "display": "Gratuit / Free",
        "price": "0€",
        "quick_scan": True,
        "full_scan": True,
        "realtime_monitor": False,
        "memory_scan": True,
        "network_guard": False,
        "ai_analyzer": True,
        "forensic": True,
        "ransomguard": False,
        "sandbox": True,
        "api_ai": True,
        "quarantine": True,
        "max_files_scan": -1,
        "max_schedules": -1,
        "reports": True,
        "multi_lang": True,
        "themes": True,
        "support": "Community",
        "updates": "Manual",
        "description": "Outils locaux manuels; surveillance avancée sur licence",
    },
    "PRO": {
        "display": "Professionnel / Professional",
        "price": "À définir par le propriétaire",
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
        "support": "À définir par le propriétaire",
        "updates": "Manuelle",
        "description": "Outils locaux avancés",
    },
    "ENTERPRISE": {
        "display": "Entreprise / Enterprise",
        "price": "À définir par le propriétaire",
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
        "support": "À définir par le propriétaire",
        "updates": "Manuelle",
        "siem_export": False,
        "multi_endpoint": False,
        "white_label": False,
        "description": "Outils locaux, un poste",
    }
}


def decode_part(text):
    return base64.b64decode(text + "=" * (-len(text) % 4), altchars=b"-_", validate=True)


class ElpatiPayment:
    def __init__(self):
        from elpati.elpati_crypto import ElpatiCrypto
        from elpati.elpati_log import ElpatiLog
        self.crypto = ElpatiCrypto()
        self.log = ElpatiLog()
        self._lic_file = LIC_DIR / "license.lic"
        self._current = self._load()

    def _load(self):
        if self._lic_file.exists():
            try:
                value = json.loads(self.crypto.decrypt(self._lic_file.read_bytes()))
                if isinstance(value, dict):
                    return value
            except Exception:
                self.log.warning("Licence locale illisible : mode FREE.")
        return {"tier": "FREE", "issued": None, "expires": None, "key": "",
                "machine_id": self._machine_id(), "activations": 0}

    def _save(self):
        atomic_write(self._lic_file, self.crypto.encrypt(json.dumps(self._current).encode()))

    def _machine_id(self):
        raw = "|".join([platform.node(), platform.machine(), platform.processor()]).encode()
        return hashlib.sha256(raw).hexdigest()[:16]

    def generate_key(self, tier="PRO", days=365, bind_machine=False):
        raise PermissionError("Émission réservée au propriétaire : utiliser vendor_tools/license_issuer.py hors de l'application.")

    def generate_demo_key(self):
        return self.generate_key("PRO", 7)

    def generate_trial_key(self, days=30):
        return self.generate_key("PRO", days)

    def generate_enterprise_key(self, days=365):
        return self.generate_key("ENTERPRISE", days)

    def validate_key(self, key):
        try:
            parts = key.strip().split(".")
            if len(parts) != 3 or parts[0] != "CYBEROS2" or len(key) > 8192:
                raise ValueError("Format invalide. Les anciennes licences doivent être réémises.")
            payload = decode_part(parts[1])
            signature = decode_part(parts[2])
            public = Ed25519PublicKey.from_public_bytes(PUBLIC_KEY_FILE.read_bytes())
            public.verify(signature, payload)
            value = json.loads(payload)
            if set(value) != {"v", "tier", "issued", "expires", "machine_id", "id"}:
                raise ValueError("Champs de licence invalides")
            if value["v"] != 2 or value["tier"] not in LICENSE_MATRIX or not value["id"]:
                raise ValueError("Niveau invalide")
            issued = datetime.fromisoformat(value["issued"])
            expiry = datetime.fromisoformat(value["expires"])
            now = datetime.now(timezone.utc)
            if issued.tzinfo is None or expiry.tzinfo is None or expiry <= issued:
                raise ValueError("Dates invalides")
            if issued.timestamp() > now.timestamp() + 300 or expiry <= now:
                raise ValueError("Licence expirée ou pas encore valide")
            if value["machine_id"] not in ("GLOBAL", self._machine_id()):
                raise ValueError("Cette licence appartient à un autre poste")
            return {"valid": True, **value, "days": max(0, (expiry - now).days),
                    "machine_bound": value["machine_id"] != "GLOBAL"}
        except FileNotFoundError:
            return {"valid": False, "error": "Clé publique du vendeur absente. Le propriétaire doit configurer les licences."}
        except Exception:
            return {"valid": False, "error": "Licence invalide, expirée ou signature incorrecte"}

    def activate(self, key):
        result = self.validate_key(key)
        if not result["valid"]:
            return {"success": False, "error": result["error"]}
        self._current = {k: result[k] for k in ("tier", "issued", "expires")}
        self._current.update(key=key.strip(), machine_id=self._machine_id(), activations=1)
        self._save()
        self.log.audit(f"License activated: {result['tier']}")
        return {"success": True, "tier": result["tier"], "expires": result["expires"], "days": result["days"]}

    def is_valid(self):
        key = self._current.get("key")
        if not key:
            return self._current.get("tier") == "FREE"
        result = self.validate_key(key)
        return (result["valid"] and self._current.get("tier") == result["tier"]
                and self._current.get("expires") == result["expires"]
                and self._current.get("issued") == result["issued"])

    def get_tier(self):
        return self._current.get("tier", "FREE") if self.is_valid() else "FREE"

    def has_feature(self, feature):
        return bool(LICENSE_MATRIX[self.get_tier()].get(feature, False))

    def get_info(self):
        info = {k: v for k, v in self._current.items() if k != "key"}
        info.update(valid=self.is_valid(), matrix=LICENSE_MATRIX[self.get_tier()],
                    days_remaining=self._days_remaining())
        return info

    def _days_remaining(self):
        if not self._current.get("expires"):
            return 9999 if self.get_tier() == "FREE" else 0
        try:
            return max(0, (datetime.fromisoformat(self._current["expires"]) -
                           datetime.now(timezone.utc)).days)
        except (TypeError, ValueError):
            return 0

    def get_matrix(self):
        return LICENSE_MATRIX

    def get_all_keys_preview(self):
        return []
