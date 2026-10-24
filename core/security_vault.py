"""
CORE SECURITY VAULT - Secure Storage for Keys, Logs & Forensic Evidence
Encrypted, integrity-verified storage with tamper detection
"""
import os, json, hashlib, time
from pathlib import Path
from datetime import datetime

VAULT_DIR = Path(__file__).parent.parent / "security" / "vault"
VAULT_DIR.mkdir(parents=True, exist_ok=True)
INTEGRITY_DIR = Path(__file__).parent.parent / "security" / "integrity"
INTEGRITY_DIR.mkdir(parents=True, exist_ok=True)

class SecurityVault:
    def __init__(self):
        from elpati.elpati_crypto import ElpatiCrypto
        from elpati.elpati_log import ElpatiLog
        self.crypto = ElpatiCrypto()
        self.log = ElpatiLog()
        self.manifest_file = INTEGRITY_DIR / "manifest.json"
        self._manifest = self._load_manifest()

    def _load_manifest(self):
        if self.manifest_file.exists():
            try:
                return json.loads(self.manifest_file.read_text())
            except:
                return {}
        return {}

    def _save_manifest(self):
        self.manifest_file.write_text(json.dumps(self._manifest, indent=2))

    def verify_integrity(self) -> bool:
        """Run system integrity check on first boot or periodically."""
        root = Path(__file__).parent.parent
        core_files = list((root / "core").glob("*.py")) + list((root / "elpati").glob("*.py"))
        if not self._manifest:
            # First run - create baseline
            for f in core_files:
                rel = str(f.relative_to(root))
                self._manifest[rel] = self.crypto.hash_file(str(f))
            self._manifest["_created"] = datetime.utcnow().isoformat()
            self._save_manifest()
            self.log.audit("Security vault: baseline manifest created")
            return True

        # Compare against baseline
        tampered = []
        for f in core_files:
            rel = str(f.relative_to(root))
            if rel in self._manifest:
                curr = self.crypto.hash_file(str(f))
                if curr and curr != self._manifest.get(rel):
                    tampered.append(rel)

        if tampered:
            self.log.critical(f"Vault integrity FAIL: tampered files: {tampered}")
            return False
        return True

    def store_evidence(self, name: str, data: bytes) -> str:
        ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        fname = f"evidence_{ts}_{name}.enc"
        path = VAULT_DIR / fname
        encrypted = self.crypto.encrypt(data)
        path.write_bytes(encrypted)
        h = self.crypto.hash_data(data)
        self._manifest[f"evidence/{fname}"] = h
        self._save_manifest()
        self.log.audit(f"Evidence stored: {fname} SHA256:{h[:16]}")
        return str(path)

    def retrieve_evidence(self, fname: str) -> bytes:
        path = VAULT_DIR / fname
        if not path.exists():
            raise FileNotFoundError(f"Evidence not found: {fname}")
        encrypted = path.read_bytes()
        return self.crypto.decrypt(encrypted)

    def list_evidence(self):
        return [f.name for f in VAULT_DIR.glob("evidence_*.enc")]

    def store_key(self, key_name: str, key_data: bytes):
        keys_dir = Path(__file__).parent.parent / "security" / "keys"
        keys_dir.mkdir(exist_ok=True)
        path = keys_dir / f"{key_name}.enc"
        encrypted = self.crypto.encrypt(key_data)
        path.write_bytes(encrypted)
        self.log.audit(f"Key stored: {key_name}")

    def get_status(self):
        return {
            "vault_path": str(VAULT_DIR),
            "evidence_count": len(self.list_evidence()),
            "manifest_entries": len(self._manifest),
            "integrity": self.verify_integrity()
        }
