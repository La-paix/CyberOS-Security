"""Encrypted evidence and portable, fail-closed source integrity checking."""
import hashlib
import json
from pathlib import Path
import threading
from datetime import datetime
from uuid import uuid4
from utils.storage import atomic_write, child_file, safe_name, write_json

ROOT = Path(__file__).resolve().parent.parent
VAULT_DIR = ROOT / "security" / "vault"
VAULT_DIR.mkdir(parents=True, exist_ok=True)
INTEGRITY_DIR = ROOT / "security" / "integrity"
INTEGRITY_DIR.mkdir(parents=True, exist_ok=True)
_VAULT_LOCK = threading.RLock()
SOURCE_DIRS = ("core", "elpati", "gui", "cli", "scanner", "forensic",
               "sandbox", "quarantine", "reports", "utils")


def source_files(root=ROOT):
    files = {"main.py": root / "main.py"}
    for directory in SOURCE_DIRS:
        for file in (root / directory).rglob("*.py"):
            if "__pycache__" not in file.parts and not file.is_symlink():
                files[file.relative_to(root).as_posix()] = file
    return files


class SecurityVault:
    def __init__(self):
        from elpati.elpati_crypto import ElpatiCrypto
        from elpati.elpati_log import ElpatiLog
        self.crypto = ElpatiCrypto()
        self.log = ElpatiLog()
        self.manifest_file = INTEGRITY_DIR / "manifest.json"
        self._manifest_error = None
        self._manifest = self._load_manifest()
        self.evidence_index = VAULT_DIR / "index.json"

    def _load_manifest(self):
        try:
            raw = json.loads(self.manifest_file.read_text(encoding="utf-8"))
            if not isinstance(raw, dict) or not raw:
                raise ValueError("Manifest vide")
            result = {}
            for name, value in raw.items():
                normalized = name.replace("\\", "/")
                if normalized in result:
                    raise ValueError("Chemin dupliqué")
                if normalized.startswith("_") or normalized.startswith("evidence/"):
                    result[normalized] = value
                    continue
                if (normalized.startswith("/") or ".." in normalized.split("/") or
                    not isinstance(value, str) or len(value) != 64 or
                    any(c not in "0123456789abcdef" for c in value)):
                    raise ValueError("Entrée invalide")
                result[normalized] = value
            return result
        except (OSError, ValueError, TypeError):
            self._manifest_error = "Manifest absent ou corrompu. Réinstaller les sources officielles."
            return {}

    def verify_integrity(self) -> bool:
        # Never learn a new trusted baseline from potentially altered source.
        if self._manifest_error:
            self.log.critical(self._manifest_error)
            return False
        files = source_files()
        expected = {k: v for k, v in self._manifest.items()
                    if not k.startswith("_") and not k.startswith("evidence/")}
        if set(files) != set(expected):
            self.log.critical("Vault integrity FAIL: liste des sources différente du manifeste")
            return False
        for rel, path in files.items():
            if path.is_symlink() or self.crypto.hash_file(path) != expected[rel]:
                self.log.critical(f"Vault integrity FAIL: {rel}")
                return False
        return True

    def _read_evidence_index(self):
        if not self.evidence_index.exists():
            return {}
        value = json.loads(self.evidence_index.read_text(encoding="utf-8"))
        if not isinstance(value, dict):
            raise ValueError("Index des preuves corrompu")
        return value

    def store_evidence(self, name: str, data: bytes) -> str:
        with _VAULT_LOCK:
            index = self._read_evidence_index()
            fname = f"evidence_{datetime.utcnow():%Y%m%d_%H%M%S}_{uuid4().hex}_{safe_name(name)}.enc"
            path = child_file(VAULT_DIR, fname)
            atomic_write(path, self.crypto.encrypt(data))
            index[fname] = hashlib.sha256(data).hexdigest()
            write_json(self.evidence_index, index)
            self.log.audit(f"Evidence stored: {fname}")
            return str(path)

    def retrieve_evidence(self, fname: str) -> bytes:
        with _VAULT_LOCK:
            path = child_file(VAULT_DIR, fname)
            data = self.crypto.decrypt(path.read_bytes())
            expected = self._read_evidence_index().get(fname)
            # Preserve old evidence hashes during the explicit migration.
            if expected is None:
                expected = self._manifest.get(f"evidence/{fname}")
                actual = self.crypto.hash_data(data)
            else:
                actual = hashlib.sha256(data).hexdigest()
            if not expected or expected != actual:
                raise ValueError("Preuve absente de l'index ou intégrité incorrecte")
            return data

    def list_evidence(self):
        return sorted(f.name for f in VAULT_DIR.glob("evidence_*.enc"))

    def store_key(self, key_name: str, key_data: bytes):
        from elpati.elpati_crypto import KEYS_DIR
        atomic_write(child_file(KEYS_DIR, f"{safe_name(key_name)}.enc"), self.crypto.encrypt(key_data))

    def get_status(self):
        return {"vault_path": str(VAULT_DIR), "evidence_count": len(self.list_evidence()),
                "manifest_entries": len(self._manifest), "integrity": self.verify_integrity()}
