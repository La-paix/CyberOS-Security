"""Encrypted quarantine with unique identifiers and non-destructive restoration."""
import hashlib
import os
import json
from pathlib import Path
import threading
from datetime import datetime
from uuid import uuid4
from utils.storage import atomic_write, child_file, write_json

QUARANTINE_DIR = Path(__file__).resolve().parent.parent / "quarantine" / "vault"
QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)
QUARANTINE_INDEX = QUARANTINE_DIR / "index.json"
_INDEX_LOCK = threading.RLock()


class QuarantineManager:
    def __init__(self):
        QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)
        from elpati.elpati_log import ElpatiLog
        from elpati.elpati_crypto import ElpatiCrypto
        self.log = ElpatiLog()
        self.crypto = ElpatiCrypto()
        self._index = self._load_index()

    def _load_index(self):
        if not QUARANTINE_INDEX.exists():
            if any(QUARANTINE_DIR.glob("*.qvault")):
                raise ValueError("Index de quarantaine absent : restaurer la sauvegarde.")
            return {"entries": []}
        value = json.loads(QUARANTINE_INDEX.read_text(encoding="utf-8"))
        if not isinstance(value, dict) or not isinstance(value.get("entries"), list):
            raise ValueError("Index de quarantaine corrompu")
        identifiers = set()
        for entry in value["entries"]:
            if not isinstance(entry, dict) or entry.get("id") in identifiers:
                raise ValueError("Entrée de quarantaine invalide")
            child_file(QUARANTINE_DIR, entry.get("id"))
            identifiers.add(entry["id"])
        return value

    def _save_index(self):
        write_json(QUARANTINE_INDEX, self._index)

    def quarantine_file(self, filepath: str, threat_info: dict) -> dict:
        with _INDEX_LOCK:
            try:
                self._index = self._load_index()
                src = Path(filepath)
                if src.is_symlink() or not src.is_file():
                    return {"success": False, "error": "Fichier absent ou lien symbolique refusé"}
                src = src.resolve()
                app_root = Path(__file__).resolve().parent.parent
                protected = {app_root / name for name in ("security", "quarantine", "logs")}
                if any(src.is_relative_to(root) for root in protected):
                    return {"success": False, "error": "Données internes de CyberOS exclues"}
                before = src.stat()
                if before.st_size > 100 * 1024 * 1024:
                    return {"success": False, "error": "Limite de quarantaine : 100 Mio"}
                content = src.read_bytes()
                qname = f"Q_{datetime.utcnow():%Y%m%d_%H%M%S}_{uuid4().hex}.qvault"
                dst = child_file(QUARANTINE_DIR, qname)
                encrypted = self.crypto.encrypt(content)
                # Exclusive creation: no payload is ever replaced.
                with dst.open("xb") as stream:
                    if os.name != "nt":
                        os.fchmod(stream.fileno(), 0o600)
                    stream.write(encrypted)
                    stream.flush()
                    os.fsync(stream.fileno())
                if self.crypto.decrypt(dst.read_bytes()) != content:
                    raise ValueError("Vérification de stockage échouée")
                entry = {"id": qname, "original_path": str(src), "original_name": src.name,
                         "quarantine_file": qname, "hash": hashlib.sha3_256(content).hexdigest(),
                         "size": len(content), "quarantined_at": datetime.utcnow().isoformat(),
                         "threat_info": threat_info, "restored": False, "source_removed": False}
                self._index["entries"].append(entry)
                self._save_index()  # Metadata and payload are durable before removing the source.
                current = src.stat()
                if ((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) !=
                    (current.st_dev, current.st_ino, current.st_size, current.st_mtime_ns) or
                    src.is_symlink() or self.crypto.hash_file(src) != entry["hash"]):
                    return {"success": False, "error": "Fichier modifié pendant l'opération; original conservé",
                            "quarantine_id": qname}
                src.unlink()
                entry["source_removed"] = True
                self._save_index()
                self.log.threat(f"Quarantined: {filepath} -> {qname}")
                return {"success": True, "quarantine_id": qname, "entry": dict(entry)}
            except Exception as exc:
                self.log.error(f"Quarantine failed for {filepath}: {exc}")
                return {"success": False, "error": str(exc)}

    def restore_file(self, quarantine_id, restore_path=None):
        with _INDEX_LOCK:
            try:
                self._index = self._load_index()
                entry = next((e for e in self._index["entries"] if e["id"] == quarantine_id), None)
                if entry is None:
                    return {"success": False, "error": "Entrée inconnue"}
                content = self.crypto.decrypt(child_file(QUARANTINE_DIR, quarantine_id).read_bytes())
                if hashlib.sha3_256(content).hexdigest() != entry["hash"]:
                    raise ValueError("Empreinte de quarantaine incorrecte")
                target = Path(restore_path or entry["original_path"])
                if target.exists() or target.is_symlink():
                    return {"success": False, "error": "La destination existe déjà. Choisir un autre chemin."}
                target.parent.mkdir(parents=True, exist_ok=True)
                with target.open("xb") as stream:
                    stream.write(content)
                    stream.flush()
                    os.fsync(stream.fileno())
                entry.update(restored=True, restored_at=datetime.utcnow().isoformat(), restore_path=str(target))
                self._save_index()
                self.log.audit(f"Quarantine restored: {quarantine_id}")
                return {"success": True, "restored_to": str(target)}
            except Exception as exc:
                return {"success": False, "error": str(exc)}

    def delete_quarantined(self, quarantine_id):
        with _INDEX_LOCK:
            try:
                self._index = self._load_index()
                entry = next((e for e in self._index["entries"] if e["id"] == quarantine_id), None)
                if entry is None:
                    return {"success": False, "error": "Entrée inconnue"}
                child_file(QUARANTINE_DIR, quarantine_id).unlink(missing_ok=True)
                self._index["entries"].remove(entry)
                self._save_index()
                self.log.audit(f"Quarantine entry deleted: {quarantine_id}")
                return {"success": True}
            except Exception as exc:
                return {"success": False, "error": str(exc)}

    def list_quarantined(self):
        with _INDEX_LOCK:
            self._index = self._load_index()
            return [dict(e) for e in self._index["entries"] if not e.get("restored")]

    def get_stats(self):
        with _INDEX_LOCK:
            self._index = self._load_index()
            entries = self._index["entries"]
            return {"total": len(entries), "active": sum(not e.get("restored") for e in entries),
                    "restored": sum(bool(e.get("restored")) for e in entries),
                    "quarantine_dir": str(QUARANTINE_DIR)}
