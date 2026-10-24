"""
QUARANTINE MANAGER - Secure File Isolation
Moves threats to encrypted quarantine, tracks metadata, allows restoration
"""
import os, json, shutil, time
from pathlib import Path
from datetime import datetime

QUARANTINE_DIR = Path(__file__).parent.parent / "quarantine" / "vault"
QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)
QUARANTINE_INDEX = QUARANTINE_DIR / "index.json"

class QuarantineManager:
    def __init__(self):
        from elpati.elpati_log import ElpatiLog
        from elpati.elpati_crypto import ElpatiCrypto
        self.log = ElpatiLog()
        self.crypto = ElpatiCrypto()
        self._index = self._load_index()

    def _load_index(self) -> dict:
        if QUARANTINE_INDEX.exists():
            try:
                return json.loads(QUARANTINE_INDEX.read_text())
            except:
                pass
        return {"entries": []}

    def _save_index(self):
        QUARANTINE_INDEX.write_text(json.dumps(self._index, indent=2))

    def quarantine_file(self, filepath: str, threat_info: dict) -> dict:
        try:
            src = Path(filepath)
            if not src.exists():
                return {"success": False, "error": "File not found"}

            # Read, encrypt, and store
            file_hash = self.crypto.hash_file(filepath)
            with open(filepath, "rb") as f:
                content = f.read()
            encrypted = self.crypto.encrypt(content)

            ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            qname = f"Q_{ts}_{src.name}.qvault"
            dst = QUARANTINE_DIR / qname
            dst.write_bytes(encrypted)

            entry = {
                "id": qname, "original_path": str(src.resolve()),
                "original_name": src.name, "quarantine_file": qname,
                "hash": file_hash, "size": src.stat().st_size,
                "quarantined_at": datetime.utcnow().isoformat(),
                "threat_info": threat_info, "restored": False
            }
            self._index["entries"].append(entry)
            self._save_index()

            # Delete original
            src.unlink()
            self.log.threat(f"Quarantined: {filepath} -> {qname}")
            return {"success": True, "quarantine_id": qname, "entry": entry}
        except Exception as e:
            self.log.error(f"Quarantine failed for {filepath}: {e}")
            return {"success": False, "error": str(e)}

    def restore_file(self, quarantine_id: str, restore_path: str = None) -> dict:
        entry = next((e for e in self._index["entries"] if e["id"] == quarantine_id), None)
        if not entry:
            return {"success": False, "error": "Quarantine entry not found"}
        try:
            qfile = QUARANTINE_DIR / quarantine_id
            if not qfile.exists():
                return {"success": False, "error": "Quarantine file missing"}

            encrypted = qfile.read_bytes()
            content = self.crypto.decrypt(encrypted)

            target = Path(restore_path or entry["original_path"])
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(content)

            entry["restored"] = True
            entry["restored_at"] = datetime.utcnow().isoformat()
            entry["restore_path"] = str(target)
            self._save_index()
            self.log.audit(f"File restored from quarantine: {quarantine_id} -> {target}")
            return {"success": True, "restored_to": str(target)}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def delete_quarantined(self, quarantine_id: str) -> dict:
        entry = next((e for e in self._index["entries"] if e["id"] == quarantine_id), None)
        if not entry:
            return {"success": False, "error": "Not found"}
        try:
            qfile = QUARANTINE_DIR / quarantine_id
            if qfile.exists():
                qfile.unlink()
            self._index["entries"] = [e for e in self._index["entries"] if e["id"] != quarantine_id]
            self._save_index()
            self.log.audit(f"Quarantine entry permanently deleted: {quarantine_id}")
            return {"success": True}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def list_quarantined(self) -> list:
        return [e for e in self._index["entries"] if not e.get("restored")]

    def get_stats(self) -> dict:
        entries = self._index["entries"]
        return {
            "total": len(entries),
            "active": len([e for e in entries if not e.get("restored")]),
            "restored": len([e for e in entries if e.get("restored")]),
            "quarantine_dir": str(QUARANTINE_DIR)
        }
