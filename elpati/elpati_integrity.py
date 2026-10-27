"""
ELPATI INTEGRITY - Surveillance d'intégrité des fichiers (FIM)
File Integrity Monitoring — comme Tripwire ou OSSEC
Surveille les fichiers critiques et détecte toute modification
"""
import os, hashlib, json, threading, time
from utils.storage import write_json
from pathlib import Path
from datetime import datetime

FIM_DB = Path(__file__).parent.parent / "security" / "fim_baseline.json"

CRITICAL_PATHS_WINDOWS = [
    "C:\\Windows\\System32\\drivers\\etc\\hosts",
    "C:\\Windows\\System32\\cmd.exe",
    "C:\\Windows\\System32\\ntoskrnl.exe",
]
CRITICAL_PATHS_LINUX = [
    "/etc/hosts", "/etc/passwd", "/etc/shadow", "/etc/sudoers",
    "/etc/crontab", "/etc/ssh/sshd_config",
    "/bin/bash", "/usr/bin/sudo",
]

class ElpatiIntegrity:
    def __init__(self):
        from elpati.elpati_log import ElpatiLog
        self.log = ElpatiLog()
        self._baseline = self._load_baseline()
        self._alert_callbacks = []
        self._active = False
        self._thread = None
        self._stop = threading.Event()
        self._changes = []

    def _load_baseline(self):
        if FIM_DB.exists():
            try: return json.loads(FIM_DB.read_text(encoding='utf-8'))
            except Exception as exc:
                raise ValueError("Baseline FIM corrompue") from exc
        return {}

    def _save_baseline(self):
        FIM_DB.parent.mkdir(parents=True, exist_ok=True)
        write_json(FIM_DB, self._baseline)

    def _hash_file(self, path):
        try:
            h = hashlib.sha3_256()
            with open(path, 'rb') as f:
                for chunk in iter(lambda: f.read(65536), b''): h.update(chunk)
            return h.hexdigest()
        except: return None

    def create_baseline(self, paths=None, overwrite=False):
        """Créer la baseline d'intégrité."""
        if paths is None:
            import platform
            paths = CRITICAL_PATHS_WINDOWS if platform.system() == 'Windows' else CRITICAL_PATHS_LINUX
        count = 0
        for path in paths:
            p = Path(path)
            if p.exists() and p.is_file() and (overwrite or str(p) not in self._baseline):
                h = self._hash_file(str(p))
                if h:
                    self._baseline[str(p)] = {
                        "hash": h, "size": p.stat().st_size,
                        "baseline_at": datetime.utcnow().isoformat()
                    }
                    count += 1
        self._save_baseline()
        self.log.audit(f"FIM: Baseline créée — {count} fichiers")
        return count

    def add_watch(self, path):
        p = Path(path)
        if p.exists():
            h = self._hash_file(str(p))
            if h:
                self._baseline[str(p)] = {"hash": h, "size": p.stat().st_size,
                                           "baseline_at": datetime.utcnow().isoformat()}
                self._save_baseline()
                return True
        return False

    def check_integrity(self):
        """Vérifier tous les fichiers surveillés."""
        changes = []
        for fpath, info in list(self._baseline.items()):
            p = Path(fpath)
            if not p.exists():
                changes.append({"path": fpath, "type": "DELETED", "score": 90})
                self.log.threat(f"FIM: Fichier supprimé: {fpath}")
            else:
                curr_hash = self._hash_file(fpath)
                if curr_hash is None:
                    changes.append({"path": fpath, "type": "UNREADABLE", "score": 50})
                elif curr_hash != info["hash"]:
                    changes.append({"path": fpath, "type": "MODIFIED",
                                    "old_hash": info["hash"][:12], "new_hash": curr_hash[:12],
                                    "score": 85})
                    self.log.threat(f"FIM: Fichier modifié: {fpath}")
                    for cb in self._alert_callbacks:
                        try: cb({"severity":"HIGH","message":f"Fichier critique modifié: {fpath}","score":85})
                        except: pass
        self._changes = changes
        return changes

    def start_monitoring(self, interval=60):
        if self._active:
            return
        self._stop.clear()
        self._active = True
        def _loop():
            while self._active:
                self.check_integrity()
                self._stop.wait(interval)
        self._thread = threading.Thread(target=_loop, daemon=True, name="ELPATI-FIM")
        self._thread.start()
        self.log.info("FIM: Surveillance démarrée")

    def stop_monitoring(self):
        self._active = False
        self._stop.set()
        if self._thread and self._thread is not threading.current_thread():
            self._thread.join(timeout=2)
    def register_alert_callback(self, cb): self._alert_callbacks.append(cb)
    def get_watched_count(self): return len(self._baseline)
    def get_changes(self): return self._changes
    def get_status(self):
        return {"watching": len(self._baseline), "changes": len(self._changes), "active": self._active}
