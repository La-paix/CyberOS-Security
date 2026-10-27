"""Hash-chained local audit log. This detects edits, not a privileged attacker."""
import hashlib
import json
import threading
from datetime import datetime
from pathlib import Path
from utils.storage import write_json

LOGS_DIR = Path(__file__).resolve().parent.parent / "logs"
LOGS_DIR.mkdir(exist_ok=True)
GENESIS = "GENESIS_ELPATI_2026"


class ElpatiLog:
    _instance = None
    _lock = threading.RLock()

    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._init_done = False
            return cls._instance

    def __init__(self):
        with self._lock:
            if self._init_done:
                return
            self.log_file = LOGS_DIR / "cyberos_secure.log"
            self.chain_file = LOGS_DIR / "chain.json"
            self._flock = threading.RLock()
            self._load_error = False
            self._chain = self._load_chain()
            self._init_done = True

    def _load_chain(self):
        if not self.chain_file.exists():
            return []
        try:
            value = json.loads(self.chain_file.read_text(encoding="utf-8"))
            if not isinstance(value, list):
                raise ValueError("Invalid chain")
            return value
        except (OSError, ValueError):
            self._load_error = True
            return []

    def _prev_hash(self):
        return self._chain[-1]["hash"] if self._chain else GENESIS

    @staticmethod
    def _hash(entry):
        payload = f"{entry['ts']}|{entry['level']}|{entry['msg']}|{entry['prev']}"
        return hashlib.sha256(payload.encode()).hexdigest()

    def _write(self, level, message):
        with self._flock:
            # Preserve a damaged chain for investigation instead of overwriting it.
            if not self.verify_chain()[0]:
                with self.log_file.open("a", encoding="utf-8") as stream:
                    stream.write(f"[CHAIN_INVALID] [{level}] {str(message)!r}\n")
                return
            entry = {"ts": datetime.utcnow().isoformat(), "level": level,
                     "msg": str(message), "prev": self._prev_hash()}
            entry["hash"] = self._hash(entry)
            self._chain.append(entry)
            write_json(self.chain_file, self._chain)
            with self.log_file.open("a", encoding="utf-8") as stream:
                stream.write(f"[{entry['ts']}] [{level}] {str(message)!r} |{entry['hash'][:10]}\n")

    def info(self, message): self._write("INFO", message)
    def warning(self, message): self._write("WARNING", message)
    def error(self, message): self._write("ERROR", message)
    def critical(self, message): self._write("CRITICAL", message)
    def threat(self, message): self._write("THREAT", message)
    def audit(self, message): self._write("AUDIT", message)

    def verify_chain(self):
        with self._flock:
            if self._load_error:
                return False, 0
            previous = GENESIS
            for i, entry in enumerate(self._chain):
                try:
                    if entry["prev"] != previous or self._hash(entry) != entry["hash"]:
                        return False, i
                    previous = entry["hash"]
                except (KeyError, TypeError):
                    return False, i
            return True, len(self._chain)

    def get_recent(self, n=100):
        with self._flock:
            return [dict(item) for item in self._chain[-n:]]

    def flush_chain(self):
        with self._flock:
            if self.verify_chain()[0]:
                write_json(self.chain_file, self._chain)
