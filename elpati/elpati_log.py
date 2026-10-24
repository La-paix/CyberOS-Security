"""ELPATI LOG - Tamper-proof blockchain-style logging."""
import os, json, hashlib, threading, time
from datetime import datetime
from pathlib import Path

LOGS_DIR = Path(__file__).parent.parent / "logs"
LOGS_DIR.mkdir(exist_ok=True)

class ElpatiLog:
    _instance = None
    _lock = threading.Lock()
    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._init_done = False
        return cls._instance
    def __init__(self):
        if self._init_done: return
        self._init_done = True
        self.log_file = LOGS_DIR / "cyberos_secure.log"
        self.chain_file = LOGS_DIR / "chain.json"
        self._chain = self._load_chain()
        self._flock = threading.Lock()
    def _load_chain(self):
        if self.chain_file.exists():
            try: return json.loads(self.chain_file.read_text())
            except: pass
        return []
    def _prev_hash(self):
        return self._chain[-1]["hash"] if self._chain else "GENESIS_ELPATI_2026"
    def _write(self, level, message):
        with self._flock:
            ts = datetime.utcnow().isoformat()
            prev = self._prev_hash()
            payload = f"{ts}|{level}|{message}|{prev}"
            h = hashlib.sha256(payload.encode()).hexdigest()
            entry = {"ts": ts, "level": level, "msg": message, "prev": prev, "hash": h}
            self._chain.append(entry)
            if len(self._chain) % 50 == 0:
                self.chain_file.write_text(json.dumps(self._chain[-1000:], indent=2))
            with open(self.log_file, "a", encoding="utf-8") as f:
                f.write(f"[{ts}] [{level:8}] {message} |{h[:10]}\n")
    def info(self, m):    self._write("INFO", m)
    def warning(self, m): self._write("WARNING", m)
    def error(self, m):   self._write("ERROR", m)
    def critical(self, m):self._write("CRITICAL", m)
    def threat(self, m):  self._write("THREAT", m)
    def audit(self, m):   self._write("AUDIT", m)
    def verify_chain(self):
        for i in range(1, len(self._chain)):
            c = self._chain[i]
            p = self._chain[i-1]
            pl = f"{c['ts']}|{c['level']}|{c['msg']}|{c['prev']}"
            if hashlib.sha256(pl.encode()).hexdigest() != c["hash"] or c["prev"] != p["hash"]:
                return False, i
        return True, len(self._chain)
    def get_recent(self, n=100): return self._chain[-n:]
    def flush_chain(self):
        self.chain_file.write_text(json.dumps(self._chain[-2000:], indent=2))
