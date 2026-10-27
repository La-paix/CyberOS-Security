"""
ELPATI SELF PROTECTION - Anti-tampering & Process Protection
Prevents unauthorized termination and file modification
"""
import os, sys, hashlib, threading, time, signal
from pathlib import Path

class ElpatiSelfProtection:
    def __init__(self):
        self.root = Path(__file__).parent.parent
        self._active = False
        self._stop_event = threading.Event()
        self._monitor_thread = None
        self._file_hashes = {}
        self._critical_files = [
            "main.py", "core/controller.py", "core/engine.py",
            "core/security_vault.py", "elpati/elpati_crypto.py",
            "elpati/elpati_log.py"
        ]

    def activate(self):
        if self._active:
            return
        self._stop_event.clear()
        self._active = True
        self._snapshot_files()
        self._install_signal_handlers()
        self._monitor_thread = threading.Thread(
            target=self._monitor_loop, daemon=True, name="ELPATI-SelfProtect")
        self._monitor_thread.start()

    def _snapshot_files(self):
        for rel in self._critical_files:
            fpath = self.root / rel
            if fpath.exists():
                with open(fpath, "rb") as f:
                    self._file_hashes[rel] = hashlib.sha256(f.read()).hexdigest()

    def _check_integrity(self):
        from elpati.elpati_log import ElpatiLog
        log = ElpatiLog()
        for rel, orig_hash in self._file_hashes.items():
            fpath = self.root / rel
            if not fpath.exists():
                log.critical(f"SELF-PROTECT: Critical file missing: {rel}")
                return False
            with open(fpath, "rb") as f:
                curr = hashlib.sha256(f.read()).hexdigest()
            if curr != orig_hash:
                log.critical(f"SELF-PROTECT: Tampering detected: {rel}")
                return False
        return True

    def _install_signal_handlers(self):
        def handle_sigterm(sig, frame):
            from elpati.elpati_log import ElpatiLog
            ElpatiLog().audit("SELF-PROTECT: SIGTERM received - clean shutdown initiated")
            sys.exit(0)
        try:
            signal.signal(signal.SIGTERM, handle_sigterm)
        except (OSError, ValueError):
            pass

    def _monitor_loop(self):
        while self._active:
            self._stop_event.wait(30)
            self._check_integrity()

    def deactivate(self):
        self._active = False
        self._stop_event.set()
        worker = getattr(self, "_thread", None) or getattr(self, "_monitor_thread", None)
        if worker and worker is not threading.current_thread():
            worker.join(timeout=2)

    def get_status(self):
        return {"active": self._active, "files_monitored": len(self._file_hashes),
                "integrity": self._check_integrity()}
