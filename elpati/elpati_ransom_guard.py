"""
ELPATI RANSOM GUARD - Ransomware Detection & Prevention
Honeypot files, extension monitoring, entropy analysis, backup protection
"""
import os, time, threading, math, random, string
from pathlib import Path
from collections import defaultdict
from datetime import datetime

class ElpatiRansomGuard:
    def __init__(self):
        from elpati.elpati_log import ElpatiLog
        self.log = ElpatiLog()
        self._active = False
        self._stop_event = threading.Event()
        self._honeypot_files = []
        self._file_change_counts = defaultdict(int)
        self._alert_callbacks = []
        self._thread = None
        self._honeypot_dir = Path(__file__).parent.parent / "security" / "honeypots"
        self._honeypot_dir.mkdir(parents=True, exist_ok=True)
        self._honeypot_hashes = {}
        self._seen_extensions = set()
        self._ransom_extensions = {
            ".locky", ".zepto", ".cerber", ".encrypted", ".crypt", ".enc",
            ".locked", ".vault", ".wnry", ".wncry", ".ryuk", ".revil",
            ".sodinokibi", ".darkside", ".lockbit", ".blackmatter", ".conti"
        }
        from elpati.elpati_threat_intel import AMBIGUOUS_ENCRYPTED_EXTENSIONS
        self._ransom_extensions.difference_update(AMBIGUOUS_ENCRYPTED_EXTENSIONS)

    def deploy_honeypots(self, count: int = 10):
        """Create decoy files to detect ransomware activity."""
        import hashlib
        for i in range(count):
            fname = self._honeypot_dir / f"important_document_{i:03d}.docx"
            # Create realistic-looking decoy content
            content = f"CONFIDENTIAL DOCUMENT {i}\n" + "X" * random.randint(1000, 5000)
            fname.write_text(content, encoding="utf-8")
            self._honeypot_hashes[str(fname)] = hashlib.sha256(content.encode()).hexdigest()
            self._honeypot_files.append(str(fname))
        self.log.info(f"RansomGuard: {count} honeypot files deployed")
        return len(self._honeypot_files)

    def start(self):
        if self._active:
            return
        self._stop_event.clear()
        if not self._honeypot_files:
            self.deploy_honeypots()
        self._active = True
        self._thread = threading.Thread(target=self._watch_loop, daemon=True, name="ELPATI-RansomGuard")
        self._thread.start()
        self.log.info("ELPATI RansomGuard started")

    def stop(self):
        self._active = False
        self._stop_event.set()
        worker = getattr(self, "_thread", None) or getattr(self, "_monitor_thread", None)
        if worker and worker is not threading.current_thread():
            worker.join(timeout=2)

    def _watch_loop(self):
        while self._active:
            try:
                self._check_honeypots()
                self._scan_recent_extensions()
                self._stop_event.wait(5)
            except Exception as e:
                self.log.error(f"RansomGuard error: {e}")
                self._stop_event.wait(10)

    def _check_honeypots(self):
        import hashlib
        for fpath, orig_hash in list(self._honeypot_hashes.items()):
            p = Path(fpath)
            if not p.exists():
                self._fire_alert("CRITICAL", f"Honeypot file deleted: {p.name}", 95)
                continue
            try:
                curr_hash = hashlib.sha256(p.read_bytes()).hexdigest()
                if curr_hash != orig_hash:
                    self._fire_alert("CRITICAL", f"Honeypot file modified: {p.name} - RANSOMWARE LIKELY ACTIVE", 100)
                    self._honeypot_hashes[fpath] = curr_hash
            except:
                pass

    def _scan_recent_extensions(self):
        """Scan for new files with ransomware extensions in common dirs."""
        scan_dirs = [Path.home() / "Documents", Path.home() / "Desktop",
                     Path.home() / "Downloads"]
        for d in scan_dirs:
            if d.exists():
                try:
                    for f in d.glob("**/*"):
                        if self._stop_event.is_set():
                            return
                        if f.is_file() and f.suffix.lower() in self._ransom_extensions:
                            key = (str(f), f.stat().st_mtime_ns)
                            if key not in self._seen_extensions:
                                self._seen_extensions.add(key)
                                self._fire_alert("MEDIUM", f"Extension a examiner, infection non confirmee: {f}", 45,
                                                 review_required=True)
                except:
                    pass

    def calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy to detect encrypted/compressed data."""
        if not data:
            return 0.0
        freq = defaultdict(int)
        for b in data:
            freq[b] += 1
        length = len(data)
        entropy = 0.0
        for count in freq.values():
            p = count / length
            if p > 0:
                entropy -= p * math.log2(p)
        return entropy

    def check_file_entropy(self, filepath: str) -> dict:
        """Files with entropy > 7.0 are likely encrypted."""
        try:
            with open(filepath, "rb") as f:
                data = f.read(65536)
            entropy = self.calculate_entropy(data)
            suspected_encrypted = entropy > 7.2
            return {
                "path": filepath, "entropy": round(entropy, 4),
                "suspected_encrypted": suspected_encrypted,
                "score": 80 if suspected_encrypted else 0,
                "note": "High entropy indicates encryption/compression" if suspected_encrypted else "Normal"
            }
        except Exception as e:
            return {"path": filepath, "error": str(e), "entropy": 0}

    def _fire_alert(self, severity, message, score, *, review_required=False):
        self.log.threat(f"[RANSOMGUARD-{severity}] {message}")
        for cb in self._alert_callbacks:
            try:
                cb({"severity": severity, "message": message, "score": score,
                    "review_required": review_required,
                    "ts": datetime.utcnow().isoformat()})
            except:
                pass

    def register_alert_callback(self, cb):
        self._alert_callbacks.append(cb)

    def get_status(self):
        return {
            "active": self._active, "honeypots": len(self._honeypot_files),
            "monitored_extensions": len(self._ransom_extensions)
        }
