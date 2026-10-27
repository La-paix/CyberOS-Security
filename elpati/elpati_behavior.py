"""
ELPATI BEHAVIOR - Behavioral Analysis & Anomaly Detection
Detects suspicious patterns and behavioral indicators of compromise
"""
import time, threading, json, psutil
from collections import defaultdict, deque
from datetime import datetime

class ElpatiBehavior:
    def __init__(self):
        from elpati.elpati_log import ElpatiLog
        self.log = ElpatiLog()
        self._events = deque(maxlen=5000)
        self._process_activity = defaultdict(list)
        self._file_access_counts = defaultdict(int)
        self._lock = threading.Lock()
        self._rules = self._load_rules()

    def _load_rules(self):
        return [
            {"name": "MASS_FILE_ENCRYPTION", "description": "Mass file modification (ransomware)",
             "threshold": 50, "window_sec": 60, "score": 95},
            {"name": "RAPID_PROCESS_SPAWN", "description": "Rapid process spawning",
             "threshold": 20, "window_sec": 10, "score": 70},
            {"name": "HIGH_ENTROPY_WRITE", "description": "High-entropy data write pattern",
             "threshold": 10, "window_sec": 30, "score": 80},
            {"name": "NETWORK_SCAN_PATTERN", "description": "Port scanning behavior",
             "threshold": 100, "window_sec": 30, "score": 75},
            {"name": "PRIVILEGE_ESCALATION", "description": "Privilege escalation attempt",
             "threshold": 1, "window_sec": 60, "score": 90},
        ]

    def record_event(self, event_type: str, details: dict):
        with self._lock:
            event = {
                "type": event_type, "ts": time.time(),
                "ts_str": datetime.utcnow().isoformat(),
                "details": details
            }
            self._events.append(event)
            return self._analyze_patterns(event)

    def _analyze_patterns(self, new_event):
        now = time.time()
        # Check file modification rate
        if new_event["type"] == "FILE_MODIFIED":
            path = new_event["details"].get("path", "")
            ext = path.split(".")[-1].lower() if "." in path else ""
            self._file_access_counts[ext] += 1
            # Count modifications in last 60 seconds
            recent = [e for e in self._events
                      if e["type"] == "FILE_MODIFIED" and now - e["ts"] < 60]
            if len(recent) > 50:
                self.log.threat(f"BEHAVIOR: Mass file modification detected ({len(recent)} files/60s)")
                return {"alert": True, "rule": "MASS_FILE_ENCRYPTION", "score": 95}

    def analyze_process_behavior(self, pid: int) -> dict:
        """Deep behavioral analysis of a process."""
        try:
            proc = psutil.Process(pid)
            score = 0
            flags = []

            # Check open files
            try:
                open_files = proc.open_files()
                suspicious_exts = [".doc", ".xls", ".pdf", ".jpg", ".png", ".db", ".sql"]
                doc_files = [f for f in open_files if any(f.path.endswith(e) for e in suspicious_exts)]
                if len(doc_files) > 20:
                    score += 40
                    flags.append(f"Accessing {len(doc_files)} document files")
            except:
                pass

            # Check network connections
            try:
                conns = proc.net_connections()
                if len(conns) > 50:
                    score += 30
                    flags.append(f"Excessive connections: {len(conns)}")
                external = [c for c in conns if c.raddr and not c.raddr.ip.startswith(("127.", "192.168.", "10.", "172."))]
                if len(external) > 10:
                    score += 25
                    flags.append(f"External connections: {len(external)}")
            except:
                pass

            # Check CPU
            try:
                cpu = proc.cpu_percent(interval=0.1)
                if cpu > 80:
                    score += 15
                    flags.append(f"High CPU: {cpu}%")
            except:
                pass

            # Check memory
            try:
                mem = proc.memory_info()
                if mem.rss > 500 * 1024 * 1024:  # 500MB
                    score += 10
                    flags.append(f"High memory: {mem.rss // (1024*1024)}MB")
            except:
                pass

            return {"pid": pid, "score": min(score, 100), "flags": flags,
                    "risk": "HIGH" if score > 60 else "MEDIUM" if score > 30 else "LOW"}
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return {"pid": pid, "score": 0, "flags": ["Process terminated"], "risk": "NONE"}

    def get_risk_summary(self) -> dict:
        recent = [e for e in self._events if time.time() - e["ts"] < 3600]
        type_counts = defaultdict(int)
        for e in recent:
            type_counts[e["type"]] += 1
        return {"events_last_hour": len(recent), "event_types": dict(type_counts),
                "file_access_by_ext": dict(list(self._file_access_counts.items())[:20])}
