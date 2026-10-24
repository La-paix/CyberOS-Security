"""
ELPATI MONITOR - Real-time System Surveillance
Monitors processes, files, network, and system events
"""
import os, time, threading, json, psutil
from pathlib import Path
from datetime import datetime
from collections import deque

class ElpatiMonitor:
    def __init__(self):
        from elpati.elpati_log import ElpatiLog
        self.log = ElpatiLog()
        self._active = False
        self._thread = None
        self._events = deque(maxlen=1000)
        self._process_baseline = {}
        self._connection_baseline = set()
        self._alert_callbacks = []
        self._lock = threading.Lock()
        self._stats = {"events": 0, "alerts": 0, "processes_scanned": 0}

    def start(self):
        if self._active:
            return
        self._active = True
        self._snapshot_baseline()
        self._thread = threading.Thread(target=self._monitor_loop,
                                        daemon=True, name="ELPATI-Monitor")
        self._thread.start()
        self.log.info("ELPATI Monitor started")

    def stop(self):
        self._active = False
        self.log.info("ELPATI Monitor stopped")

    def _snapshot_baseline(self):
        try:
            for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline']):
                try:
                    self._process_baseline[proc.info['pid']] = proc.info['name']
                except:
                    pass
        except:
            pass

    def _monitor_loop(self):
        iteration = 0
        while self._active:
            try:
                self._check_new_processes()
                if iteration % 3 == 0:
                    self._check_network_connections()
                if iteration % 10 == 0:
                    self._check_cpu_anomaly()
                iteration += 1
            except Exception as e:
                self.log.error(f"Monitor loop error: {e}")
            time.sleep(2)

    def _check_new_processes(self):
        try:
            current = {}
            for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'cpu_percent', 'memory_percent']):
                try:
                    current[proc.info['pid']] = proc.info
                except:
                    pass

            new_pids = set(current.keys()) - set(self._process_baseline.keys())
            for pid in new_pids:
                info = current[pid]
                event = {
                    "type": "NEW_PROCESS", "ts": datetime.utcnow().isoformat(),
                    "pid": pid, "name": info.get('name', 'unknown'),
                    "exe": info.get('exe') or 'unknown',
                    "cmdline": ' '.join(info.get('cmdline') or [])[:200]
                }
                self._add_event(event)
                # Check against threat intel
                from elpati.elpati_threat_intel import ElpatiThreatIntel
                ti = ElpatiThreatIntel()
                result = ti.check_process_name(info.get('name', ''))
                if result['detected']:
                    self._fire_alert("CRITICAL", f"Malicious process detected: {info.get('name')} PID:{pid}", 95)

            self._process_baseline = {pid: info.get('name', '') for pid, info in current.items()}
            self._stats["processes_scanned"] += len(current)
        except Exception as e:
            pass

    def _check_network_connections(self):
        try:
            conns = psutil.net_connections(kind='inet')
            current_remote = set()
            for c in conns:
                if c.raddr:
                    current_remote.add(f"{c.raddr.ip}:{c.raddr.port}")

            new_conns = current_remote - self._connection_baseline
            for conn in new_conns:
                ip = conn.split(":")[0]
                from elpati.elpati_threat_intel import ElpatiThreatIntel
                result = ElpatiThreatIntel().check_ip(ip)
                if result['detected']:
                    self._fire_alert("HIGH", f"Suspicious connection to {conn}", result['score'])
                event = {"type": "NEW_CONNECTION", "ts": datetime.utcnow().isoformat(),
                         "remote": conn, "flagged": result['detected']}
                self._add_event(event)

            self._connection_baseline = current_remote
        except:
            pass

    def _check_cpu_anomaly(self):
        try:
            cpu = psutil.cpu_percent(interval=0.5)
            mem = psutil.virtual_memory().percent
            if cpu > 90:
                self._fire_alert("MEDIUM", f"High CPU usage: {cpu}%", 50)
            if mem > 95:
                self._fire_alert("MEDIUM", f"Critical memory usage: {mem}%", 55)
        except:
            pass

    def _add_event(self, event):
        with self._lock:
            self._events.append(event)
            self._stats["events"] += 1

    def _fire_alert(self, severity, message, score):
        self._stats["alerts"] += 1
        self.log.threat(f"[{severity}] score={score} {message}")
        for cb in self._alert_callbacks:
            try:
                cb({"severity": severity, "message": message, "score": score,
                    "ts": datetime.utcnow().isoformat()})
            except:
                pass

    def register_alert_callback(self, cb):
        self._alert_callbacks.append(cb)

    def get_events(self, n=100):
        with self._lock:
            return list(self._events)[-n:]

    def get_stats(self):
        return {**self._stats, "active": self._active}

    def get_system_snapshot(self):
        try:
            return {
                "cpu_percent": psutil.cpu_percent(interval=0.1),
                "memory": dict(psutil.virtual_memory()._asdict()),
                "disk": {p.mountpoint: dict(psutil.disk_usage(p.mountpoint)._asdict())
                         for p in psutil.disk_partitions() if p.fstype},
                "net_io": dict(psutil.net_io_counters()._asdict()),
                "process_count": len(psutil.pids()),
                "boot_time": psutil.boot_time(),
                "ts": datetime.utcnow().isoformat()
            }
        except Exception as e:
            return {"error": str(e), "ts": datetime.utcnow().isoformat()}
