"""
ELPATI SHIELD - Active Protection & Process/Network Blocking
Terminates malicious processes and blocks network connections
"""
import os, signal, subprocess, psutil
from datetime import datetime

class ElpatiShield:
    def __init__(self):
        from elpati.elpati_log import ElpatiLog
        self.log = ElpatiLog()
        self._blocked_pids = set()
        self._action_history = []
        self._protection_level = "ACTIVE"  # PASSIVE, ACTIVE, AGGRESSIVE

    def set_protection_level(self, level: str):
        assert level in ("PASSIVE", "ACTIVE", "AGGRESSIVE")
        self._protection_level = level
        self.log.audit(f"Shield: Protection level set to {level}")

    def kill_process(self, pid: int, force: bool = False) -> dict:
        """Terminate a malicious process."""
        if self._protection_level == "PASSIVE":
            self.log.warning(f"Shield PASSIVE: would kill PID {pid} but skipped")
            return {"action": "skipped", "reason": "passive_mode", "pid": pid}
        try:
            proc = psutil.Process(pid)
            proc_name = proc.name()
            if force:
                proc.kill()
            else:
                proc.terminate()
            self._blocked_pids.add(pid)
            action = {"action": "killed", "pid": pid, "name": proc_name,
                      "force": force, "ts": datetime.utcnow().isoformat()}
            self._action_history.append(action)
            self.log.threat(f"Shield: Process terminated PID={pid} name={proc_name}")
            return action
        except psutil.NoSuchProcess:
            return {"action": "not_found", "pid": pid}
        except psutil.AccessDenied:
            self.log.error(f"Shield: Access denied killing PID {pid}")
            return {"action": "denied", "pid": pid}

    def quarantine_file(self, filepath: str, quarantine_dir: str) -> dict:
        """Move file to quarantine."""
        import shutil
        from pathlib import Path
        try:
            src = Path(filepath)
            dst_dir = Path(quarantine_dir)
            dst_dir.mkdir(parents=True, exist_ok=True)
            dst = dst_dir / f"{src.name}.quarantine"
            shutil.move(str(src), str(dst))
            self.log.threat(f"Shield: File quarantined {filepath} -> {dst}")
            return {"action": "quarantined", "original": filepath, "destination": str(dst),
                    "ts": datetime.utcnow().isoformat()}
        except Exception as e:
            self.log.error(f"Shield: Quarantine failed for {filepath}: {e}")
            return {"action": "failed", "error": str(e)}

    def isolate_process(self, pid: int) -> dict:
        """Reduce process priority to minimal."""
        try:
            proc = psutil.Process(pid)
            proc.nice(19)  # Lowest priority
            action = {"action": "isolated", "pid": pid, "ts": datetime.utcnow().isoformat()}
            self._action_history.append(action)
            self.log.audit(f"Shield: Process {pid} isolated (priority reduced)")
            return action
        except Exception as e:
            return {"action": "failed", "error": str(e), "pid": pid}

    def block_network_ip(self, ip: str) -> dict:
        """Block IP using OS firewall (Linux iptables / macOS pf)."""
        if self._protection_level == "PASSIVE":
            return {"action": "skipped", "reason": "passive_mode"}
        try:
            if os.name == 'posix':
                # Try iptables (Linux)
                result = subprocess.run(
                    ["iptables", "-A", "OUTPUT", "-d", ip, "-j", "DROP"],
                    capture_output=True, timeout=5)
                if result.returncode == 0:
                    action = {"action": "blocked", "ip": ip, "method": "iptables",
                              "ts": datetime.utcnow().isoformat()}
                    self.log.audit(f"Shield: IP {ip} blocked via iptables")
                    self._action_history.append(action)
                    return action
        except Exception as e:
            pass
        return {"action": "manual_required", "ip": ip,
                "note": f"Add firewall rule to block {ip}"}

    def get_action_history(self, n=50):
        return self._action_history[-n:]

    def get_status(self):
        return {"protection_level": self._protection_level,
                "blocked_pids": list(self._blocked_pids),
                "actions_taken": len(self._action_history)}
