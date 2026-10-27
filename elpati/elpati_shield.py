"""
ELPATI SHIELD - Active Protection & Process/Network Blocking
Terminates malicious processes and blocks network connections
"""
import os, signal, subprocess, psutil
import ipaddress
import platform
from datetime import datetime

class ElpatiShield:
    def __init__(self):
        from elpati.elpati_log import ElpatiLog
        self.log = ElpatiLog()
        self._blocked_pids = set()
        self._action_history = []
        self._protection_level = "PASSIVE"  # PASSIVE, ACTIVE, AGGRESSIVE

    def set_protection_level(self, level: str):
        if level not in ("PASSIVE", "ACTIVE", "AGGRESSIVE"):
            raise ValueError("Niveau inconnu")
        self._protection_level = level
        self.log.audit(f"Shield: Protection level set to {level}")

    def kill_process(self, pid: int, force: bool = False) -> dict:
        """Terminate a malicious process."""
        if self._protection_level == "PASSIVE":
            self.log.warning(f"Shield PASSIVE: would kill PID {pid} but skipped")
            return {"action": "skipped", "reason": "passive_mode", "pid": pid}
        if pid in {0, 1, os.getpid(), os.getppid()}:
            return {"action": "denied", "reason": "protected_pid", "pid": pid}
        try:
            proc = psutil.Process(pid)
            proc_name = proc.name()
            if proc_name.lower() in {"system", "registry", "smss.exe", "csrss.exe", "wininit.exe", "lsass.exe", "services.exe"}:
                return {"action": "denied", "reason": "system_process", "pid": pid}
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

    def quarantine_file(self, filepath, quarantine_dir=None):
        from quarantine.quarantine_manager import QuarantineManager
        if self._protection_level == "PASSIVE":
            return {"action": "skipped", "reason": "passive_mode"}
        return QuarantineManager().quarantine_file(filepath, {"source": "shield"})

    def isolate_process(self, pid: int) -> dict:
        """Reduce process priority to minimal."""
        if self._protection_level == "PASSIVE":
            return {"action": "skipped", "reason": "passive_mode", "pid": pid}
        if pid in {0, 1, os.getpid(), os.getppid()}:
            return {"action": "denied", "reason": "protected_pid", "pid": pid}
        try:
            proc = psutil.Process(pid)
            proc.nice(psutil.IDLE_PRIORITY_CLASS if os.name == "nt" else 19)  # Lowest priority
            action = {"action": "priority_reduced", "pid": pid, "ts": datetime.utcnow().isoformat()}
            self._action_history.append(action)
            self.log.audit(f"Shield: Process {pid} priority reduced (not network-isolated)")
            return action
        except Exception as e:
            return {"action": "failed", "error": str(e), "pid": pid}

    def block_network_ip(self, ip, unblock=False):
        try:
            ip = str(ipaddress.ip_address(ip))
        except ValueError:
            return {"action": "failed", "error": "Adresse IP invalide"}
        if self._protection_level == "PASSIVE":
            return {"action": "skipped", "reason": "passive_mode"}
        try:
            if os.name == "nt":
                name = f"CyberOS-block-{ip}"
                command = (["netsh", "advfirewall", "firewall", "delete", "rule", f"name={name}"]
                           if unblock else ["netsh", "advfirewall", "firewall", "add", "rule",
                           f"name={name}", "dir=out", "action=block", f"remoteip={ip}"])
            elif platform.system() == "Linux":
                binary = "ip6tables" if ":" in ip else "iptables"
                command = [binary, "-D" if unblock else "-A", "OUTPUT", "-d", ip, "-j", "DROP"]
            else:
                return {"action": "manual_required", "ip": ip, "reason": "platform_not_supported"}
            result = subprocess.run(command, capture_output=True, timeout=5)
            if result.returncode:
                return {"action": "failed", "ip": ip, "reason": "firewall_command_failed"}
            action = {"action": "unblocked" if unblock else "blocked", "ip": ip,
                      "ts": datetime.utcnow().isoformat()}
            self._action_history.append(action)
            self.log.audit(f"Shield firewall: {action}")
            return action
        except (OSError, subprocess.SubprocessError) as exc:
            return {"action": "manual_required", "ip": ip, "error": str(exc)}

    def get_action_history(self, n=50):
        return self._action_history[-n:]

    def get_status(self):
        return {"protection_level": self._protection_level,
                "blocked_pids": list(self._blocked_pids),
                "actions_taken": len(self._action_history)}
