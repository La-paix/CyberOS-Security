"""
FORENSIC ENGINE - Digital Forensics & Evidence Collection
Collects partial local observations and exports hashed evidence; no legal certification
"""
import os, json, hashlib, platform, time, psutil
from pathlib import Path
from datetime import datetime
from uuid import uuid4
from utils.storage import atomic_write, safe_name

FORENSIC_DIR = Path(__file__).parent.parent / "reports" / "forensic"
FORENSIC_DIR.mkdir(parents=True, exist_ok=True)

class ForensicEngine:
    def __init__(self):
        from elpati.elpati_log import ElpatiLog
        from elpati.elpati_crypto import ElpatiCrypto
        from core.security_vault import SecurityVault
        self.log = ElpatiLog()
        self.crypto = ElpatiCrypto()
        self.vault = SecurityVault()

    def collect_system_snapshot(self) -> dict:
        """Collect complete system state for forensic analysis."""
        snapshot = {
            "collection_ts": datetime.utcnow().isoformat(),
            "collector": "CyberOS_Security ELPATI Forensic Engine v2026.1",
            "system_info": self._collect_system_info(),
            "running_processes": self._collect_processes(),
            "network_connections": self._collect_network(),
            "open_ports": self._collect_ports(),
            "startup_items": self._collect_startup(),
            "recent_files": self._collect_recent_files(),
            "user_accounts": self._collect_users(),
        }
        return snapshot

    def _collect_system_info(self) -> dict:
        try:
            return {
                "hostname": platform.node(),
                "os": platform.system(),
                "os_version": platform.version(),
                "os_release": platform.release(),
                "architecture": platform.machine(),
                "processor": platform.processor(),
                "python_version": platform.python_version(),
                "cpu_count": psutil.cpu_count(),
                "memory_total_gb": round(psutil.virtual_memory().total / (1024**3), 2),
                "disk_partitions": [
                    {"device": p.device, "mountpoint": p.mountpoint, "fstype": p.fstype}
                    for p in psutil.disk_partitions()
                ],
                "boot_time": datetime.fromtimestamp(psutil.boot_time()).isoformat(),
                "uptime_hours": round((time.time() - psutil.boot_time()) / 3600, 2)
            }
        except Exception as e:
            return {"error": str(e)}

    def _collect_processes(self) -> list:
        procs = []
        for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'username',
                                          'status', 'create_time', 'memory_percent', 'cpu_percent']):
            try:
                info = dict(proc.info)
                info['create_time'] = datetime.fromtimestamp(
                    info['create_time']).isoformat() if info.get('create_time') else None
                info['cmdline'] = ' '.join(info.get('cmdline') or [])[:300]
                procs.append(info)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return sorted(procs, key=lambda x: x.get('pid', 0))

    def _collect_network(self) -> list:
        conns = []
        try:
            for conn in psutil.net_connections(kind='inet'):
                c = {
                    "local": f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "",
                    "remote": f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "",
                    "status": conn.status, "pid": conn.pid
                }
                if conn.pid:
                    try:
                        c["process"] = psutil.Process(conn.pid).name()
                    except:
                        c["process"] = "unknown"
                conns.append(c)
        except:
            pass
        return conns

    def _collect_ports(self) -> list:
        listening = []
        try:
            for conn in psutil.net_connections(kind='inet'):
                if conn.status == 'LISTEN':
                    entry = {"port": conn.laddr.port, "ip": conn.laddr.ip, "pid": conn.pid}
                    if conn.pid:
                        try:
                            entry["process"] = psutil.Process(conn.pid).name()
                        except:
                            entry["process"] = "unknown"
                    listening.append(entry)
        except:
            pass
        return listening

    def _collect_startup(self) -> list:
        items = []
        if os.name == 'posix':
            # Linux/macOS startup locations
            startup_dirs = [
                "/etc/init.d", "/etc/rc.local", "/etc/cron.d",
                str(Path.home() / ".config/autostart"),
                "/Library/LaunchAgents", "/Library/LaunchDaemons",
                str(Path.home() / "Library/LaunchAgents"),
            ]
            for d in startup_dirs:
                p = Path(d)
                if p.is_file():
                    items.append({"type": "file", "path": str(p)})
                elif p.is_dir():
                    try:
                        for f in p.iterdir():
                            items.append({"type": "dir_entry", "path": str(f)})
                    except:
                        pass
        elif os.name == 'nt':
            items.append({"type": "registry", "note": "Use registry scanner for Windows startup"})
        return items

    def _collect_recent_files(self) -> list:
        recent = []
        home = Path.home()
        scan_dirs = [home / "Downloads", home / "Documents", home / "Desktop", Path("/tmp")]
        cutoff = time.time() - 86400  # Last 24 hours
        for d in scan_dirs:
            if d.exists():
                try:
                    for f in d.glob("*"):
                        try:
                            if f.is_file() and f.stat().st_mtime > cutoff:
                                recent.append({
                                    "path": str(f), "size": f.stat().st_size,
                                    "modified": datetime.fromtimestamp(f.stat().st_mtime).isoformat(),
                                    "hash": self.crypto.hash_file(str(f))[:16] + "..."
                                })
                        except:
                            pass
                except:
                    pass
        return sorted(recent, key=lambda x: x.get("modified", ""), reverse=True)[:50]

    def _collect_users(self) -> list:
        users = []
        try:
            for user in psutil.users():
                users.append({
                    "name": user.name, "terminal": user.terminal,
                    "host": user.host,
                    "started": datetime.fromtimestamp(user.started).isoformat() if user.started else None
                })
        except:
            pass
        return users

    def generate_report(self, incident_id: str = None, include_scan: bool = False) -> str:
        """Generate full forensic report and save to vault."""
        if not incident_id:
            incident_id = datetime.utcnow().strftime("INC-%Y%m%d-%H%M%S")

        self.log.audit(f"Forensic: Generating report {incident_id}")
        snapshot = self.collect_system_snapshot()

        report = {
            "incident_id": incident_id,
            "report_type": "FORENSIC_SNAPSHOT",
            "generated_by": "CyberOS_Security ELPATI v2026.1",
            "chain_of_custody": {
                "collected_at": datetime.utcnow().isoformat(),
                "tool": "ELPATI Forensic Engine",
                "integrity_method": "SHA256 of sorted JSON before report_hash is inserted",
                "hash_scope": "canonical_json_without_chain_of_custody.report_hash"
            },
            "data": snapshot
        }

        report_json = json.dumps(report, sort_keys=True, separators=(",", ":"), default=str)
        report_hash = hashlib.sha256(report_json.encode()).hexdigest()
        report["chain_of_custody"]["report_hash"] = report_hash

        # Save to file
        report_file = FORENSIC_DIR / f"{safe_name(incident_id)}_{uuid4().hex[:12]}.json"
        final_json = json.dumps(report, indent=2, default=str)
        atomic_write(report_file, final_json)

        # Store in vault
        self.vault.store_evidence(f"{incident_id}.json", final_json.encode())

        self.log.audit(f"Forensic report generated: {incident_id} hash={report_hash[:16]}")
        return str(report_file)

    def get_report_list(self) -> list:
        reports = []
        for f in FORENSIC_DIR.glob("*.json"):
            try:
                size = f.stat().st_size
                reports.append({"name": f.name, "size": size,
                                 "created": datetime.fromtimestamp(f.stat().st_ctime).isoformat()})
            except:
                pass
        return sorted(reports, key=lambda x: x["created"], reverse=True)
