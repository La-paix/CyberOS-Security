"""
ELPATI NETWORK GUARD - Network Traffic Analysis & Protection
Monitors connections, detects C2 communication, port scanning, exfiltration
"""
import socket, threading, time, json, psutil
from collections import defaultdict, deque
from datetime import datetime

class ElpatiNetworkGuard:
    def __init__(self):
        from elpati.elpati_log import ElpatiLog
        from elpati.elpati_threat_intel import ElpatiThreatIntel
        self.log = ElpatiLog()
        self.ti = ElpatiThreatIntel()
        self._active = False
        self._blocked_ips = set()
        self._blocked_ports = {4444, 1337, 31337, 9999, 8888, 6666, 5555}  # Common C2 ports
        self._connection_history = deque(maxlen=2000)
        self._port_scan_tracker = defaultdict(lambda: defaultdict(int))
        self._data_transfer = defaultdict(int)
        self._lock = threading.Lock()
        self._alerts = deque(maxlen=500)
        self._thread = None

    def start(self):
        self._active = True
        self._thread = threading.Thread(target=self._guard_loop, daemon=True, name="ELPATI-NetGuard")
        self._thread.start()
        self.log.info("ELPATI Network Guard started")

    def stop(self):
        self._active = False

    def _guard_loop(self):
        while self._active:
            try:
                self._analyze_connections()
                self._check_dns_anomalies()
                time.sleep(3)
            except Exception as e:
                self.log.error(f"NetGuard error: {e}")
                time.sleep(5)

    def _analyze_connections(self):
        try:
            conns = psutil.net_connections(kind='inet')
            for conn in conns:
                if conn.status == 'ESTABLISHED' and conn.raddr:
                    ip = conn.raddr.ip
                    port = conn.raddr.port
                    entry = {"ts": datetime.utcnow().isoformat(), "ip": ip, "port": port,
                             "local_port": conn.laddr.port if conn.laddr else 0,
                             "pid": conn.pid, "status": conn.status}

                    # Check blocked IPs
                    if ip in self._blocked_ips:
                        self._fire_alert("CRITICAL", f"Connection to blocked IP: {ip}:{port}", 95)

                    # Check suspicious ports
                    if port in self._blocked_ports:
                        self._fire_alert("HIGH", f"Connection on suspicious port {port} to {ip}", 80)

                    # Check threat intel
                    ti_result = self.ti.check_ip(ip)
                    if ti_result["detected"]:
                        self._fire_alert("HIGH", f"Threat Intel match: {ip}", ti_result["score"])

                    with self._lock:
                        self._connection_history.append(entry)
        except Exception as e:
            pass

    def _check_dns_anomalies(self):
        """Check for DNS-based data exfiltration patterns (long subdomains)."""
        try:
            # This would hook DNS in production; here we check /etc/hosts anomalies
            hosts_file = "/etc/hosts"
            if not hasattr(self, '_hosts_hash'):
                import hashlib
                try:
                    self._hosts_hash = hashlib.md5(open(hosts_file, 'rb').read()).hexdigest()
                except:
                    self._hosts_hash = ""
            else:
                import hashlib
                try:
                    curr_hash = hashlib.md5(open(hosts_file, 'rb').read()).hexdigest()
                    if curr_hash != self._hosts_hash:
                        self._fire_alert("HIGH", "/etc/hosts file was modified!", 85)
                        self._hosts_hash = curr_hash
                except:
                    pass
        except:
            pass

    def _fire_alert(self, severity, message, score):
        alert = {"ts": datetime.utcnow().isoformat(), "severity": severity,
                 "message": message, "score": score}
        with self._lock:
            self._alerts.append(alert)
        self.log.threat(f"[NETGUARD-{severity}] {message} score={score}")

    def block_ip(self, ip: str):
        self._blocked_ips.add(ip)
        self.log.audit(f"NetGuard: IP blocked: {ip}")

    def unblock_ip(self, ip: str):
        self._blocked_ips.discard(ip)
        self.log.audit(f"NetGuard: IP unblocked: {ip}")

    def get_active_connections(self) -> list:
        try:
            result = []
            for conn in psutil.net_connections(kind='inet'):
                if conn.status in ['ESTABLISHED', 'LISTEN']:
                    proc_name = "unknown"
                    if conn.pid:
                        try:
                            proc_name = psutil.Process(conn.pid).name()
                        except:
                            pass
                    result.append({
                        "local": f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "",
                        "remote": f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "",
                        "status": conn.status, "pid": conn.pid, "process": proc_name
                    })
            return result
        except:
            return []

    def get_network_stats(self) -> dict:
        try:
            io = psutil.net_io_counters()
            return {
                "bytes_sent": io.bytes_sent, "bytes_recv": io.bytes_recv,
                "packets_sent": io.packets_sent, "packets_recv": io.packets_recv,
                "errin": io.errin, "errout": io.errout,
                "active_connections": len(self.get_active_connections()),
                "blocked_ips": len(self._blocked_ips),
                "alerts": len(self._alerts)
            }
        except:
            return {}

    def get_alerts(self, n=50):
        with self._lock:
            return list(self._alerts)[-n:]

    def port_scan(self, target: str, ports: list = None) -> dict:
        """Perform a local network port scan."""
        if ports is None:
            ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995,
                     1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 27017]
        open_ports = []
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)
                result = sock.connect_ex((target, port))
                if result == 0:
                    try:
                        service = socket.getservbyport(port)
                    except:
                        service = "unknown"
                    open_ports.append({"port": port, "service": service})
                sock.close()
            except:
                pass
        self.log.audit(f"Port scan on {target}: {len(open_ports)} open ports")
        return {"target": target, "open_ports": open_ports, "scanned": len(ports),
                "ts": datetime.utcnow().isoformat()}
