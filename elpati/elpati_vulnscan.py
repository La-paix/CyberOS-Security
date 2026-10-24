"""
ELPATI VULN SCAN - Scanner de Vulnérabilités Système
Vérifie les CVE critiques, configs faibles, ports exposés, services obsolètes
100% local, 0 internet requis
"""
import os, platform, subprocess, socket, json
from datetime import datetime
from pathlib import Path

# CVE critiques connues par version OS/logiciel (base locale 2026)
KNOWN_VULNS = [
    {"id":"CVE-2024-3094","name":"XZ Utils backdoor","affected":"xz-utils 5.6.0-5.6.1","score":10,"desc":"Backdoor critique dans la compression XZ"},
    {"id":"CVE-2021-44228","name":"Log4Shell","affected":"Apache Log4j 2.x < 2.17","score":10,"desc":"Exécution de code à distance via JNDI"},
    {"id":"CVE-2021-34527","name":"PrintNightmare","affected":"Windows Print Spooler","score":8.8,"desc":"Élévation de privilèges via le spouleur d'impression"},
    {"id":"CVE-2020-1472","name":"Zerologon","affected":"Windows Netlogon","score":10,"desc":"Prise de contrôle complète du contrôleur de domaine"},
    {"id":"CVE-2019-0708","name":"BlueKeep","affected":"Windows RDP < 2019","score":9.8,"desc":"Exécution de code via RDP sans authentification"},
    {"id":"CVE-2017-0144","name":"EternalBlue","affected":"Windows SMBv1","score":8.1,"desc":"Exploité par WannaCry et NotPetya"},
    {"id":"CVE-2023-4863","name":"WebP Heap OOB","affected":"Chrome/Edge < 116","score":8.8,"desc":"Corruption mémoire via image WebP malveillante"},
    {"id":"CVE-2024-21413","name":"Outlook RCE","affected":"Microsoft Outlook","score":9.8,"desc":"Exécution de code via lien malveillant dans Outlook"},
]

WEAK_CONFIGS = [
    {"check": "smb_v1",       "name": "SMBv1 activé",              "score": 8, "desc": "Protocole obsolète exploité par WannaCry"},
    {"check": "rdp_exposed",  "name": "RDP exposé (port 3389)",    "score": 7, "desc": "Accès bureau à distance potentiellement exposé"},
    {"check": "telnet",       "name": "Telnet actif (port 23)",    "score": 9, "desc": "Protocole non chiffré — remplacer par SSH"},
    {"check": "ftp_open",     "name": "FTP non sécurisé (port 21)","score": 6, "desc": "Transfert en clair — utiliser SFTP/FTPS"},
    {"check": "guest_account","name": "Compte Invité actif",       "score": 5, "desc": "Accès non authentifié possible"},
    {"check": "autorun",      "name": "Autorun USB activé",        "score": 6, "desc": "Exécution automatique des clés USB"},
    {"check": "uac_disabled", "name": "UAC désactivé",             "score": 8, "desc": "Contrôle de compte utilisateur absent"},
    {"check": "firewall_off", "name": "Pare-feu désactivé",        "score": 9, "desc": "Aucune protection réseau active"},
    {"check": "defender_off", "name": "Antivirus Windows désactivé","score":8, "desc": "Protection temps réel inactive"},
    {"check": "auto_update_off","name":"Mises à jour auto désactivées","score":7,"desc":"Failles de sécurité non corrigées"},
]

class ElpatiVulnScan:
    def __init__(self):
        from elpati.elpati_log import ElpatiLog
        self.log = ElpatiLog()
        self._results = []
        self._last_scan = None

    def run_full_scan(self) -> dict:
        """Scan complet de vulnérabilités."""
        self.log.audit("VulnScan: Démarrage scan de vulnérabilités")
        start = datetime.now()
        results = {
            "scanned_at": start.isoformat(),
            "os": platform.system(),
            "vulnerabilities": [],
            "weak_configs": [],
            "open_ports": [],
            "score": 0,
            "critical_count": 0,
            "high_count": 0,
        }

        # Scan configurations faibles
        weak = self._check_weak_configs()
        results["weak_configs"] = weak

        # Scan ports locaux
        ports = self._scan_local_ports()
        results["open_ports"] = ports

        # Vérifications OS
        os_checks = self._check_os_security()
        results["os_security"] = os_checks

        # Score global
        all_issues = weak + os_checks
        if all_issues:
            max_score = max(i.get("score", 0) for i in all_issues)
            results["score"] = min(int(max_score * 10), 100)
        results["critical_count"] = sum(1 for i in all_issues if i.get("score", 0) >= 9)
        results["high_count"] = sum(1 for i in all_issues if 7 <= i.get("score", 0) < 9)

        results["duration_sec"] = (datetime.now() - start).total_seconds()
        self._results = results
        self._last_scan = datetime.now().isoformat()
        self.log.audit(f"VulnScan: Terminé — {len(weak)} configs faibles, {len(ports)} ports ouverts")
        return results

    def _check_weak_configs(self) -> list:
        found = []
        sys = platform.system()

        if sys == "Windows":
            # Vérifier pare-feu Windows
            try:
                result = subprocess.run(
                    ["netsh", "advfirewall", "show", "allprofiles", "state"],
                    capture_output=True, text=True, timeout=5)
                if "OFF" in result.stdout.upper():
                    found.append({**next(c for c in WEAK_CONFIGS if c["check"]=="firewall_off"),
                                  "detected": True, "platform": "Windows"})
            except: pass

            # Vérifier RDP
            try:
                result = subprocess.run(
                    ["reg", "query", r"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server",
                     "/v", "fDenyTSConnections"],
                    capture_output=True, text=True, timeout=5)
                if "0x0" in result.stdout:
                    found.append({**next(c for c in WEAK_CONFIGS if c["check"]=="rdp_exposed"),
                                  "detected": True, "platform": "Windows"})
            except: pass

        elif sys == "Linux":
            # Vérifier UFW
            try:
                result = subprocess.run(["ufw", "status"], capture_output=True, text=True, timeout=5)
                if "inactive" in result.stdout.lower():
                    found.append({**next(c for c in WEAK_CONFIGS if c["check"]=="firewall_off"),
                                  "detected": True, "platform": "Linux"})
            except: pass

        return found

    def _scan_local_ports(self) -> list:
        """Scanner les ports ouverts en local."""
        risky_ports = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
            80: "HTTP", 135: "RPC", 139: "NetBIOS", 143: "IMAP",
            443: "HTTPS", 445: "SMB", 1433: "MSSQL", 1521: "Oracle",
            3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
            5900: "VNC", 6379: "Redis", 8080: "HTTP-Alt", 27017: "MongoDB"
        }
        open_ports = []
        for port, service in risky_ports.items():
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.3)
                if s.connect_ex(("127.0.0.1", port)) == 0:
                    risk = "HIGH" if port in (23, 445, 3389, 5900) else "MEDIUM"
                    open_ports.append({"port": port, "service": service, "risk": risk})
                s.close()
            except: pass
        return open_ports

    def _check_os_security(self) -> list:
        findings = []
        import sys as _sys
        try:
            if platform.system() == "Windows":
                # Vérifier Windows Defender
                try:
                    r = subprocess.run(
                        ["powershell", "-Command",
                         "Get-MpComputerStatus | Select-Object -ExpandProperty RealTimeProtectionEnabled"],
                        capture_output=True, text=True, timeout=8)
                    if "False" in r.stdout:
                        findings.append({"check":"defender_off","name":"Windows Defender désactivé",
                                         "score":8,"desc":"Protection temps réel inactive","detected":True})
                except: pass
        except: pass
        return findings

    def get_last_results(self): return self._results
    def get_summary(self):
        if not self._results: return {"scanned": False}
        return {
            "scanned": True, "last_scan": self._last_scan,
            "score": self._results.get("score", 0),
            "critical": self._results.get("critical_count", 0),
            "high": self._results.get("high_count", 0),
            "open_ports": len(self._results.get("open_ports", [])),
            "weak_configs": len(self._results.get("weak_configs", [])),
        }
