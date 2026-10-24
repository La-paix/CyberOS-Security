"""
ELPATI THREAT INTEL - Local Malware Signature Database
100% offline threat intelligence with YARA-like rules
"""
import os, json, hashlib, re
from pathlib import Path
from datetime import datetime

THREAT_DB_DIR = Path(__file__).parent.parent / "threat_db"
THREAT_DB_DIR.mkdir(exist_ok=True)

# Built-in threat signatures (MD5/SHA256 known malware hashes + patterns)
BUILTIN_SIGNATURES = {
    "known_malware_hashes": [
        # EICAR test file
        "44d88612fea8a8f36de82e1278abb02f",
        "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
        # Mimikatz variants (partial list)
        "e13b6573a1a674b5e857b4ab93284e27",
        "92a35f1c62eefc8a31df16f2e6973cf4",
    ],
    "suspicious_strings": [
        "CreateRemoteThread", "VirtualAllocEx", "WriteProcessMemory",
        "NtUnmapViewOfSection", "ZwUnmapViewOfSection", "RtlDecompressBuffer",
        "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess",
        "GetProcAddress", "LoadLibraryA", "WSAStartup", "WSAConnect",
        "cmd.exe /c", "powershell -enc", "powershell -nop",
        "certutil -decode", "bitsadmin /transfer",
        "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        "schtasks /create", "at.exe", "wscript.exe", "cscript.exe",
        "mshta.exe", "regsvr32 /s /n /u /i:",
        "vssadmin delete shadows", "bcdedit /set", "wbadmin delete",
    ],
    "ransomware_extensions": [
        ".locky", ".zepto", ".odin", ".aesir", ".cerber", ".cerber2", ".cerber3",
        ".crypted", ".crypt", ".encrypted", ".enc", ".locked", ".vault", ".wnry",
        ".wncry", ".wannacry", ".petya", ".nopetyaaa", ".exe.encrypted",
        ".ryuk", ".revil", ".sodinokibi", ".darkside", ".lockbit", ".blackmatter",
    ],
    "malicious_processes": [
        "mimikatz.exe", "pwdump.exe", "fgdump.exe", "gsecdump.exe",
        "wce.exe", "quarks-pwdump.exe", "cachedump.exe",
        "meterpreter", "metasploit", "cobaltstrike", "beacon.exe",
        "empire.exe", "powersploit", "sharphound.exe",
        "ncrack.exe", "hydra.exe", "medusa.exe",
        "nmap.exe", "masscan.exe", "zmap.exe",
    ],
    "suspicious_ips": [
        "185.220.101.", "178.62.", "198.199.", "45.33.",
        "104.131.", "192.241.",
    ],
    "yara_like_rules": [
        {
            "name": "RANSOMWARE_SHADOW_DELETE",
            "description": "Shadow copy deletion - common ransomware behavior",
            "pattern": r"vssadmin.*delete.*shadows|wmic.*shadowcopy.*delete",
            "score": 95
        },
        {
            "name": "POWERSHELL_ENCODED_CMD",
            "description": "PowerShell encoded command execution",
            "pattern": r"powershell.*-e[nc]{1,2}\s+[A-Za-z0-9+/=]{20,}",
            "score": 75
        },
        {
            "name": "PROCESS_INJECTION",
            "description": "Classic process injection technique",
            "pattern": r"VirtualAllocEx.{0,100}WriteProcessMemory.{0,100}CreateRemoteThread",
            "score": 90
        },
        {
            "name": "CREDENTIAL_DUMP",
            "description": "LSASS credential dumping attempt",
            "pattern": r"lsass\.exe|sekurlsa|wdigest|kerberos.*credentials",
            "score": 85
        },
        {
            "name": "LATERAL_MOVEMENT",
            "description": "Lateral movement via PSExec or WMI",
            "pattern": r"psexec|wmiexec|wmic.*process.*call.*create",
            "score": 80
        },
    ]
}

class ElpatiThreatIntel:
    def __init__(self):
        self.db_file = THREAT_DB_DIR / "signatures.json"
        self.custom_db_file = THREAT_DB_DIR / "custom_signatures.json"
        self._db = self._load_db()
        self._custom = self._load_custom()
        self.stats = {"scans": 0, "detections": 0}

    def _load_db(self):
        if self.db_file.exists():
            try:
                return json.loads(self.db_file.read_text())
            except:
                pass
        db = BUILTIN_SIGNATURES.copy()
        db["_version"] = "2026.1.0"
        db["_updated"] = datetime.utcnow().isoformat()
        db["_count"] = sum(len(v) if isinstance(v, list) else 1 for v in db.values())
        self.db_file.write_text(json.dumps(db, indent=2))
        return db

    def _load_custom(self):
        if self.custom_db_file.exists():
            try:
                return json.loads(self.custom_db_file.read_text())
            except:
                pass
        return {"hashes": [], "strings": [], "rules": []}

    def check_hash(self, file_hash: str) -> dict:
        self.stats["scans"] += 1
        fh = file_hash.lower()
        all_hashes = self._db.get("known_malware_hashes", []) + self._custom.get("hashes", [])
        if fh in [h.lower() for h in all_hashes]:
            self.stats["detections"] += 1
            return {"detected": True, "type": "known_malware", "score": 100, "hash": fh}
        return {"detected": False, "score": 0}

    def scan_strings(self, content: str) -> list:
        findings = []
        content_lower = content.lower()
        for s in self._db.get("suspicious_strings", []):
            if s.lower() in content_lower:
                findings.append({"type": "suspicious_string", "match": s, "score": 60})
        for rule in self._db.get("yara_like_rules", []):
            try:
                if re.search(rule["pattern"], content, re.IGNORECASE | re.DOTALL):
                    findings.append({
                        "type": "yara_rule", "name": rule["name"],
                        "description": rule["description"], "score": rule["score"]
                    })
            except:
                pass
        if findings:
            self.stats["detections"] += 1
        return findings

    def check_extension(self, filename: str) -> dict:
        ext = Path(filename).suffix.lower()
        ransom_exts = self._db.get("ransomware_extensions", [])
        if ext in ransom_exts:
            return {"detected": True, "type": "ransomware_extension", "score": 85, "ext": ext}
        return {"detected": False, "score": 0}

    def check_process_name(self, proc_name: str) -> dict:
        pn = proc_name.lower()
        malicious = [p.lower() for p in self._db.get("malicious_processes", [])]
        if pn in malicious or any(pn in m for m in malicious):
            return {"detected": True, "type": "malicious_process", "score": 95, "process": proc_name}
        return {"detected": False, "score": 0}

    def check_ip(self, ip: str) -> dict:
        for prefix in self._db.get("suspicious_ips", []):
            if ip.startswith(prefix):
                return {"detected": True, "type": "suspicious_ip", "score": 65, "ip": ip}
        return {"detected": False, "score": 0}

    def add_custom_hash(self, file_hash: str, description: str = ""):
        self._custom["hashes"].append({"hash": file_hash, "desc": description})
        self.custom_db_file.write_text(json.dumps(self._custom, indent=2))

    def get_stats(self):
        return {**self.stats, "db_version": self._db.get("_version", "unknown"),
                "signatures": self._db.get("_count", 0)}
