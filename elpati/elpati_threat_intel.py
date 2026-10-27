"""
ELPATI THREAT INTEL - Local Malware Signature Database
100% offline threat intelligence with YARA-like rules
"""
import os, json, hashlib, re
from utils.storage import write_json
import threading
_CUSTOM_LOCK = threading.RLock()
from pathlib import Path
from datetime import datetime

THREAT_DB_DIR = Path(__file__).parent.parent / "threat_db"
THREAT_DB_DIR.mkdir(exist_ok=True)

# These extensions are also routinely used by legitimate encrypted storage.
# A filename alone must not turn a backup/password file into a malware verdict.
AMBIGUOUS_ENCRYPTED_EXTENSIONS = frozenset({".enc", ".crypt", ".encrypted", ".vault"})
FILE_REVIEW_PATTERNS = (
    ("SHADOW_COPY_DELETION_COMMAND", 60,
     re.compile(r"\b(?:vssadmin(?:\.exe)?[ \t]+delete[ \t]+shadows|wmic(?:\.exe)?[ \t]+shadowcopy[ \t]+delete)\b", re.I)),
    ("ENCODED_POWERSHELL_COMMAND", 55,
     re.compile(r"\bpowershell(?:\.exe)?[ \t]+[^\r\n]{0,180}?-(?:enc(?:odedcommand)?|e)[ \t]+[A-Za-z0-9+/=]{20,}", re.I)),
    ("CREDENTIAL_DUMP_COMMAND", 65,
     re.compile(r"\b(?:procdump(?:64)?(?:\.exe)?)[ \t]+[^\r\n]{0,180}?-ma[ \t]+lsass(?:\.exe)?\b|\bsekurlsa::(?:logonpasswords|tickets)\b", re.I)),
)

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
                return json.loads(self.db_file.read_text(encoding="utf-8"))
            except:
                pass
        db = BUILTIN_SIGNATURES.copy()
        db["_version"] = "2026.1.0"
        db["_updated"] = datetime.utcnow().isoformat()
        db["_count"] = sum(len(v) if isinstance(v, list) else 1 for v in db.values())
        self.db_file.write_text(json.dumps(db, indent=2), encoding="utf-8")
        return db

    def _load_custom(self):
        if not self.custom_db_file.exists():
            return {"hashes": [], "strings": [], "rules": []}
        value = json.loads(self.custom_db_file.read_text(encoding="utf-8"))
        if not isinstance(value, dict) or any(not isinstance(value.get(k, []), list)
                                               for k in ("hashes", "strings", "rules")):
            raise ValueError("Base de signatures personnalisées corrompue")
        return {"hashes": value.get("hashes", []), "strings": value.get("strings", []),
                "rules": value.get("rules", [])}

    def check_hash(self, file_hash: str) -> dict:
        self.stats["scans"] += 1
        fh = str(file_hash).lower()
        all_hashes = self._db.get("known_malware_hashes", []) + self._custom.get("hashes", [])
        normalized = {str(h.get("hash", "") if isinstance(h, dict) else h).lower()
                      for h in all_hashes}
        if fh and fh in normalized:
            self.stats["detections"] += 1
            return {"detected": True, "type": "known_malware", "score": 100, "hash": fh}
        return {"detected": False, "score": 0}

    def scan_strings(self, content: str) -> list:
        findings = []
        content_lower = content.lower()
        for s in self._db.get("suspicious_strings", []) + self._custom.get("strings", []):
            if s.lower() in content_lower:
                findings.append({"type": "suspicious_string", "match": s, "score": 60})
        for rule in self._db.get("yara_like_rules", []) + self._custom.get("rules", []):
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
        if ext in AMBIGUOUS_ENCRYPTED_EXTENSIONS:
            return {"detected": False, "score": 0, "ambiguous": True, "ext": ext}
        ransom_exts = self._db.get("ransomware_extensions", [])
        if ext in ransom_exts:
            return {"detected": True, "type": "extension_indicator", "score": 45,
                    "confirmed": False, "ext": ext}
        return {"detected": False, "score": 0}

    def file_review_patterns(self, content: str, extension: str) -> list:
        """Static command indicators, never proof that a command ran.

        Imported Windows API names and standalone credential-related words
        are deliberately not file verdicts. Python rule dictionaries and
        documentation strings are not interpreted as executed shell commands.
        """
        if extension == ".py":
            import ast
            commands = []
            try:
                tree = ast.parse(content)
            except (SyntaxError, ValueError, RecursionError):
                tree = None
            if tree is not None:
                for node in ast.walk(tree):
                    if not isinstance(node, ast.Call) or not node.args:
                        continue
                    func = node.func
                    if not (isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name)):
                        continue
                    name = func.value.id + "." + func.attr
                    if name not in {"subprocess.run", "subprocess.Popen", "subprocess.call",
                                    "subprocess.check_call", "subprocess.check_output", "os.system", "os.popen"}:
                        continue
                    try:
                        value = ast.literal_eval(node.args[0])
                    except (ValueError, TypeError, SyntaxError, MemoryError, RecursionError):
                        continue
                    if isinstance(value, str):
                        commands.append(value)
                    elif isinstance(value, (list, tuple)) and all(isinstance(v, str) for v in value):
                        commands.append(" ".join(value))
            command_text = "\n".join(commands)
        else:
            command_text = "\n".join(line for line in content.splitlines()
                                     if not line.lstrip().lower().startswith(("#", "rem ", "::")))
        findings = [{"name": name, "score": score, "confirmed": False}
                    for name, score, pattern in FILE_REVIEW_PATTERNS if pattern.search(command_text)]
        # Owner-supplied rules remain review indicators, even when their score is high.
        for rule in self._custom.get("rules", []):
            try:
                if re.search(rule["pattern"], content, re.IGNORECASE):
                    findings.append({"name": str(rule["name"]), "score": 60, "confirmed": False})
            except (KeyError, TypeError, re.error):
                continue
        return findings

    def check_process_name(self, proc_name: str) -> dict:
        pn = (proc_name or "").lower()
        malicious = [p.lower() for p in self._db.get("malicious_processes", [])]
        if pn and pn in malicious:
            return {"detected": True, "type": "malicious_process", "score": 95, "process": proc_name}
        return {"detected": False, "score": 0}

    def check_ip(self, ip: str) -> dict:
        for prefix in self._db.get("suspicious_ips", []):
            if ip.startswith(prefix):
                return {"detected": True, "type": "suspicious_ip", "score": 65, "ip": ip}
        return {"detected": False, "score": 0}

    def add_custom_hash(self, file_hash: str, description: str = ""):
        file_hash = file_hash.lower().strip()
        if len(file_hash) not in (32, 64) or not re.fullmatch(r"[0-9a-f]+", file_hash):
            raise ValueError("Empreinte MD5, SHA-256 ou SHA3-256 requise")
        with _CUSTOM_LOCK:
            self._custom = self._load_custom()
            if not any((h.get("hash") if isinstance(h, dict) else h) == file_hash
                       for h in self._custom["hashes"]):
                self._custom["hashes"].append({"hash": file_hash, "desc": description})
            write_json(self.custom_db_file, self._custom)

    def get_stats(self):
        return {**self.stats, "db_version": self._db.get("_version", "unknown"),
                "signatures": self._db.get("_count", 0)}
